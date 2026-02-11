import os
import hashlib
import pandas as pd
import numpy as np
import json
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_file, Response, stream_with_context
from werkzeug.utils import secure_filename
from PIL import Image, ImageChops
from io import BytesIO
import plotly.graph_objs as go
import plotly.utils
from config import config
import time
import queue
import threading

# New modular utilities
from utils.security import allowed_file as _allowed_file_util, hash_file as _hash_file_util, schedule_cleanup, log_audit_event
from utils.detection import detect_csv_anomalies as _detect_csv_anomalies_mod, analyze_image as _analyze_image_mod
from utils.cleaner import auto_clean as _auto_clean
from model_trainer import train_model_streaming as _train_model_streaming
import uuid
import re

# NEW: Universal Scanner System
from scanners import scan_file as universal_scan, get_supported_extensions, is_supported, ScannerRegistry


def create_app(config_name=None):
    """Application factory pattern"""
    app = Flask(__name__)
    
    # Load configuration
    config_name = config_name or os.environ.get('FLASK_ENV', 'development')
    app.config.from_object(config[config_name])
    
    # Create uploads directory if it doesn't exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Register routes
    register_routes(app)
    
    return app

def register_routes(app):
    """Register all routes with the app"""
    # Ensure a session id exists for audit and traceability
    @app.before_request
    def _ensure_session():
        try:
            session.permanent = True
            if 'session_id' not in session:
                session['session_id'] = uuid.uuid4().hex[:8]
        except Exception:
            pass
    
    @app.route('/')
    def index():
        """Landing page describing the AI integrity problem"""
        return render_template('index.html')

    @app.route('/upload')
    def upload_page():
        """File upload page"""
        return render_template('upload.html')

    # Preferred entry per UX flow
    @app.route('/secure-upload')
    def secure_upload():
        return redirect(url_for('upload_page'))

    @app.route('/scan', methods=['POST'])
    def scan_file():
        """Handle file upload and scanning"""
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(url_for('upload_page'))
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(url_for('upload_page'))
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            file_type = filename.rsplit('.', 1)[1].lower()
            
            df = pd.read_csv(filepath)
            anomalies = _detect_csv_anomalies_mod(df)
            
            chart_json = generate_anomaly_chart(anomalies)
            
            report = {
                "filename": filename,
                "summary": {
                    "total_anomalies": len(anomalies),
                    "rows_scanned": len(df),
                    "integrity_status": "Compromised" if len(anomalies) > 0 else "Secure"
                },
                "anomalies": anomalies
            }
            
            session['last_upload'] = {
                'path': filepath,
                'filename': filename,
                'file_type': file_type,
                'sha256': _hash_file_util(filepath),
            }
            schedule_cleanup(filepath, delay_seconds=15 * 60)

            return render_template('results.html', 
                                 report=report,
                                 chart_json=chart_json)
        else:
            flash('Invalid file type. Please upload CSV files only.', 'error')
            return redirect(url_for('upload_page'))

    @app.route('/api/scan-status')
    def scan_status():
        """API endpoint for checking scan status (for future real-time updates)"""
        return jsonify({'status': 'completed'})
    
    @app.route('/api/audit-log', methods=['GET'])
    def api_audit_log():
        """Export audit log as JSON."""
        from utils.security import AUDIT_LOG_PATH
        try:
            with open(AUDIT_LOG_PATH, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return jsonify({'success': True, 'count': len(data), 'logs': data})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @app.route('/api/audit-log/export')
    def export_audit_csv():
        """Export audit log as CSV file."""
        from utils.security import AUDIT_LOG_PATH
        import csv
        from io import StringIO
        
        try:
            with open(AUDIT_LOG_PATH, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            output = StringIO()
            if data:
                writer = csv.DictWriter(output, fieldnames=data[0].keys())
                writer.writeheader()
                writer.writerows(data)
            
            output.seek(0)
            return Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition': 'attachment; filename=audit_log.csv'}
            )
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @app.route('/api/models', methods=['GET'])
    def api_models():
        """Get all models information as JSON."""
        from model_trainer import HASHES_PATH
        try:
            with open(HASHES_PATH, 'r', encoding='utf-8') as f:
                models = json.load(f)
            return jsonify({'success': True, 'count': len(models), 'models': models})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @app.route('/api/verify/<file_hash>', methods=['POST'])
    def api_verify_hash():
        """Verify a file's hash for integrity checking."""
        file = request.files.get('file')
        expected_hash = request.view_args.get('file_hash')
        
        if not file:
            return jsonify({'success': False, 'error': 'No file provided'}), 400
        
        try:
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                file.save(tmp.name)
                actual_hash = _hash_file_util(tmp.name)
                os.remove(tmp.name)
            
            match = (actual_hash == expected_hash)
            return jsonify({
                'success': True,
                'match': match,
                'expected': expected_hash,
                'actual': actual_hash,
                'status': 'verified' if match else 'tampered'
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/universal-scan', methods=['POST'])
    def api_universal_scan():
        """
        Universal file scanning API endpoint.
        
        Automatically detects file format and routes to appropriate scanner.
        Supports: CSV, Excel, Parquet, JSON, Images, Text, Audio, Video,
                  Vector embeddings (NPY, HDF5), and more.
        
        Returns:
            JSON with scan results including anomalies, metadata, and statistics.
        """
        if 'file' not in request.files:
            return jsonify({
                'success': False, 
                'error': 'No file provided',
                'supported_formats': list(get_supported_extensions())
            }), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        # Check if format is supported
        filename = secure_filename(file.filename)
        if not is_supported(filename):
            ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else 'unknown'
            return jsonify({
                'success': False,
                'error': f'Unsupported file format: .{ext}',
                'supported_formats': list(get_supported_extensions())
            }), 400
        
        try:
            import tempfile
            
            # Save to temp file
            with tempfile.NamedTemporaryFile(delete=False, suffix='_' + filename) as tmp:
                file.save(tmp.name)
                temp_path = tmp.name
            
            try:
                # Run universal scanner
                result = universal_scan(temp_path)
                
                # Calculate file hash
                file_hash = _hash_file_util(temp_path)
                
                # Log audit event
                log_audit_event('universal_scan', {
                    'filename': filename,
                    'file_type': result.file_type,
                    'category': result.category,
                    'total_anomalies': result.total_anomalies,
                    'max_severity': str(result.max_severity) if result.max_severity else None,
                    'sha256': file_hash,
                })
                
                return jsonify({
                    'success': True,
                    'filename': filename,
                    'sha256': file_hash,
                    'scan_duration_ms': result.scan_duration_ms,
                    'file_type': result.file_type,
                    'category': result.category,
                    'scanner': result.scanner_name,
                    'total_anomalies': result.total_anomalies,
                    'severity_counts': result.severity_counts,
                    'max_severity': str(result.max_severity) if result.max_severity else None,
                    'integrity_status': 'Compromised' if result.has_high_or_critical else 'Secure',
                    'anomalies': [a.to_dict() for a in result.anomalies],
                    'metadata': result.metadata,
                })
            finally:
                # Cleanup temp file
                if os.path.exists(temp_path):
                    os.remove(temp_path)
        
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @app.route('/api/supported-formats', methods=['GET'])
    def api_supported_formats():
        """Get all supported file formats grouped by category."""
        categories = ScannerRegistry.get_categories()
        scanners = ScannerRegistry.get_scanners_info()
        
        return jsonify({
            'success': True,
            'total_formats': len(get_supported_extensions()),
            'categories': categories,
            'scanners': scanners,
        })

    @app.route('/clean/<filename>', methods=['GET', 'POST'])
    def clean_file(filename):
        """Manual and auto cleaning route."""
        info = session.get('last_upload')
        if not info or info.get('filename') != filename:
            flash('No dataset available for cleaning. Please scan a file first.', 'error')
            return redirect(url_for('upload_page'))

        path = info.get('path')
        df = pd.read_csv(path)
        anomalies = _detect_csv_anomalies_mod(df)

        if request.method == 'GET':
            # Default to manual review page if there are anomalies
            if anomalies:
                return render_template('review.html', anomalies=anomalies, filename=filename)
            else:
                # Or show a "no cleaning needed" message
                flash('No anomalies were found, no cleaning is necessary.', 'info')
                return redirect(url_for('scan_file'))

        # POST request handles the cleaning
        rows_to_remove_str = request.form.getlist('rows_to_remove')
        rows_to_remove = [int(r) for r in rows_to_remove_str if r]
        
        from utils.cleaner import manual_clean
        cleaned_df, report = manual_clean(df, rows_to_remove)
        
        cleaned_filename = os.path.splitext(filename)[0] + '_cleaned.csv'
        cleaned_path = os.path.join(app.config['UPLOAD_FOLDER'], cleaned_filename)
        cleaned_df.to_csv(cleaned_path, index=False)
        
        session['cleaned_csv'] = cleaned_path
        report['filename'] = filename
        report['cleaned_filename'] = cleaned_filename

        return render_template('clean.html', report=report)

    @app.route('/clean/auto/<filename>')
    def auto_clean_file(filename):
        """Auto-clean: Remove all High severity anomalies."""
        info = session.get('last_upload')
        if not info or info.get('filename') != filename:
            flash('No dataset available for cleaning. Please scan a file first.', 'error')
            return redirect(url_for('upload_page'))

        path = info.get('path')
        df = pd.read_csv(path)
        anomalies = _detect_csv_anomalies_mod(df)

        from utils.cleaner import auto_clean
        cleaned_df, report = auto_clean(df, anomalies)
        
        cleaned_filename = os.path.splitext(filename)[0] + '_cleaned.csv'
        cleaned_path = os.path.join(app.config['UPLOAD_FOLDER'], cleaned_filename)
        cleaned_df.to_csv(cleaned_path, index=False)
        
        session['cleaned_csv'] = cleaned_path
        report['filename'] = filename
        report['cleaned_filename'] = cleaned_filename

        return render_template('clean.html', report=report)

    @app.route('/train', methods=['GET'])
    def train_model():
        return render_template('train.html')

    @app.route('/train', methods=['POST'])
    def train_model_post():
        """Train a simple model on a cleaned CSV - starts async training and redirects to live console."""
        file = request.files.get('file')
        model_type = request.form.get('model_type', 'LogisticRegression')
        
        if not file or file.filename == '':
            flash('Please upload a cleaned CSV file.', 'error')
            return redirect(url_for('train_model'))
            
        filename = secure_filename(file.filename)
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(path)
        
        job_id = uuid.uuid4().hex[:8]
        session['training_job'] = {
            'job_id': job_id,
            'path': path,
            'model_type': model_type,
            'status': 'queued'
        }
        
        return redirect(url_for('train_live', job_id=job_id))
    
    @app.route('/train/live/<job_id>')
    def train_live(job_id):
        """Live training console page with SSE connection."""
        return render_template('train_live.html', job_id=job_id)
    
    @app.route('/train/stream/<job_id>')
    def train_stream(job_id):
        """Server-Sent Events stream for real-time training progress."""
        job = session.get('training_job')
        if not job or job.get('job_id') != job_id:
            return Response("data: {\"error\": \"Job not found\"}\n\n", mimetype='text/event-stream')
        
        def generate():
            try:
                path = job.get('path')
                model_type = job.get('model_type')
                df = pd.read_csv(path)
                
                for event in _train_model_streaming(df, model_type=model_type):
                    yield f"data: {json.dumps(event)}\n\n"
                    time.sleep(0.1)
                
                yield f"data: {json.dumps({'message': 'complete'})}\n\n"
                
            except Exception as e:
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
        
        return Response(stream_with_context(generate()), mimetype='text/event-stream')

    @app.route('/download/cleaned', methods=['GET'])
    def download_cleaned():
        path = session.get('cleaned_csv')
        if path and os.path.exists(path):
            return send_file(path, as_attachment=True)
        flash('Cleaned file is not available. Please run cleaning again.', 'error')
        return redirect(url_for('upload_page'))
    
    @app.route('/models')
    def models_dashboard():
        """Model comparison dashboard showing all trained models."""
        from model_trainer import HASHES_PATH, TRAINED_DIR
        try:
            with open(HASHES_PATH, 'r', encoding='utf-8') as f:
                models_data = json.load(f)
            
            models = []
            for m in models_data:
                # Handle both old and new format
                model_name = m.get('model_name') or m.get('file')
                model_hash = m.get('hash') or m.get('sha256')
                
                # Get accuracy from different formats
                if 'metrics' in m:
                    accuracy = m['metrics'].get('accuracy', 0)
                    precision = m['metrics'].get('precision', 0)
                    recall = m['metrics'].get('recall', 0)
                else:
                    accuracy = m.get('accuracy', 0)
                    precision = m.get('precision', 0)
                    recall = m.get('recall', 0)
                
                file_path = os.path.join(TRAINED_DIR, model_name)
                exists = os.path.exists(file_path)
                verified = False
                if exists and model_hash:
                    current_hash = _hash_file_util(file_path)
                    verified = (current_hash == model_hash)
                
                models.append({
                    "model_name": model_name,
                    "hash": model_hash,
                    "metrics": {
                        "accuracy": accuracy,
                        "precision": precision,
                        "recall": recall
                    },
                    "trained_at": m.get("trained_at"),
                    "verified": verified,
                    "exists": exists
                })

            models.sort(key=lambda x: x['metrics']['accuracy'], reverse=True)
            
            return render_template('models.html', models=models)
        except FileNotFoundError:
             return render_template('models.html', models=[])
        except Exception as e:
            flash(f'Error loading models: {e}', 'error')
            return render_template('models.html', models=[])
    
    @app.route('/models/download/<filename>')
    def download_model(filename):
        """Download a trained model file."""
        from model_trainer import TRAINED_DIR
        path = os.path.join(TRAINED_DIR, secure_filename(filename))
        if os.path.exists(path):
            return send_file(path, as_attachment=True)
        flash('Model file not found.', 'error')
        return redirect(url_for('models_dashboard'))
    
    @app.route('/models/delete/<filename>', methods=['POST'])
    def delete_model(filename):
        """Delete a trained model."""
        from model_trainer import TRAINED_DIR, HASHES_PATH
        filename = secure_filename(filename)
        path = os.path.join(TRAINED_DIR, filename)
        
        try:
            if os.path.exists(path):
                os.remove(path)
            
            # Remove from registry
            with open(HASHES_PATH, 'r', encoding='utf-8') as f:
                models = json.load(f)
            models = [m for m in models if m.get('file') != filename]
            with open(HASHES_PATH, 'w', encoding='utf-8') as f:
                json.dump(models, f, indent=2)
            
            flash(f'Model {filename} deleted successfully.', 'success')
        except Exception as e:
            flash(f'Error deleting model: {e}', 'error')
        
        return redirect(url_for('models_dashboard'))

def allowed_file(filename):
    """Check if file extension is allowed using config."""
    allowed = {'csv', 'png', 'jpg', 'jpeg', 'gif', 'bmp'}
    try:
        # Try to read allowed set from loaded config via current_app if available
        allowed = config.get('default').ALLOWED_EXTENSIONS  # fallback if app context missing
    except Exception:
        pass
    return _allowed_file_util(filename, allowed)

def calculate_file_hash(filepath):
    """Calculate SHA-256 hash of uploaded file"""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        # Read file in chunks to handle large files
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def _robust_z_score(series: pd.Series):
    """Compute robust z-scores using Median Absolute Deviation (MAD)."""
    s = pd.to_numeric(series, errors='coerce')
    med = np.nanmedian(s)
    mad = np.nanmedian(np.abs(s - med))
    if mad == 0 or np.isnan(mad):
        # Fallback to standard deviation if MAD is zero
        std = np.nanstd(s)
        if std == 0 or np.isnan(std):
            return pd.Series(np.zeros(len(s)), index=series.index)
        return (s - np.nanmean(s)) / std
    return 0.6745 * (s - med) / mad


def _iqr_bounds(series: pd.Series):
    """Return lower and upper bounds using IQR method."""
    s = pd.to_numeric(series, errors='coerce')
    q1 = np.nanpercentile(s, 25)
    q3 = np.nanpercentile(s, 75)
    iqr = q3 - q1
    lower = q1 - 1.5 * iqr
    upper = q3 + 1.5 * iqr
    return lower, upper


def _detect_csv_anomalies(df: pd.DataFrame, max_findings: int = 50):
    """Detect real anomalies in a CSV using robust statistics on numeric columns.
    - Uses robust z-score (MAD) and IQR fences per numeric column.
    - Aggregates per-row anomalies into severity and confidence.
    """
    anomalies = []
    if df.empty:
        return anomalies
    # Keep only numeric columns for detection
    num_df = df.select_dtypes(include=[np.number]).copy()
    if num_df.empty:
        return anomalies
    row_scores = np.zeros(len(num_df))
    detail_records = []
    for col in num_df.columns:
        rz = _robust_z_score(num_df[col])
        lower, upper = _iqr_bounds(num_df[col])

        # Flags
        z_flags = np.abs(rz) > 3.5
        iqr_flags = (num_df[col] < lower) | (num_df[col] > upper)
        flags = z_flags | iqr_flags

        # Accumulate row scores by magnitude
        row_scores += np.where(flags, np.minimum(np.abs(rz.fillna(0)), 10), 0)

        # Record detailed column anomalies
        flagged_idx = np.where(flags)[0]
        for idx in flagged_idx:
            value = num_df.iloc[idx][col]
            rz_val = float(rz.iloc[idx]) if not np.isnan(rz.iloc[idx]) else 0.0
            magnitude = min(abs(rz_val) / 4.0, 1.0)  # normalize
            severity = 'High' if abs(rz_val) > 5 else 'Medium' if abs(rz_val) > 4 else 'Low'
            detail_records.append({
                'row': int(idx) + 1,
                'column': col,
                'value': None if pd.isna(value) else (float(value) if isinstance(value, (int, float, np.floating, np.integer)) else value),
                'rz': rz_val,
                'severity': severity,
                'confidence': round(0.6 + 0.4 * magnitude, 2)
            })

    # Rank rows by total anomaly score
    top_indices = np.argsort(-row_scores)[:max_findings]
    for idx in top_indices:
        if row_scores[idx] <= 0:
            continue
        # Collect columns for this row
        cols = [d for d in detail_records if d['row'] == int(idx) + 1]
        if not cols:
            continue
        # Determine overall severity
        high = any(c['severity'] == 'High' for c in cols)
        med = any(c['severity'] == 'Medium' for c in cols)
        severity = 'High' if high else 'Medium' if med else 'Low'
        confidence = round(min(0.95, 0.5 + 0.05 * len(cols) + 0.02 * float(row_scores[idx])) , 2)
        columns_str = ', '.join(sorted({c['column'] for c in cols}))
        anomalies.append({
            'type': 'Data Outlier',
            'location': f'Row {int(idx) + 1} (Columns: {columns_str})',
            'severity': severity,
            'description': 'Robust statistical detection flagged outlier values (MAD/IQR).',
            'confidence': confidence
        })

    # If too few anomalies found, surface a few strongest individual column hits
    if len(anomalies) < 5 and detail_records:
        detail_records.sort(key=lambda d: abs(d['rz']), reverse=True)
        for d in detail_records[: (5 - len(anomalies))]:
            anomalies.append({
                'type': 'Column Outlier',
                'location': f"Row {d['row']}, Column '{d['column']}'",
                'severity': d['severity'],
                'description': 'Value deviates significantly from distribution (robust z-score).',
                'confidence': d['confidence']
            })

    # Integrate injection signature scan for text columns for this legacy path
    try:
        from utils.detection import detect_csv_anomalies as _mod
        return _mod(df, max_findings=max_findings)
    except Exception:
        return anomalies


def _analyze_image(filepath: str):
    """Detect basic image anomalies: potential manipulation (ELA) and blur (gradient variance)."""
    findings = []
    with Image.open(filepath) as img:
        img = img.convert('RGB')

        # Error Level Analysis (ELA) - approximate manipulation signal
        buf = BytesIO()
        img.save(buf, format='JPEG', quality=90)
        buf.seek(0)
        comp = Image.open(buf).convert('RGB')

        diff = ImageChops.difference(img, comp)
        diff_np = np.asarray(diff, dtype=np.uint8)
        ela_score = float(diff_np.mean())  # average difference

        # Heuristic thresholds (tunable)
        if ela_score > 12.0:
            findings.append({
                'type': 'Visual Manipulation',
                'location': 'Global',
                'severity': 'High' if ela_score > 20 else 'Medium',
                'description': 'Error Level Analysis suggests possible local recompression or edits.',
                'confidence': round(min(0.95, 0.5 + (ela_score / 40.0)), 2)
            })

        # Blur/Sharpness via simple gradient variance (no OpenCV dependency)
        gray = np.asarray(img.convert('L'), dtype=np.float32)
        # Simple finite differences
        gx = gray[:, 1:] - gray[:, :-1]
        gy = gray[1:, :] - gray[:-1, :]
        grad_mag = np.sqrt(gx[:, :-1] ** 2 + gy[:-1, :] ** 2)
        grad_var = float(np.var(grad_mag))

        if grad_var < 25.0:  # low gradient variance => possibly blurry
            findings.append({
                'type': 'Image Quality',
                'location': 'Global',
                'severity': 'Medium' if grad_var < 15 else 'Low',
                'description': 'Low edge/texture energy indicates blur or low-detail image.',
                'confidence': round(0.6 if grad_var < 20 else 0.55, 2)
            })

        # Dynamic range check (very narrow intensity spread)
        rng = float(gray.max() - gray.min())
        if rng < 30.0:
            findings.append({
                'type': 'Image Quality',
                'location': 'Global',
                'severity': 'Low',
                'description': 'Very low dynamic range; image may be washed out or overly compressed.',
                'confidence': 0.55
            })

    # Prefer modular implementation when available
    try:
        return _analyze_image_mod(filepath)
    except Exception:
        return findings


def simulate_anomaly_detection(filepath, file_type):
    """
    Perform anomaly detection on uploaded dataset using lightweight, real methods:
    - CSV: robust statistics (MAD-based z-scores and IQR fences) on numeric columns
    - Images: ELA (error level analysis) + blur/dynamic range checks
    """
    anomalies = []

    if file_type == 'csv':
        try:
            df = pd.read_csv(filepath)
            anomalies = _detect_csv_anomalies(df, max_findings=50)
        except Exception as e:
            anomalies.append({
                'type': 'File Error',
                'location': 'File processing',
                'severity': 'High',
                'description': f'Error reading CSV file: {str(e)}',
                'confidence': 1.0
            })

    elif file_type in ['png', 'jpg', 'jpeg', 'gif', 'bmp']:
        try:
            anomalies = _analyze_image(filepath)
        except Exception as e:
            anomalies.append({
                'type': 'File Error',
                'location': 'Image processing',
                'severity': 'High',
                'description': f'Error processing image: {str(e)}',
                'confidence': 1.0
            })

    return anomalies

def generate_anomaly_chart(anomalies):
    """Generate a chart visualization of anomalies using Plotly"""
    if not anomalies:
        return None
    
    # Count anomalies by severity
    severity_counts = {'High': 0, 'Medium': 0, 'Low': 0}
    for anomaly in anomalies:
        severity = anomaly.get('severity', 'Low')
        severity_counts[severity] += 1
    
    # Create pie chart
    fig = go.Figure(data=[go.Pie(
        labels=list(severity_counts.keys()),
        values=list(severity_counts.values()),
        marker_colors=['#dc3545', '#ffc107', '#28a745']  # Bootstrap colors
    )])
    
    fig.update_layout(
        title="Anomaly Distribution by Severity",
        font=dict(size=14),
        showlegend=True,
        height=400
    )
    
    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

# Create the app instance
app = create_app()

if __name__ == '__main__':
    app.run(debug=True)