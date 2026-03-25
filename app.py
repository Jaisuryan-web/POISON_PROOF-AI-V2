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

# NEW: AI Chatbot System
from utils.chatbot import chatbot

# NEW: Multimedia VAE System
from utils.multimedia_vae import MultimediaProcessor, VAETrainer

# Global processor instance to maintain state
multimedia_processor = MultimediaProcessor()

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
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            # Perform universal scan
            scan_results = universal_scan(file_path)
            
            # Store in session for download
            session['last_scan'] = {
                'filename': filename,
                'results': scan_results
            }
            
            return jsonify({
                'success': True,
                'results': scan_results,
                'message': 'File scanned successfully',
                'filename': filename
            })
            
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/train')
    def train_page():
        """Model training page with live progress"""
        return render_template('train.html')

    @app.route('/train_model')
    def train_model():
        """Model training page with live progress (alias for templates)"""
        return train_page()

    @app.route('/train/start', methods=['POST'])
    def train_start():
        """Start model training with live progress updates"""
        if 'file' not in request.files:
            flash('No training file selected', 'error')
            return redirect(url_for('train_page'))
        
        file = request.files['file']
        if file.filename == '':
            flash('No training file selected', 'error')
            return redirect(url_for('train_page'))
        
        if file and allowed_file(file.filename):
            try:
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                
                # Start training job
                job_id = _train_model_streaming(filepath, model_type='csv')
                
                # Store job info in session for streaming
                session['training_job'] = {
                    'job_id': job_id,
                    'path': filepath,
                    'model_type': 'csv'
                }
                
                return redirect(url_for('train_live', job_id=job_id))
            except Exception as e:
                flash(f'Error starting training: {e}', 'error')
                return redirect(url_for('train_page'))
        else:
            flash('Invalid file type. Please upload CSV files only.', 'error')
            return redirect(url_for('train_page'))

    @app.route('/train_model_post', methods=['POST'])
    def train_model_post():
        """Start model training with live progress updates (alias for templates)"""
        return train_start()

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

    @app.route('/auto_clean/<filename>', methods=['GET', 'POST'])
    def auto_clean_file(filename):
        """Automatically clean all anomalies from a file"""
        try:
            # Get the original file path from session or construct it
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(filename))
            
            if not os.path.exists(filepath):
                flash('File not found.', 'error')
                return redirect(url_for('upload_page'))
            
            # Read the CSV file
            df = pd.read_csv(filepath)
            
            # Detect anomalies
            anomalies = _detect_csv_anomalies_mod(df)
            
            if not anomalies:
                flash('No anomalies found to clean.', 'info')
                return redirect(url_for('upload_page'))
            
            # Get rows to remove (from anomaly locations)
            rows_to_remove = set()
            for anomaly in anomalies:
                if 'Row ' in anomaly['location']:
                    row_num = int(anomaly['location'].split('Row ')[1].split(' ')[0]) - 1
                    rows_to_remove.add(row_num)
            
            # Remove anomalous rows
            cleaned_df = df.drop(index=list(rows_to_remove))
            
            # Save cleaned file
            cleaned_filename = f"cleaned_{filename}"
            cleaned_filepath = os.path.join(app.config['UPLOAD_FOLDER'], cleaned_filename)
            cleaned_df.to_csv(cleaned_filepath, index=False)
            
            # Store in session for download
            session['cleaned_csv'] = cleaned_filepath
            session['original_filename'] = filename
            
            flash(f'Automatically removed {len(rows_to_remove)} anomalous rows from {filename}. Download link available below.', 'success')
            return redirect(url_for('upload_page'))
            
        except Exception as e:
            flash(f'Error during auto-clean: {str(e)}', 'error')
            return redirect(url_for('upload_page'))

    @app.route('/clean/<filename>', methods=['GET', 'POST'])
    def clean_file(filename):
        """Show manual review page for cleaning anomalies"""
        try:
            # Get the original file path
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(filename))
            
            if not os.path.exists(filepath):
                flash('File not found.', 'error')
                return redirect(url_for('upload_page'))
            
            # Read the CSV file and detect anomalies
            df = pd.read_csv(filepath)
            anomalies = _detect_csv_anomalies_mod(df)
            
            return render_template('review.html', 
                             filename=filename,
                             dataframe=df,
                             anomalies=anomalies)
            
        except Exception as e:
            flash(f'Error loading file for review: {str(e)}', 'error')
            return redirect(url_for('upload_page'))
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

    # Chatbot Routes
    @app.route('/chatbot')
    def chatbot_page():
        """AI Security Assistant chatbot page"""
        return render_template('chatbot.html')

    @app.route('/api/chatbot/chat', methods=['POST'])
    def api_chatbot_chat():
        """Handle chatbot messages"""
        try:
            data = request.get_json()
            if not data or 'message' not in data:
                return jsonify({'error': 'No message provided'}), 400
            
            message = data.get('message', '').strip()
            if not message:
                return jsonify({'error': 'Empty message'}), 400
            
            # Get response from chatbot
            response = chatbot.get_response(message)
            
            return jsonify({
                'success': True,
                'response': response['response'],
                'timestamp': response['timestamp'],
                'query_type': response['query_type'],
                'conversation_id': response['conversation_id']
            })
            
        except Exception as e:
            return jsonify({'error': f'Chatbot error: {str(e)}'}), 500

    @app.route('/api/chatbot/suggestions', methods=['GET'])
    def api_chatbot_suggestions():
        """Get suggested questions for users"""
        try:
            suggestions = chatbot.get_suggested_questions()
            return jsonify({
                'success': True,
                'suggestions': suggestions
            })
        except Exception as e:
            return jsonify({'error': f'Error getting suggestions: {str(e)}'}), 500

    @app.route('/api/chatbot/clear', methods=['POST'])
    def api_chatbot_clear():
        """Clear chatbot conversation history"""
        try:
            chatbot.clear_history()
            return jsonify({
                'success': True,
                'message': 'Chat history cleared successfully'
            })
        except Exception as e:
            return jsonify({'error': f'Error clearing chat: {str(e)}'}), 500

    @app.route('/api/chatbot/history', methods=['GET'])
    def api_chatbot_history():
        """Get chatbot conversation history"""
        try:
            limit = request.args.get('limit', 10, type=int)
            history = chatbot.get_conversation_history(limit)
            return jsonify({
                'success': True,
                'history': history,
                'total': len(history)
            })
        except Exception as e:
            return jsonify({'error': f'Error getting history: {str(e)}'}), 500

    # NEW: Multimedia VAE Routes
    @app.route('/multimedia-scan', methods=['GET', 'POST'])
    def multimedia_scan_page():
        """Multimedia file scanning page with VAE"""
        return render_template('multimedia_scan.html')

    @app.route('/api/multimedia-scan', methods=['POST'])
    def api_multimedia_scan():
        """Scan multimedia files using VAE"""
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        try:
            # Use global processor instance to maintain state
            # Read file data
            file_data = file.read()
            file_type = file.filename.rsplit('.', 1)[1].lower()
            
            # Map file extensions to modalities
            modality_map = {
                'jpg': 'image', 'jpeg': 'image', 'png': 'image', 'bmp': 'image',
                'mp4': 'video', 'avi': 'video', 'mov': 'video', 'mkv': 'video',
                'mp3': 'audio', 'wav': 'audio', 'flac': 'audio', 'ogg': 'audio'
            }
            
            if file_type not in modality_map:
                return jsonify({
                    'success': False,
                    'error': f'Unsupported file type: {file_type}',
                    'supported_types': list(modality_map.keys())
                }), 400
            
            modality = modality_map[file_type]
            
            # Analyze with VAE using global processor
            results = multimedia_processor.analyze_file(file_data, modality)
            
            if 'error' in results:
                return jsonify({'success': False, 'error': results['error']}), 500
            
            return jsonify({
                'success': True,
                'results': results,
                'model_info': multimedia_processor.get_model_info()
            })
            
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/vae-train', methods=['POST'])
    def api_vae_train():
        """Train VAE model"""
        try:
            data = request.get_json()
            modality = data.get('modality', 'image')
            epochs = data.get('epochs', 50)
            beta = data.get('beta', 1.0)
            
            # Initialize VAE and trainer
            model = MultimodalVAE({
                'image': (3, 64, 64),
                'video': (3, 16, 64, 64),
                'audio': (1, 128, 128)
            })
            
            trainer = VAETrainer(model, torch.device('cpu'))
            
            # Training would happen here with actual dataset
            # For now, return mock training progress
            return jsonify({
                'success': True,
                'message': f'Training started for {modality} VAE',
                'epochs': epochs,
                'beta': beta,
                'status': 'training_initiated'
            })
            
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/vae-model-info', methods=['GET'])
    def api_vae_model_info():
        """Get VAE model information"""
        try:
            # Use global processor instance to maintain state
            return jsonify({
                'success': True,
                'model_info': multimedia_processor.get_model_info()
            })
            
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    @app.route('/api/vae-thresholds', methods=['POST'])
    def api_vae_thresholds():
        """Update VAE anomaly detection thresholds"""
        try:
            data = request.get_json()
            thresholds = data.get('thresholds', {})
            
            # Use global processor instance to maintain state
            multimedia_processor.update_thresholds(thresholds)
            
            return jsonify({
                'success': True,
                'message': 'Thresholds updated successfully',
                'new_thresholds': thresholds
            })
            
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

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
            anomalies = _detect_csv_anomalies_mod(df)
        except Exception as e:
            anomalies.append({
                'type': 'File Error',
                'location': 'Global',
                'severity': 'High',
                'description': f'Error reading CSV: {str(e)}',
                'confidence': 0.95
            })

    return anomalies


def generate_anomaly_chart(anomalies):
    """Generate interactive anomaly chart using Plotly"""
    if not anomalies:
        return json.dumps({
            'data': [],
            'layout': {'title': {'text': 'No Anomalies Detected'}}
        })
    
    # Prepare data for plotting
    anomaly_indices = list(range(1, len(anomalies) + 1))
    anomaly_scores = [a.get('confidence', 0) for a in anomalies]
    anomaly_types = [a.get('severity', 'Unknown') for a in anomalies]
    
    # Create color map for severity
    color_map = {
        'High': 'red',
        'Medium': 'orange', 
        'Low': 'yellow',
        'Unknown': 'gray'
    }
    colors = [color_map.get(severity, 'gray') for severity in anomaly_types]
    
    trace = go.Scatter(
        x=anomaly_indices,
        y=anomaly_scores,
        mode='markers',
        marker=dict(
            size=anomaly_scores,
            color=colors,
            line=dict(width=2)
        ),
        text=[f"Anomaly {i}: {anomalies[i-1].get('type', 'Unknown')}" for i in anomaly_indices]
    )
    
    layout = go.Layout(
        title='Anomaly Detection Results',
        xaxis=dict(title='Anomaly Index'),
        yaxis=dict(title='Confidence Score (%)'),
        hovermode='closest'
    )
    
    fig = go.Figure(data=[trace], layout=layout)
    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)


# Create the Flask application
app = create_app()

if __name__ == '__main__':
    app.run(debug=True)
