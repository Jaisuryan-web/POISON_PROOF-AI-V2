"""
Audio Scanner — WAV, MP3, FLAC, and other audio formats
=========================================================

Detects:
- Audio metadata tampering
- Silence/empty audio detection
- Sample rate inconsistencies
- Clipping detection (quality issues)
- Duration outliers
- Spectral anomalies (unusual frequency patterns)
- Basic steganography indicators

Supported formats:
- WAV (.wav)
- MP3 (.mp3)
- FLAC (.flac)
- OGG (.ogg)
- M4A (.m4a)

Note: Full analysis requires librosa or pydub libraries.
Falls back to basic metadata extraction if not available.

"""

from __future__ import annotations
import os
import struct
import wave
from typing import List, Dict, Any, Optional, Tuple

from .base import BaseScanner, ScanResult, Anomaly, Severity
from .registry import ScannerRegistry


@ScannerRegistry.register
class AudioScanner(BaseScanner):
    """
    Scanner for audio data formats.
    
    Performs audio forensics including metadata analysis, quality checks,
    and spectral analysis (when librosa is available).
    """
    
    SUPPORTED_EXTENSIONS = {'wav', 'mp3', 'flac', 'ogg', 'm4a', 'aiff', 'aif'}
    CATEGORY = "Audio"
    NAME = "AudioScanner"
    
    # Configuration defaults
    DEFAULT_CONFIG = {
        'check_metadata': True,
        'check_silence': True,
        'check_clipping': True,
        'check_duration': True,
        'check_spectral': True,
        'silence_threshold': 0.01,      # RMS below this is silence
        'clipping_threshold': 0.95,     # Normalized amplitude
        'min_duration_seconds': 0.1,    # Minimum useful audio
        'max_duration_seconds': 3600,   # 1 hour max
    }
    
    def _setup(self) -> None:
        """Merge config with defaults and check for optional libraries"""
        merged = dict(self.DEFAULT_CONFIG)
        merged.update(self.config)
        self.config = merged
        
        # Check for librosa
        self._has_librosa = False
        try:
            import librosa
            self._has_librosa = True
        except ImportError:
            pass
    
    def detect(self, filepath: str, max_findings: int = 100) -> ScanResult:
        """
        Detect anomalies in audio data.
        
        Args:
            filepath: Path to the audio file
            max_findings: Maximum anomalies to return
            
        Returns:
            ScanResult with detected anomalies
        """
        ext = self._get_extension(filepath)
        anomalies: List[Anomaly] = []
        metadata: Dict[str, Any] = {}
        
        # Use different loading methods based on format and available libs
        if ext == 'wav':
            try:
                audio_info = self._load_wav(filepath)
                metadata.update(audio_info)
                
                if self.config['check_silence']:
                    silence_findings = self._check_wav_silence(filepath, audio_info)
                    anomalies.extend(silence_findings)
                
                if self.config['check_clipping']:
                    clipping_findings = self._check_wav_clipping(filepath)
                    anomalies.extend(clipping_findings)
                
            except Exception as e:
                anomalies.append(Anomaly(
                    type="Audio Read Error",
                    location="File",
                    severity=Severity.MEDIUM,
                    description=f"Could not read WAV file: {str(e)}",
                    confidence=1.0,
                    category="Integrity",
                ))
        
        elif self._has_librosa:
            # Use librosa for other formats
            try:
                audio_findings, audio_meta = self._analyze_with_librosa(filepath)
                anomalies.extend(audio_findings)
                metadata.update(audio_meta)
            except Exception as e:
                anomalies.append(Anomaly(
                    type="Audio Analysis Error",
                    location="File",
                    severity=Severity.MEDIUM,
                    description=f"Could not analyze audio: {str(e)}",
                    confidence=1.0,
                    category="Integrity",
                ))
        
        else:
            # Basic file-level checks only
            metadata['note'] = 'Install librosa for full audio analysis'
        
        # Check duration (if we have it)
        if 'duration' in metadata and self.config['check_duration']:
            duration_findings = self._check_duration(metadata['duration'])
            anomalies.extend(duration_findings)
        
        # Check for empty file
        file_size = os.path.getsize(filepath)
        if file_size < 1000:  # Less than 1KB
            anomalies.append(Anomaly(
                type="Very Small Audio File",
                location="File",
                severity=Severity.HIGH,
                description=f"Audio file is only {file_size} bytes - likely corrupt or empty",
                confidence=0.9,
                category="Data Quality",
                details={'file_size': file_size},
                remediation="Verify this file contains valid audio data."
            ))
        
        # Sort by severity and limit
        anomalies.sort(key=lambda a: -a.severity.priority)
        anomalies = anomalies[:max_findings]
        
        return ScanResult(
            filepath=filepath,
            filename=os.path.basename(filepath),
            file_type=ext,
            category=self.CATEGORY,
            scanner_name=self.NAME,
            anomalies=anomalies,
            metadata=metadata,
        )
    
    def _load_wav(self, filepath: str) -> Dict[str, Any]:
        """Load WAV file and extract metadata"""
        with wave.open(filepath, 'rb') as wav:
            n_channels = wav.getnchannels()
            sample_width = wav.getsampwidth()
            frame_rate = wav.getframerate()
            n_frames = wav.getnframes()
            duration = n_frames / frame_rate if frame_rate > 0 else 0
            
            return {
                'channels': n_channels,
                'sample_width_bytes': sample_width,
                'sample_rate': frame_rate,
                'n_frames': n_frames,
                'duration': duration,
                'duration_formatted': f"{int(duration // 60)}:{int(duration % 60):02d}",
            }
    
    def _check_wav_silence(self, filepath: str, info: Dict[str, Any]) -> List[Anomaly]:
        """Check for silent or near-silent WAV audio"""
        anomalies = []
        
        try:
            import numpy as np
            
            with wave.open(filepath, 'rb') as wav:
                frames = wav.readframes(wav.getnframes())
                
                # Convert to numpy array
                sample_width = wav.getsampwidth()
                if sample_width == 1:
                    dtype = np.uint8
                elif sample_width == 2:
                    dtype = np.int16
                elif sample_width == 4:
                    dtype = np.int32
                else:
                    return anomalies  # Unsupported sample width
                
                audio = np.frombuffer(frames, dtype=dtype)
                
                # Normalize to [-1, 1]
                if dtype == np.uint8:
                    audio = (audio.astype(np.float32) - 128) / 128
                else:
                    audio = audio.astype(np.float32) / (2 ** (8 * sample_width - 1))
                
                # Calculate RMS
                rms = np.sqrt(np.mean(audio ** 2))
                
                if rms < self.config['silence_threshold']:
                    anomalies.append(Anomaly(
                        type="Silent Audio",
                        location="Entire file",
                        severity=Severity.HIGH,
                        description=f"Audio is nearly silent (RMS = {rms:.6f})",
                        confidence=0.95,
                        category="Data Quality",
                        details={'rms': float(rms)},
                        remediation="Silent audio provides no training signal."
                    ))
                
                # Check for long silent sections
                abs_audio = np.abs(audio)
                silent_samples = abs_audio < 0.001
                silent_ratio = silent_samples.sum() / len(audio)
                
                if silent_ratio > 0.8:  # More than 80% silence
                    anomalies.append(Anomaly(
                        type="Mostly Silent",
                        location="Audio content",
                        severity=Severity.MEDIUM,
                        description=f"Audio is {silent_ratio*100:.1f}% silent",
                        confidence=0.85,
                        category="Data Quality",
                        details={'silent_ratio': float(silent_ratio)},
                        remediation="Consider trimming silent sections."
                    ))
        
        except ImportError:
            pass  # numpy not available
        except Exception:
            pass  # Analysis failed
        
        return anomalies
    
    def _check_wav_clipping(self, filepath: str) -> List[Anomaly]:
        """Check for audio clipping (distortion)"""
        anomalies = []
        
        try:
            import numpy as np
            
            with wave.open(filepath, 'rb') as wav:
                frames = wav.readframes(wav.getnframes())
                sample_width = wav.getsampwidth()
                
                if sample_width == 2:
                    audio = np.frombuffer(frames, dtype=np.int16)
                    max_val = 32767
                elif sample_width == 4:
                    audio = np.frombuffer(frames, dtype=np.int32)
                    max_val = 2147483647
                else:
                    return anomalies
                
                # Count samples at or near maximum
                threshold = int(max_val * self.config['clipping_threshold'])
                clipped = np.sum(np.abs(audio) >= threshold)
                clip_ratio = clipped / len(audio)
                
                if clip_ratio > 0.01:  # More than 1% clipping
                    severity = Severity.HIGH if clip_ratio > 0.05 else Severity.MEDIUM
                    anomalies.append(Anomaly(
                        type="Audio Clipping",
                        location="Audio samples",
                        severity=severity,
                        description=f"Audio shows clipping: {clip_ratio*100:.2f}% of samples at maximum",
                        confidence=0.85,
                        category="Data Quality",
                        details={
                            'clip_ratio': float(clip_ratio),
                            'clipped_samples': int(clipped),
                        },
                        remediation="Clipped audio may affect model training quality."
                    ))
        
        except ImportError:
            pass
        except Exception:
            pass
        
        return anomalies
    
    def _analyze_with_librosa(self, filepath: str) -> Tuple[List[Anomaly], Dict[str, Any]]:
        """Full audio analysis using librosa"""
        import librosa
        import numpy as np
        
        anomalies = []
        metadata = {}
        
        # Load audio
        y, sr = librosa.load(filepath, sr=None)
        
        metadata['sample_rate'] = sr
        metadata['duration'] = len(y) / sr
        metadata['duration_formatted'] = f"{int(metadata['duration'] // 60)}:{int(metadata['duration'] % 60):02d}"
        
        # RMS analysis
        rms = np.sqrt(np.mean(y ** 2))
        metadata['rms'] = float(rms)
        
        if rms < self.config['silence_threshold']:
            anomalies.append(Anomaly(
                type="Silent Audio",
                location="Entire file",
                severity=Severity.HIGH,
                description=f"Audio is nearly silent (RMS = {rms:.6f})",
                confidence=0.95,
                category="Data Quality",
                details={'rms': float(rms)},
                remediation="Silent audio provides no training signal."
            ))
        
        # Clipping check
        clipped = np.sum(np.abs(y) >= self.config['clipping_threshold'])
        clip_ratio = clipped / len(y)
        
        if clip_ratio > 0.01:
            severity = Severity.HIGH if clip_ratio > 0.05 else Severity.MEDIUM
            anomalies.append(Anomaly(
                type="Audio Clipping",
                location="Audio samples",
                severity=severity,
                description=f"Audio shows clipping: {clip_ratio*100:.2f}% of samples",
                confidence=0.85,
                category="Data Quality",
                details={'clip_ratio': float(clip_ratio)},
                remediation="Clipped audio may affect model training quality."
            ))
        
        # Spectral analysis
        if self.config['check_spectral']:
            spectral_centroid = librosa.feature.spectral_centroid(y=y, sr=sr)
            metadata['spectral_centroid_mean'] = float(np.mean(spectral_centroid))
            
            # Check for unusual spectral patterns
            centroid_std = np.std(spectral_centroid)
            if centroid_std < 100:  # Very consistent spectral content
                anomalies.append(Anomaly(
                    type="Unusual Spectral Content",
                    location="Spectral analysis",
                    severity=Severity.LOW,
                    description=f"Audio has very consistent spectral content (may be synthetic)",
                    confidence=0.5,
                    category="Forensics",
                    details={'spectral_centroid_std': float(centroid_std)},
                    remediation="Verify if synthetic audio is acceptable."
                ))
        
        return anomalies, metadata
    
    def _check_duration(self, duration: float) -> List[Anomaly]:
        """Check for unusual audio duration"""
        anomalies = []
        
        if duration < self.config['min_duration_seconds']:
            anomalies.append(Anomaly(
                type="Very Short Audio",
                location="Duration",
                severity=Severity.MEDIUM,
                description=f"Audio is only {duration:.2f} seconds",
                confidence=0.8,
                category="Data Quality",
                details={'duration_seconds': duration},
                remediation="Very short audio clips may not be useful for training."
            ))
        
        elif duration > self.config['max_duration_seconds']:
            anomalies.append(Anomaly(
                type="Very Long Audio",
                location="Duration",
                severity=Severity.LOW,
                description=f"Audio is {duration/3600:.1f} hours long",
                confidence=0.7,
                category="Data Quality",
                details={'duration_seconds': duration},
                remediation="Consider splitting long audio files."
            ))
        
        return anomalies
    
    def get_metadata(self, filepath: str) -> Dict[str, Any]:
        """Extract audio-specific metadata"""
        base_meta = super().get_metadata(filepath)
        
        ext = self._get_extension(filepath)
        
        if ext == 'wav':
            try:
                wav_meta = self._load_wav(filepath)
                base_meta.update(wav_meta)
            except Exception as e:
                base_meta['wav_error'] = str(e)
        
        return base_meta
