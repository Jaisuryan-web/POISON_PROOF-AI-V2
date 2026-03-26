"""
Multimedia Variational Autoencoder for Anomaly Detection
Supports Images, Videos, and Audio files for real-time analysis
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
import cv2
import librosa
from PIL import Image
import io
import base64
from typing import Dict, List, Tuple, Optional, Union
import json
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MultimodalVAE(nn.Module):
    """Variational Autoencoder for multimedia anomaly detection"""
    
    def __init__(self, input_dims: Dict[str, Tuple], latent_dim: int = 128):
        super(MultimodalVAE, self).__init__()
        self.input_dims = input_dims
        self.latent_dim = latent_dim
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        # Modality-specific encoders
        self.image_encoder = self._build_image_encoder()
        self.video_encoder = self._build_video_encoder()
        self.audio_encoder = self._build_audio_encoder()
        
        # Shared latent space
        self.fc_mu = nn.Linear(512, latent_dim)
        self.fc_logvar = nn.Linear(512, latent_dim)
        
        # Modality-specific decoders
        self.image_decoder = self._build_image_decoder()
        self.video_decoder = self._build_video_decoder()
        self.audio_decoder = self._build_audio_decoder()
        
        # Anomaly detection layers
        self.anomaly_detector = nn.Sequential(
            nn.Linear(latent_dim, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
            nn.Sigmoid()
        )
        
    def _build_image_encoder(self):
        """CNN encoder for images"""
        return nn.Sequential(
            nn.Conv2d(3, 32, 4, stride=2, padding=1),  # 64x64 -> 32x32
            nn.ReLU(),
            nn.Conv2d(32, 64, 4, stride=2, padding=1),  # 32x32 -> 16x16
            nn.ReLU(),
            nn.Conv2d(64, 128, 4, stride=2, padding=1),  # 16x16 -> 8x8
            nn.ReLU(),
            nn.Conv2d(128, 256, 4, stride=2, padding=1),  # 8x8 -> 4x4
            nn.ReLU(),
            nn.Flatten(),
            nn.Linear(256 * 4 * 4, 512)
        )
    
    def _build_video_encoder(self):
        """3D CNN encoder for video frames"""
        return nn.Sequential(
            nn.Conv3d(3, 32, (3, 4, 4), stride=(1, 2, 2), padding=(1, 1, 1)),
            nn.ReLU(),
            nn.Conv3d(32, 64, (3, 4, 4), stride=(1, 2, 2), padding=(1, 1, 1)),
            nn.ReLU(),
            nn.Conv3d(64, 128, (3, 4, 4), stride=(1, 2, 2), padding=(1, 1, 1)),
            nn.ReLU(),
            nn.AdaptiveAvgPool3d((1, 4, 4)),
            nn.Flatten(),
            nn.Linear(128 * 4 * 4, 512)
        )
    
    def _build_audio_encoder(self):
        """CNN encoder for audio spectrograms"""
        return nn.Sequential(
            nn.Conv2d(1, 32, 3, stride=2, padding=1),
            nn.ReLU(),
            nn.Conv2d(32, 64, 3, stride=2, padding=1),
            nn.ReLU(),
            nn.Conv2d(64, 128, 3, stride=2, padding=1),
            nn.ReLU(),
            nn.AdaptiveAvgPool2d((4, 4)),
            nn.Flatten(),
            nn.Linear(128 * 4 * 4, 512)
        )
    
    def _build_image_decoder(self):
        """CNN decoder for images"""
        return nn.Sequential(
            nn.Linear(self.latent_dim, 256 * 4 * 4),
            nn.ReLU(),
            nn.Unflatten(1, (256, 4, 4)),
            nn.ConvTranspose2d(256, 128, 4, stride=2, padding=1),  # 4x4 -> 8x8
            nn.ReLU(),
            nn.ConvTranspose2d(128, 64, 4, stride=2, padding=1),  # 8x8 -> 16x16
            nn.ReLU(),
            nn.ConvTranspose2d(64, 32, 4, stride=2, padding=1),  # 16x16 -> 32x32
            nn.ReLU(),
            nn.ConvTranspose2d(32, 3, 4, stride=2, padding=1),  # 32x32 -> 64x64
            nn.Sigmoid()
        )
    
    def _build_video_decoder(self):
        """3D CNN decoder for video"""
        return nn.Sequential(
            nn.Linear(self.latent_dim, 128 * 4 * 4),
            nn.ReLU(),
            nn.Unflatten(1, (128, 4, 4)),
            nn.Unflatten(1, (1, 128, 4, 4)),  # Add temporal dimension
            nn.ConvTranspose3d(128, 64, (3, 4, 4), stride=(1, 2, 2), padding=(1, 1, 1)),
            nn.ReLU(),
            nn.ConvTranspose3d(64, 32, (3, 4, 4), stride=(1, 2, 2), padding=(1, 1, 1)),
            nn.ReLU(),
            nn.ConvTranspose3d(32, 3, (3, 4, 4), stride=(1, 2, 2), padding=(1, 1, 1)),
            nn.Sigmoid()
        )
    
    def _build_audio_decoder(self):
        """CNN decoder for audio"""
        return nn.Sequential(
            nn.Linear(self.latent_dim, 128 * 4 * 4),
            nn.ReLU(),
            nn.Unflatten(1, (128, 4, 4)),
            nn.ConvTranspose2d(128, 64, 3, stride=2, padding=1),
            nn.ReLU(),
            nn.ConvTranspose2d(64, 32, 3, stride=2, padding=1),
            nn.ReLU(),
            nn.ConvTranspose2d(32, 1, 3, stride=2, padding=1),
            nn.Sigmoid()
        )
    
    def encode(self, x: torch.Tensor, modality: str) -> Tuple[torch.Tensor, torch.Tensor]:
        """Encode input to latent distribution"""
        if modality == 'image':
            h = self.image_encoder(x)
        elif modality == 'video':
            h = self.video_encoder(x)
        elif modality == 'audio':
            h = self.audio_encoder(x)
        else:
            raise ValueError(f"Unsupported modality: {modality}")
        
        mu = self.fc_mu(h)
        logvar = self.fc_logvar(h)
        return mu, logvar
    
    def reparameterize(self, mu: torch.Tensor, logvar: torch.Tensor) -> torch.Tensor:
        """Reparameterization trick"""
        std = torch.exp(0.5 * logvar)
        eps = torch.randn_like(std)
        return mu + eps * std
    
    def decode(self, z: torch.Tensor, modality: str) -> torch.Tensor:
        """Decode latent to reconstruction"""
        if modality == 'image':
            return self.image_decoder(z)
        elif modality == 'video':
            return self.video_decoder(z)
        elif modality == 'audio':
            return self.audio_decoder(z)
        else:
            raise ValueError(f"Unsupported modality: {modality}")
    
    def forward(self, x: torch.Tensor, modality: str) -> Dict[str, torch.Tensor]:
        """Forward pass"""
        mu, logvar = self.encode(x, modality)
        z = self.reparameterize(mu, logvar)
        x_recon = self.decode(z, modality)
        anomaly_score = self.anomaly_detector(z)
        
        return {
            'reconstruction': x_recon,
            'mu': mu,
            'logvar': logvar,
            'z': z,
            'anomaly_score': anomaly_score
        }
    
    def loss_function(self, recon_x: torch.Tensor, x: torch.Tensor, mu: torch.Tensor, 
                     logvar: torch.Tensor, anomaly_score: torch.Tensor, 
                     beta: float = 1.0) -> Dict[str, torch.Tensor]:
        """VAE loss with anomaly detection"""
        # Reconstruction loss
        recon_loss = F.mse_loss(recon_x, x, reduction='mean')
        
        # KL divergence
        kl_loss = -0.5 * torch.sum(1 + logvar - mu.pow(2) - logvar.exp())
        
        # Total VAE loss
        vae_loss = recon_loss + beta * kl_loss
        
        # Anomaly detection loss (using reconstruction error as supervision)
        reconstruction_error = F.mse_loss(recon_x, x, reduction='none')
        reconstruction_error = reconstruction_error.view(reconstruction_error.size(0), -1).mean(dim=1)
        anomaly_target = (reconstruction_error > reconstruction_error.median()).float()
        anomaly_loss = F.binary_cross_entropy(anomaly_score.squeeze(), anomaly_target)
        
        return {
            'total_loss': vae_loss + 0.1 * anomaly_loss,
            'recon_loss': recon_loss,
            'kl_loss': kl_loss,
            'anomaly_loss': anomaly_loss
        }

class MultimediaProcessor:
    """Real-time multimedia processing with VAE"""
    
    def __init__(self, model_path: Optional[str] = None):
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model = MultimodalVAE({
            'image': (3, 64, 64),
            'video': (3, 16, 64, 64),
            'audio': (1, 128, 128)
        }).to(self.device)
        
        if model_path:
            self.load_model(model_path)
        
        self.preprocessing = {
            'image': self._preprocess_image,
            'video': self._preprocess_video,
            'audio': self._preprocess_audio
        }
        
        self.thresholds = {
            'image': 0.7,
            'video': 0.6,
            'audio': 0.8
        }
    
    def load_model(self, model_path: str):
        """Load trained VAE model"""
        try:
            checkpoint = torch.load(model_path, map_location=self.device)
            self.model.load_state_dict(checkpoint['model_state_dict'])
            self.model.eval()
            logger.info(f"Model loaded from {model_path}")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
    
    def save_model(self, model_path: str):
        """Save trained VAE model"""
        torch.save({
            'model_state_dict': self.model.state_dict(),
            'thresholds': self.thresholds
        }, model_path)
    
    def _preprocess_image(self, image_data: Union[np.ndarray, bytes]) -> torch.Tensor:
        """Preprocess image for VAE"""
        if isinstance(image_data, bytes):
            image = Image.open(io.BytesIO(image_data))
        else:
            image = Image.fromarray(image_data)
        
        # Resize and normalize
        image = image.resize((64, 64)).convert('RGB')
        image_array = np.array(image) / 255.0
        image_tensor = torch.FloatTensor(image_array).permute(2, 0, 1)
        
        return image_tensor.unsqueeze(0).to(self.device)
    
    def _preprocess_video(self, video_data: bytes) -> torch.Tensor:
        """Preprocess video for VAE"""
        # Save video temporarily
        with open('temp_video.mp4', 'wb') as f:
            f.write(video_data)
        
        # Extract frames
        cap = cv2.VideoCapture('temp_video.mp4')
        frames = []
        
        while len(frames) < 16:  # Take first 16 frames
            ret, frame = cap.read()
            if not ret:
                break
            
            frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            frame = cv2.resize(frame, (64, 64))
            frame = frame / 255.0
            frames.append(frame)
        
        cap.release()
        
        # Pad if necessary
        while len(frames) < 16:
            frames.append(frames[-1] if frames else np.zeros((64, 64, 3)))
        
        video_array = np.array(frames)  # (16, 64, 64, 3)
        video_tensor = torch.FloatTensor(video_array).permute(3, 0, 1, 2)  # (3, 16, 64, 64)
        
        return video_tensor.unsqueeze(0).to(self.device)
    
    def _preprocess_audio(self, audio_data: bytes) -> torch.Tensor:
        """Preprocess audio for VAE"""
        # Load audio
        y, sr = librosa.load(io.BytesIO(audio_data), sr=22050)
        
        # Create mel spectrogram
        mel_spec = librosa.feature.melspectrogram(y=y, sr=sr, n_mels=128)
        mel_spec_db = librosa.power_to_db(mel_spec, ref=np.max)
        
        # Normalize and resize
        mel_spec_norm = (mel_spec_db - mel_spec_db.min()) / (mel_spec_db.max() - mel_spec_db.min())
        
        # Resize to 128x128
        mel_spec_resized = cv2.resize(mel_spec_norm, (128, 128))
        
        # Add channel dimension
        audio_tensor = torch.FloatTensor(mel_spec_resized).unsqueeze(0).unsqueeze(0)
        
        return audio_tensor.to(self.device)
    
    def analyze_file(self, file_data: bytes, file_type: str) -> Dict:
        """Analyze multimedia file for anomalies"""
        try:
            # Preprocess
            if file_type not in self.preprocessing:
                raise ValueError(f"Unsupported file type: {file_type}")
            
            x = self.preprocessing[file_type](file_data)
            
            # Map file extension to modality for threshold lookup
            modality_map = {
                'jpg': 'image', 'jpeg': 'image', 'png': 'image', 'bmp': 'image',
                'mp4': 'video', 'avi': 'video', 'mov': 'video', 'mkv': 'video',
                'mp3': 'audio', 'wav': 'audio', 'flac': 'audio', 'ogg': 'audio'
            }
            
            modality = modality_map.get(file_type, file_type)
            
            # VAE inference
            with torch.no_grad():
                results = self.model(x, modality)
                
                # Calculate reconstruction error
                recon_error = F.mse_loss(results['reconstruction'], x, reduction='none')
                recon_error = recon_error.view(recon_error.size(0), -1).mean(dim=1)
                
                # Anomaly detection
                anomaly_score = results['anomaly_score'].item()
                is_anomaly = anomaly_score > self.thresholds[modality]
                
                return {
                    'file_type': modality,
                    'anomaly_score': float(anomaly_score),
                    'reconstruction_error': float(recon_error.item()),
                    'is_anomaly': bool(is_anomaly),
                    'threshold': self.thresholds[modality],
                    'timestamp': datetime.now().isoformat(),
                    'analysis_details': {
                        'latent_mean': results['mu'].mean().item(),
                        'latent_std': results['mu'].std().item(),
                        'reconstruction_quality': 1.0 - float(recon_error.item())
                    }
                }
        
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return {
                'error': str(e),
                'file_type': file_type,
                'timestamp': datetime.now().isoformat()
            }
    
    def real_time_analyze(self, file_stream, file_type: str) -> Dict:
        """Real-time analysis for streaming data"""
        # Similar to analyze_file but optimized for real-time processing
        return self.analyze_file(file_stream, file_type)
    
    def update_thresholds(self, new_thresholds: Dict[str, float]):
        """Update anomaly detection thresholds"""
        self.thresholds.update(new_thresholds)
    
    def get_model_info(self) -> Dict:
        """Get model information"""
        total_params = sum(p.numel() for p in self.model.parameters())
        trainable_params = sum(p.numel() for p in self.model.parameters() if p.requires_grad)
        
        return {
            'model_type': 'Multimodal Variational Autoencoder',
            'total_parameters': total_params,
            'trainable_parameters': trainable_params,
            'device': str(self.device),
            'supported_modalities': ['image', 'video', 'audio'],
            'input_dimensions': self.model.input_dims,
            'latent_dimension': self.model.latent_dim,
            'current_thresholds': self.thresholds
        }

# Training utilities
class VAETrainer:
    """Trainer for multimodal VAE"""
    
    def __init__(self, model: MultimodalVAE, device: torch.device):
        self.model = model
        self.device = device
        self.optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
        self.training_history = []
    
    def train_epoch(self, dataloader, modality: str, beta: float = 1.0):
        """Train for one epoch"""
        self.model.train()
        total_loss = 0
        epoch_losses = {'recon_loss': 0, 'kl_loss': 0, 'anomaly_loss': 0}
        
        for batch_idx, (data, _) in enumerate(dataloader):
            data = data.to(self.device)
            
            self.optimizer.zero_grad()
            results = self.model(data, modality)
            
            losses = self.model.loss_function(
                results['reconstruction'], data,
                results['mu'], results['logvar'],
                results['anomaly_score'], beta
            )
            
            total_loss += losses['total_loss'].item()
            epoch_losses['recon_loss'] += losses['recon_loss'].item()
            epoch_losses['kl_loss'] += losses['kl_loss'].item()
            epoch_losses['anomaly_loss'] += losses['anomaly_loss'].item()
            
            losses['total_loss'].backward()
            self.optimizer.step()
        
        # Average losses
        num_batches = len(dataloader)
        avg_losses = {k: v / num_batches for k, v in epoch_losses.items()}
        avg_losses['total_loss'] = total_loss / num_batches
        
        return avg_losses
    
    def validate(self, dataloader, modality: str):
        """Validate model"""
        self.model.eval()
        total_loss = 0
        
        with torch.no_grad():
            for data, _ in dataloader:
                data = data.to(self.device)
                results = self.model(data, modality)
                
                losses = self.model.loss_function(
                    results['reconstruction'], data,
                    results['mu'], results['logvar'],
                    results['anomaly_score']
                )
                
                total_loss += losses['total_loss'].item()
        
        return total_loss / len(dataloader)

# Utility functions for data loading
def create_sample_data():
    """Create sample multimedia data for testing"""
    # This would be replaced with actual dataset loading
    pass

if __name__ == "__main__":
    # Test the VAE
    processor = MultimediaProcessor()
    print("Multimedia VAE initialized successfully!")
    print(processor.get_model_info())
