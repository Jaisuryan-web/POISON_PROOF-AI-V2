"""
Image Scanner — PNG, JPG, TIFF, WebP, and other image formats
==============================================================

Detects:
- Error Level Analysis (ELA) for manipulation detection
- EXIF metadata tampering and editing software traces
- Entropy analysis for steganography detection
- Blur detection (quality issues)
- Dynamic range analysis
- Adversarial perturbation detection
- Synthetic/AI-generated image indicators

Supported formats:
- PNG (.png)
- JPEG (.jpg, .jpeg)
- GIF (.gif)
- BMP (.bmp)
- WebP (.webp)
- TIFF (.tiff, .tif)

"""

from __future__ import annotations
import os
import io
import numpy as np
from typing import List, Dict, Any, Optional, Tuple
from PIL import Image, ImageChops

from .base import BaseScanner, ScanResult, Anomaly, Severity
from .registry import ScannerRegistry


@ScannerRegistry.register
class ImageScanner(BaseScanner):
    """
    Scanner for image data formats.
    
    Performs image forensics including ELA, EXIF analysis, entropy detection,
    and quality metrics.
    """
    
    SUPPORTED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'tiff', 'tif'}
    CATEGORY = "Image"
    NAME = "ImageScanner"
    
    # Configuration defaults
    DEFAULT_CONFIG = {
        'ela_quality': 90,           # JPEG quality for ELA
        'ela_threshold_medium': 12.0,  # Mean ELA for Medium severity
        'ela_threshold_high': 20.0,    # Mean ELA for High severity
        'entropy_threshold_high': 7.8,  # High entropy (steganography)
        'entropy_threshold_low': 5.5,   # Low entropy (synthetic)
        'blur_threshold': 25.0,         # Gradient variance for blur
        'dynamic_range_threshold': 30,  # Min dynamic range
        'check_ela': True,
        'check_exif': True,
        'check_entropy': True,
        'check_blur': True,
        'check_dynamic_range': True,
        'check_adversarial': True,
    }
    
    # Known editing software indicators
    EDITING_SOFTWARE = [
        'photoshop', 'gimp', 'paint.net', 'affinity', 'lightroom',
        'capture one', 'corel', 'pixelmator', 'acorn', 'canva',
        'snapseed', 'vsco', 'afterlight', 'darkroom', 'luminar',
        'photopea', 'pixlr', 'fotor', 'befunky', 'picmonkey',
        'midjourney', 'dall-e', 'stable diffusion', 'openai',
    ]
    
    def _setup(self) -> None:
        """Merge config with defaults"""
        merged = dict(self.DEFAULT_CONFIG)
        merged.update(self.config)
        self.config = merged
    
    def validate(self, filepath: str) -> bool:
        """Validate image file is readable"""
        if not super().validate(filepath):
            return False
        
        try:
            with Image.open(filepath) as img:
                img.verify()
            return True
        except Exception:
            return False
    
    def detect(self, filepath: str, max_findings: int = 100) -> ScanResult:
        """
        Detect anomalies in image data.
        
        Args:
            filepath: Path to the image file
            max_findings: Maximum anomalies to return
            
        Returns:
            ScanResult with detected anomalies
        """
        ext = self._get_extension(filepath)
        anomalies: List[Anomaly] = []
        metadata: Dict[str, Any] = {}
        
        try:
            with Image.open(filepath) as img:
                # Extract basic metadata
                metadata = {
                    'width': img.width,
                    'height': img.height,
                    'format': img.format,
                    'mode': img.mode,
                    'megapixels': round(img.width * img.height / 1_000_000, 2),
                }
                
                # Convert to RGB for analysis
                if img.mode == 'RGBA':
                    rgb_img = img.convert('RGB')
                elif img.mode != 'RGB':
                    rgb_img = img.convert('RGB')
                else:
                    rgb_img = img.copy()
                
                # 1. Error Level Analysis
                if self.config['check_ela']:
                    ela_findings = self._analyze_ela(rgb_img)
                    anomalies.extend(ela_findings)
                
                # 2. EXIF Metadata Analysis
                if self.config['check_exif']:
                    exif_findings = self._analyze_exif(img)
                    anomalies.extend(exif_findings)
                    metadata['exif'] = self._extract_exif_summary(img)
                
                # 3. Entropy Analysis
                if self.config['check_entropy']:
                    entropy_findings = self._analyze_entropy(rgb_img)
                    anomalies.extend(entropy_findings)
                
                # 4. Blur Detection
                if self.config['check_blur']:
                    blur_findings = self._analyze_blur(rgb_img)
                    anomalies.extend(blur_findings)
                
                # 5. Dynamic Range Analysis
                if self.config['check_dynamic_range']:
                    range_findings = self._analyze_dynamic_range(rgb_img)
                    anomalies.extend(range_findings)
                
                # 6. Adversarial Detection (basic statistical checks)
                if self.config['check_adversarial']:
                    adv_findings = self._check_adversarial_indicators(rgb_img)
                    anomalies.extend(adv_findings)
        
        except Exception as e:
            anomalies.append(Anomaly(
                type="Image Processing Error",
                location="File",
                severity=Severity.MEDIUM,
                description=f"Could not fully analyze image: {str(e)}",
                confidence=1.0,
                category="Integrity",
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
    
    def _analyze_ela(self, img: Image.Image) -> List[Anomaly]:
        """
        Error Level Analysis - detects manipulation by comparing
        original image to recompressed version.
        """
        anomalies = []
        
        try:
            # Recompress as JPEG
            buffer = io.BytesIO()
            img.save(buffer, format='JPEG', quality=self.config['ela_quality'])
            buffer.seek(0)
            recompressed = Image.open(buffer)
            
            # Calculate difference
            diff = ImageChops.difference(img, recompressed)
            diff_array = np.array(diff)
            
            # Calculate ELA statistics
            ela_mean = np.mean(diff_array)
            ela_max = np.max(diff_array)
            ela_std = np.std(diff_array)
            
            # Analyze regional differences
            h, w = diff_array.shape[:2]
            block_size = max(h // 4, w // 4, 50)
            
            max_block_mean = 0
            max_block_pos = (0, 0)
            
            for y in range(0, h - block_size, block_size // 2):
                for x in range(0, w - block_size, block_size // 2):
                    block = diff_array[y:y+block_size, x:x+block_size]
                    block_mean = np.mean(block)
                    if block_mean > max_block_mean:
                        max_block_mean = block_mean
                        max_block_pos = (x, y)
            
            # Determine severity
            if ela_mean > self.config['ela_threshold_high']:
                severity = Severity.HIGH
                confidence = min(0.95, 0.7 + (ela_mean - 20) * 0.01)
                description = f"High ELA detected (mean={ela_mean:.1f}) - likely manipulated"
            elif ela_mean > self.config['ela_threshold_medium']:
                severity = Severity.MEDIUM
                confidence = 0.7
                description = f"Moderate ELA detected (mean={ela_mean:.1f}) - possible edits"
            else:
                # Low ELA - no anomaly to report
                return anomalies
            
            anomalies.append(Anomaly(
                type="ELA Manipulation",
                location=f"Region near ({max_block_pos[0]}, {max_block_pos[1]})",
                severity=severity,
                description=description,
                confidence=confidence,
                category="Forensics",
                details={
                    'ela_mean': float(ela_mean),
                    'ela_max': float(ela_max),
                    'ela_std': float(ela_std),
                    'max_block_mean': float(max_block_mean),
                    'max_block_position': max_block_pos,
                },
                remediation="This image may have been edited. Verify source authenticity."
            ))
            
        except Exception:
            pass  # ELA may fail for some formats
        
        return anomalies
    
    def _analyze_exif(self, img: Image.Image) -> List[Anomaly]:
        """Analyze EXIF metadata for tampering indicators."""
        anomalies = []
        
        try:
            exif = img._getexif() if hasattr(img, '_getexif') else None
            
            if exif is None:
                # Missing EXIF might indicate stripped metadata
                anomalies.append(Anomaly(
                    type="Missing EXIF Data",
                    location="Metadata",
                    severity=Severity.LOW,
                    description="Image has no EXIF metadata - may have been stripped",
                    confidence=0.5,
                    category="Metadata",
                    remediation="Missing EXIF is common but could indicate metadata was removed."
                ))
                return anomalies
            
            # Check for editing software
            software_tags = [305, 11]  # Software, ProcessingSoftware
            for tag_id in software_tags:
                if tag_id in exif:
                    software = str(exif[tag_id]).lower()
                    for editor in self.EDITING_SOFTWARE:
                        if editor in software:
                            severity = Severity.HIGH if editor in ['midjourney', 'dall-e', 'stable diffusion'] else Severity.MEDIUM
                            anomalies.append(Anomaly(
                                type="Editing Software Detected",
                                location="EXIF Software tag",
                                severity=severity,
                                description=f"Image was processed with: {exif[tag_id]}",
                                confidence=0.95,
                                category="Metadata",
                                details={'software': str(exif[tag_id])},
                                remediation="This image has been edited. Verify if edits are acceptable."
                            ))
                            break
            
            # Check for timestamp inconsistencies
            date_tags = {
                306: 'DateTime',
                36867: 'DateTimeOriginal',
                36868: 'DateTimeDigitized',
            }
            dates = {}
            for tag_id, name in date_tags.items():
                if tag_id in exif:
                    dates[name] = exif[tag_id]
            
            if len(dates) > 1:
                # Check if dates are inconsistent
                unique_dates = set(dates.values())
                if len(unique_dates) > 1:
                    anomalies.append(Anomaly(
                        type="EXIF Date Inconsistency",
                        location="EXIF Date tags",
                        severity=Severity.MEDIUM,
                        description=f"Multiple different dates found: {dates}",
                        confidence=0.7,
                        category="Metadata",
                        details={'dates': dates},
                        remediation="Inconsistent dates may indicate the image was modified."
                    ))
        
        except Exception:
            pass
        
        return anomalies
    
    def _extract_exif_summary(self, img: Image.Image) -> Dict[str, Any]:
        """Extract key EXIF fields for metadata"""
        summary = {}
        
        try:
            exif = img._getexif() if hasattr(img, '_getexif') else None
            if exif:
                # Common EXIF tags
                tag_names = {
                    271: 'make',
                    272: 'model',
                    305: 'software',
                    306: 'datetime',
                    36867: 'datetime_original',
                    37378: 'aperture',
                    37379: 'brightness',
                    33434: 'exposure_time',
                    34850: 'exposure_program',
                    34855: 'iso',
                }
                for tag_id, name in tag_names.items():
                    if tag_id in exif:
                        summary[name] = str(exif[tag_id])
        except Exception:
            pass
        
        return summary
    
    def _analyze_entropy(self, img: Image.Image) -> List[Anomaly]:
        """Entropy analysis for steganography detection."""
        anomalies = []
        
        try:
            gray = img.convert('L')
            pixels = np.array(gray).flatten()
            
            # Calculate Shannon entropy
            hist, _ = np.histogram(pixels, bins=256, range=(0, 256))
            hist = hist / hist.sum()  # Normalize
            hist = hist[hist > 0]  # Remove zeros
            entropy = -np.sum(hist * np.log2(hist))
            
            if entropy > self.config['entropy_threshold_high']:
                anomalies.append(Anomaly(
                    type="High Entropy",
                    location="Image pixels",
                    severity=Severity.MEDIUM,
                    description=f"Unusually high entropy ({entropy:.2f} bits) - possible steganography",
                    confidence=0.7,
                    category="Forensics",
                    details={'entropy': float(entropy)},
                    remediation="High entropy may indicate hidden data. Analyze with stego tools."
                ))
            elif entropy < self.config['entropy_threshold_low']:
                anomalies.append(Anomaly(
                    type="Low Entropy",
                    location="Image pixels",
                    severity=Severity.LOW,
                    description=f"Very low entropy ({entropy:.2f} bits) - synthetic or low-complexity image",
                    confidence=0.6,
                    category="Forensics",
                    details={'entropy': float(entropy)},
                    remediation="Low entropy is unusual for natural photographs."
                ))
        
        except Exception:
            pass
        
        return anomalies
    
    def _analyze_blur(self, img: Image.Image) -> List[Anomaly]:
        """Detect blur using gradient variance."""
        anomalies = []
        
        try:
            # Convert to grayscale numpy array
            gray = np.array(img.convert('L'), dtype=np.float64)
            
            # Calculate Laplacian variance (sharpness metric)
            # Simple Laplacian kernel approximation
            gy, gx = np.gradient(gray)
            gradient_magnitude = np.sqrt(gx**2 + gy**2)
            variance = np.var(gradient_magnitude)
            
            if variance < self.config['blur_threshold']:
                severity = Severity.HIGH if variance < 15 else Severity.MEDIUM
                anomalies.append(Anomaly(
                    type="Image Blur",
                    location="Entire image",
                    severity=severity,
                    description=f"Low gradient variance ({variance:.1f}) - image is blurry",
                    confidence=0.8,
                    category="Quality",
                    details={'gradient_variance': float(variance)},
                    remediation="Blurry images may reduce model quality. Consider removing."
                ))
        
        except Exception:
            pass
        
        return anomalies
    
    def _analyze_dynamic_range(self, img: Image.Image) -> List[Anomaly]:
        """Check for poor dynamic range (washed out images)."""
        anomalies = []
        
        try:
            gray = np.array(img.convert('L'))
            dynamic_range = int(np.max(gray)) - int(np.min(gray))
            
            if dynamic_range < self.config['dynamic_range_threshold']:
                anomalies.append(Anomaly(
                    type="Low Dynamic Range",
                    location="Entire image",
                    severity=Severity.MEDIUM if dynamic_range < 20 else Severity.LOW,
                    description=f"Poor dynamic range ({dynamic_range}/255) - washed out or over-compressed",
                    confidence=0.75,
                    category="Quality",
                    details={
                        'dynamic_range': dynamic_range,
                        'min_value': int(np.min(gray)),
                        'max_value': int(np.max(gray)),
                    },
                    remediation="Low contrast images may affect model training quality."
                ))
        
        except Exception:
            pass
        
        return anomalies
    
    def _check_adversarial_indicators(self, img: Image.Image) -> List[Anomaly]:
        """
        Basic checks for adversarial perturbation indicators.
        
        Note: Full adversarial detection requires ML models.
        This performs statistical heuristics.
        """
        anomalies = []
        
        try:
            pixels = np.array(img, dtype=np.float64)
            
            # Check for unusual pixel value distributions
            # Adversarial perturbations often create micro-patterns
            
            # 1. Check for excessive high-frequency noise
            if len(pixels.shape) == 3:
                # For each channel
                for c in range(pixels.shape[2]):
                    channel = pixels[:, :, c]
                    
                    # Simple edge detection
                    dy = np.abs(np.diff(channel, axis=0))
                    dx = np.abs(np.diff(channel, axis=1))
                    
                    # Calculate percentage of edges with exact value 1
                    # (common in some adversarial attacks)
                    one_edges_y = np.sum(dy == 1) / dy.size
                    one_edges_x = np.sum(dx == 1) / dx.size
                    
                    if one_edges_y > 0.3 or one_edges_x > 0.3:
                        anomalies.append(Anomaly(
                            type="Suspicious Pixel Pattern",
                            location=f"Color channel {c}",
                            severity=Severity.MEDIUM,
                            description="Unusual single-pixel differences detected - possible adversarial perturbation",
                            confidence=0.5,
                            category="Adversarial",
                            details={
                                'channel': c,
                                'one_edge_ratio_y': float(one_edges_y),
                                'one_edge_ratio_x': float(one_edges_x),
                            },
                            remediation="This image may contain adversarial perturbations. Verify with specialized tools."
                        ))
                        break
            
            # 2. Check for perfectly uniform regions (unusual in natural photos)
            std_per_row = np.std(pixels, axis=1)
            if np.mean(std_per_row) < 1.0:
                anomalies.append(Anomaly(
                    type="Synthetic Image Indicator",
                    location="Entire image",
                    severity=Severity.LOW,
                    description="Very low pixel variance - may be synthetic or heavily processed",
                    confidence=0.5,
                    category="Forensics",
                    details={'mean_row_std': float(np.mean(std_per_row))},
                    remediation="Verify image authenticity if natural photos are expected."
                ))
        
        except Exception:
            pass
        
        return anomalies
    
    def get_metadata(self, filepath: str) -> Dict[str, Any]:
        """Extract image-specific metadata"""
        base_meta = super().get_metadata(filepath)
        
        try:
            with Image.open(filepath) as img:
                base_meta.update({
                    'width': img.width,
                    'height': img.height,
                    'format': img.format,
                    'mode': img.mode,
                    'megapixels': round(img.width * img.height / 1_000_000, 2),
                })
        except Exception as e:
            base_meta['image_error'] = str(e)
        
        return base_meta
