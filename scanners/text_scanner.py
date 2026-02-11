"""
Text/NLP Scanner — TXT, JSONL, and text-based dataset formats
===============================================================

Detects:
- Prompt injection attacks
- Jailbreak patterns (DAN, roleplay, etc.)
- Toxic/harmful content
- PII leakage (emails, SSN, credit cards, etc.)
- Encoding attacks (homoglyphs, zero-width characters)
- Language anomalies
- Repetition attacks
- Length outliers

Supported formats:
- Plain text (.txt)
- JSON Lines (.jsonl)
- JSON (.json) - with text fields
- Markdown (.md)

"""

from __future__ import annotations
import os
import re
import json
from typing import List, Dict, Any, Optional, Set, Tuple
from collections import Counter
import unicodedata

from .base import BaseScanner, ScanResult, Anomaly, Severity
from .registry import ScannerRegistry


# Prompt injection and jailbreak patterns
JAILBREAK_PATTERNS = [
    # Direct instruction override
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", "Instruction override attempt"),
    (r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions?", "Instruction disregard attempt"),
    (r"forget\s+(all\s+)?(previous|prior|above)\s+instructions?", "Instruction forget attempt"),
    (r"do\s+not\s+follow\s+(previous|prior|your)\s+instructions?", "Instruction bypass attempt"),
    
    # Role-play attacks
    (r"you\s+are\s+now\s+(a|an|the)", "Role assignment attack"),
    (r"pretend\s+(you\s+are|to\s+be)", "Role pretend attack"),
    (r"act\s+as\s+(if\s+you\s+are|a|an)", "Role act-as attack"),
    (r"roleplay\s+as", "Roleplay attack"),
    (r"imagine\s+you\s+are", "Imagination prompt attack"),
    (r"from\s+now\s+on\s+you\s+(are|will)", "Persistent role attack"),
    
    # DAN-style jailbreaks
    (r"\bdan\b.*mode", "DAN mode jailbreak"),
    (r"do\s+anything\s+now", "DAN jailbreak"),
    (r"developer\s+mode", "Developer mode jailbreak"),
    (r"jailbreak\s*mode", "Jailbreak mode"),
    (r"sudo\s+mode", "Sudo mode jailbreak"),
    (r"god\s*mode", "God mode jailbreak"),
    (r"unrestricted\s+mode", "Unrestricted mode jailbreak"),
    (r"no\s+rules?\s+mode", "No rules mode"),
    
    # System prompt extraction
    (r"reveal\s+(your\s+)?(system|initial)\s+prompt", "System prompt extraction"),
    (r"show\s+(me\s+)?(your\s+)?system\s+prompt", "System prompt reveal"),
    (r"what\s+(is|are)\s+your\s+(system\s+)?instructions?", "Instruction extraction"),
    (r"print\s+(your\s+)?(system\s+)?prompt", "Prompt print attack"),
    (r"display\s+(your\s+)?hidden\s+prompt", "Hidden prompt extraction"),
    
    # Filter bypass
    (r"bypass\s+(the\s+)?(filter|safety|content)", "Filter bypass attempt"),
    (r"disable\s+(the\s+)?(filter|safety|censor)", "Filter disable attempt"),
    (r"turn\s+off\s+(the\s+)?(filter|safety)", "Safety turn-off attempt"),
    (r"without\s+(any\s+)?(filter|restriction)", "Restriction bypass"),
    
    # Hypothetical scenarios
    (r"hypothetically\s+(speaking\s+)?if", "Hypothetical bypass"),
    (r"for\s+(educational|research)\s+purposes?\s+only", "Educational excuse bypass"),
    (r"in\s+a\s+fictional\s+(world|scenario|story)", "Fictional world bypass"),
    (r"this\s+is\s+just\s+a\s+(game|test|simulation)", "Game/simulation bypass"),
    
    # Token smuggling
    (r"\[system\]", "Token smuggling [system]"),
    (r"\[assistant\]", "Token smuggling [assistant]"),
    (r"\[user\]", "Token smuggling [user]"),
    (r"<\|.*?\|>", "Special token injection"),
    (r"<<SYS>>", "Llama system token"),
    (r"\[INST\]", "Llama instruction token"),
]

# Toxic/harmful content patterns
TOXIC_PATTERNS = [
    # Violence
    (r"how\s+to\s+(make|build|create)\s+(a\s+)?(bomb|explosive|weapon)", "Violence: weapon creation"),
    (r"how\s+to\s+kill", "Violence: killing instructions"),
    (r"how\s+to\s+hurt", "Violence: harm instructions"),
    
    # Illegal activities
    (r"how\s+to\s+hack", "Illegal: hacking instructions"),
    (r"how\s+to\s+(steal|rob)", "Illegal: theft instructions"),
    (r"how\s+to\s+(make|cook|synthesize)\s+(meth|drugs|cocaine)", "Illegal: drug synthesis"),
    
    # Self-harm (handle sensitively)
    (r"how\s+to\s+(commit\s+)?suicide", "Self-harm content"),
    (r"ways\s+to\s+end\s+(my|your)\s+life", "Self-harm content"),
]

# PII patterns
PII_PATTERNS = [
    # Email
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "Email address"),
    
    # Phone numbers (various formats)
    (r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b", "Phone number"),
    (r"\(\d{3}\)\s*\d{3}[-.\s]?\d{4}", "Phone number (with parens)"),
    (r"\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}", "International phone"),
    
    # SSN
    (r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b", "Social Security Number"),
    
    # Credit cards
    (r"\b4[0-9]{12}(?:[0-9]{3})?\b", "Visa card number"),
    (r"\b5[1-5][0-9]{14}\b", "MasterCard number"),
    (r"\b3[47][0-9]{13}\b", "AmEx card number"),
    (r"\b6(?:011|5[0-9]{2})[0-9]{12}\b", "Discover card number"),
    
    # IP addresses
    (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "IP address"),
    
    # API keys (generic patterns)
    (r"\b(sk|pk)[-_][a-zA-Z0-9]{20,}\b", "API key pattern"),
    (r"\b[A-Za-z0-9]{32,}\b", "Possible API key or hash"),
]

# Compile all patterns
COMPILED_JAILBREAKS = [(re.compile(p, re.IGNORECASE), d) for p, d in JAILBREAK_PATTERNS]
COMPILED_TOXIC = [(re.compile(p, re.IGNORECASE), d) for p, d in TOXIC_PATTERNS]
COMPILED_PII = [(re.compile(p, re.IGNORECASE), d) for p, d in PII_PATTERNS]

# Unicode attack characters
HOMOGLYPHS = {
    'а': 'a', 'е': 'e', 'і': 'i', 'о': 'o', 'р': 'p',  # Cyrillic look-alikes
    'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H',  # Greek look-alikes
    '０': '0', '１': '1', '２': '2', '３': '3', '４': '4',  # Fullwidth digits
}

ZERO_WIDTH_CHARS = {
    '\u200b': 'ZERO WIDTH SPACE',
    '\u200c': 'ZERO WIDTH NON-JOINER',
    '\u200d': 'ZERO WIDTH JOINER',
    '\u2060': 'WORD JOINER',
    '\ufeff': 'ZERO WIDTH NO-BREAK SPACE',
}


@ScannerRegistry.register
class TextNLPScanner(BaseScanner):
    """
    Scanner for text and NLP dataset formats.
    
    Specialized for LLM training data security, detecting prompt injection,
    jailbreak patterns, toxic content, and PII leakage.
    """
    
    SUPPORTED_EXTENSIONS = {'txt', 'jsonl', 'md'}
    CATEGORY = "Text/NLP"
    NAME = "TextNLPScanner"
    
    # Configuration defaults
    DEFAULT_CONFIG = {
        'check_jailbreaks': True,
        'check_toxic': True,
        'check_pii': True,
        'check_encoding': True,
        'check_repetition': True,
        'check_length': True,
        'length_threshold_short': 10,      # Min characters for useful text
        'length_threshold_long': 50000,    # Max before flagging
        'repetition_threshold': 0.5,       # 50% repeated content
        'max_lines_to_scan': 10000,        # Limit for large files
        'text_field': None,                # For JSONL: field containing text
        'instruction_field': None,         # For JSONL: instruction field
        'response_field': None,            # For JSONL: response field
    }
    
    def _setup(self) -> None:
        """Merge config with defaults"""
        merged = dict(self.DEFAULT_CONFIG)
        merged.update(self.config)
        self.config = merged
    
    def detect(self, filepath: str, max_findings: int = 100) -> ScanResult:
        """
        Detect anomalies in text/NLP data.
        
        Args:
            filepath: Path to the file
            max_findings: Maximum anomalies to return
            
        Returns:
            ScanResult with detected anomalies
        """
        ext = self._get_extension(filepath)
        anomalies: List[Anomaly] = []
        metadata: Dict[str, Any] = {}
        
        # Load text content
        texts = self._load_texts(filepath, ext)
        metadata['total_records'] = len(texts)
        
        # Track statistics
        total_chars = sum(len(t.get('text', '')) for t in texts)
        metadata['total_characters'] = total_chars
        
        for idx, record in enumerate(texts[:self.config['max_lines_to_scan']]):
            text = record.get('text', '')
            if not text:
                continue
            
            location = f"Record {idx + 1}"
            if 'line' in record:
                location = f"Line {record['line']}"
            
            # 1. Jailbreak detection
            if self.config['check_jailbreaks']:
                jailbreak_findings = self._detect_jailbreaks(text, location)
                anomalies.extend(jailbreak_findings)
            
            # 2. Toxic content detection
            if self.config['check_toxic']:
                toxic_findings = self._detect_toxic(text, location)
                anomalies.extend(toxic_findings)
            
            # 3. PII detection
            if self.config['check_pii']:
                pii_findings = self._detect_pii(text, location)
                anomalies.extend(pii_findings)
            
            # 4. Encoding attacks
            if self.config['check_encoding']:
                encoding_findings = self._detect_encoding_attacks(text, location)
                anomalies.extend(encoding_findings)
            
            # 5. Length outliers
            if self.config['check_length']:
                length_findings = self._detect_length_anomalies(text, location)
                anomalies.extend(length_findings)
        
        # 6. Repetition detection (dataset-wide)
        if self.config['check_repetition']:
            repetition_findings = self._detect_repetition(texts)
            anomalies.extend(repetition_findings)
        
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
    
    def _load_texts(self, filepath: str, ext: str) -> List[Dict[str, Any]]:
        """Load text content from file"""
        texts = []
        
        try:
            if ext == 'jsonl':
                with open(filepath, 'r', encoding='utf-8') as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            record = json.loads(line)
                            text = self._extract_text_from_record(record)
                            texts.append({
                                'text': text,
                                'line': line_num,
                                'record': record,
                            })
                        except json.JSONDecodeError:
                            texts.append({
                                'text': line,
                                'line': line_num,
                            })
            
            elif ext in ('txt', 'md'):
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                    texts.append({
                        'text': content,
                        'line': 1,
                    })
            
            elif ext == 'json':
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        for idx, item in enumerate(data):
                            text = self._extract_text_from_record(item)
                            texts.append({
                                'text': text,
                                'line': idx + 1,
                                'record': item,
                            })
                    elif isinstance(data, dict):
                        text = self._extract_text_from_record(data)
                        texts.append({
                            'text': text,
                            'line': 1,
                            'record': data,
                        })
        
        except Exception as e:
            texts.append({
                'text': '',
                'error': str(e),
            })
        
        return texts
    
    def _extract_text_from_record(self, record: Any) -> str:
        """Extract text content from a JSON record"""
        if isinstance(record, str):
            return record
        
        if not isinstance(record, dict):
            return str(record)
        
        # Common field names for text in ML datasets
        text_fields = [
            self.config['text_field'],
            'text', 'content', 'message', 'body',
            'prompt', 'question', 'query',
            'input', 'instruction',
            'response', 'answer', 'output', 'completion',
        ]
        
        texts = []
        for field in text_fields:
            if field and field in record:
                value = record[field]
                if isinstance(value, str):
                    texts.append(value)
                elif isinstance(value, list):
                    texts.extend(str(v) for v in value if v)
        
        # If no known fields, concatenate all string values
        if not texts:
            for v in record.values():
                if isinstance(v, str) and len(v) > 20:
                    texts.append(v)
        
        return ' '.join(texts)
    
    def _detect_jailbreaks(self, text: str, location: str) -> List[Anomaly]:
        """Detect jailbreak and prompt injection patterns"""
        anomalies = []
        
        for pattern, description in COMPILED_JAILBREAKS:
            match = pattern.search(text)
            if match:
                matched_text = match.group()
                anomalies.append(Anomaly(
                    type="Jailbreak/Prompt Injection",
                    location=location,
                    severity=Severity.CRITICAL,
                    description=f"{description}: '{matched_text[:100]}'",
                    confidence=0.95,
                    category="LLM Security",
                    details={
                        'pattern_description': description,
                        'matched_text': matched_text[:200],
                        'position': match.start(),
                    },
                    remediation="Remove this record - it contains prompt injection/jailbreak content."
                ))
                break  # One match per record is enough
        
        return anomalies
    
    def _detect_toxic(self, text: str, location: str) -> List[Anomaly]:
        """Detect toxic/harmful content"""
        anomalies = []
        
        for pattern, description in COMPILED_TOXIC:
            match = pattern.search(text)
            if match:
                matched_text = match.group()
                anomalies.append(Anomaly(
                    type="Toxic/Harmful Content",
                    location=location,
                    severity=Severity.HIGH,
                    description=f"{description}: content matched pattern",
                    confidence=0.85,
                    category="Content Safety",
                    details={
                        'pattern_description': description,
                    },
                    remediation="Review and likely remove this content."
                ))
                break
        
        return anomalies
    
    def _detect_pii(self, text: str, location: str) -> List[Anomaly]:
        """Detect PII (Personally Identifiable Information)"""
        anomalies = []
        found_types = set()
        
        for pattern, pii_type in COMPILED_PII:
            if pii_type in found_types:
                continue  # Only report each type once per record
            
            match = pattern.search(text)
            if match:
                found_types.add(pii_type)
                matched_text = match.group()
                
                # Mask the PII for reporting
                masked = matched_text[:3] + '*' * (len(matched_text) - 6) + matched_text[-3:] if len(matched_text) > 6 else '***'
                
                anomalies.append(Anomaly(
                    type="PII Detected",
                    location=location,
                    severity=Severity.HIGH,
                    description=f"{pii_type} found: {masked}",
                    confidence=0.9,
                    category="Privacy",
                    details={
                        'pii_type': pii_type,
                        'masked_value': masked,
                    },
                    remediation="Remove or anonymize this PII before training."
                ))
        
        return anomalies
    
    def _detect_encoding_attacks(self, text: str, location: str) -> List[Anomaly]:
        """Detect Unicode encoding attacks"""
        anomalies = []
        
        # Check for zero-width characters
        for char, name in ZERO_WIDTH_CHARS.items():
            if char in text:
                count = text.count(char)
                anomalies.append(Anomaly(
                    type="Zero-Width Character",
                    location=location,
                    severity=Severity.MEDIUM,
                    description=f"Found {count} {name} characters - possible text obfuscation",
                    confidence=0.8,
                    category="Encoding",
                    details={
                        'character_name': name,
                        'count': count,
                    },
                    remediation="Remove zero-width characters to prevent hidden content."
                ))
                break  # Report once
        
        # Check for homoglyphs (look-alike characters)
        homoglyph_count = sum(1 for c in text if c in HOMOGLYPHS)
        if homoglyph_count > 3:
            anomalies.append(Anomaly(
                type="Homoglyph Attack",
                location=location,
                severity=Severity.MEDIUM,
                description=f"Found {homoglyph_count} look-alike characters (Cyrillic/Greek as Latin)",
                confidence=0.75,
                category="Encoding",
                details={
                    'homoglyph_count': homoglyph_count,
                },
                remediation="Normalize text to prevent visual spoofing attacks."
            ))
        
        # Check for RTL override characters
        if '\u202e' in text or '\u202d' in text:
            anomalies.append(Anomaly(
                type="RTL Override Attack",
                location=location,
                severity=Severity.HIGH,
                description="Right-to-Left override character detected - text direction manipulation",
                confidence=0.95,
                category="Encoding",
                remediation="Remove RTL override characters."
            ))
        
        return anomalies
    
    def _detect_length_anomalies(self, text: str, location: str) -> List[Anomaly]:
        """Detect unusual text lengths"""
        anomalies = []
        length = len(text)
        
        if length < self.config['length_threshold_short']:
            anomalies.append(Anomaly(
                type="Very Short Text",
                location=location,
                severity=Severity.LOW,
                description=f"Text has only {length} characters",
                confidence=0.6,
                category="Data Quality",
                details={'length': length},
                remediation="Short texts may not provide useful training signal."
            ))
        
        elif length > self.config['length_threshold_long']:
            anomalies.append(Anomaly(
                type="Very Long Text",
                location=location,
                severity=Severity.MEDIUM,
                description=f"Text has {length:,} characters - possible data dump or error",
                confidence=0.7,
                category="Data Quality",
                details={'length': length},
                remediation="Review long texts for data quality issues."
            ))
        
        return anomalies
    
    def _detect_repetition(self, texts: List[Dict[str, Any]]) -> List[Anomaly]:
        """Detect repeated content across records"""
        anomalies = []
        
        if len(texts) < 2:
            return anomalies
        
        # Count exact duplicates
        text_counts = Counter(t.get('text', '')[:1000] for t in texts)  # Use first 1000 chars
        
        duplicates = [(text, count) for text, count in text_counts.items() if count > 1 and len(text) > 50]
        
        if duplicates:
            total_dupes = sum(c - 1 for _, c in duplicates)
            worst_dupe = max(duplicates, key=lambda x: x[1])
            
            if total_dupes > len(texts) * 0.1:  # More than 10% duplicates
                anomalies.append(Anomaly(
                    type="Duplicate Content",
                    location="Dataset-wide",
                    severity=Severity.HIGH if total_dupes > len(texts) * 0.3 else Severity.MEDIUM,
                    description=f"Found {len(duplicates)} unique texts repeated {total_dupes} times total. Most repeated appears {worst_dupe[1]} times.",
                    confidence=0.9,
                    category="Data Quality",
                    details={
                        'unique_duplicates': len(duplicates),
                        'total_duplicate_instances': total_dupes,
                        'max_repetitions': worst_dupe[1],
                        'duplicate_ratio': total_dupes / len(texts),
                    },
                    remediation="Remove duplicate records to prevent overfitting."
                ))
        
        return anomalies
    
    def get_metadata(self, filepath: str) -> Dict[str, Any]:
        """Extract text-specific metadata"""
        base_meta = super().get_metadata(filepath)
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
                base_meta['character_count'] = len(content)
                base_meta['line_count'] = content.count('\n') + 1
                base_meta['word_count'] = len(content.split())
        except Exception as e:
            base_meta['read_error'] = str(e)
        
        return base_meta
