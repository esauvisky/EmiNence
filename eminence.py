#!/usr/bin/env python3
"""
String Meaningfulness Analyzer

A GUI application for extracting strings from binary files (initially ELF files)
and using machine learning to assess their "meaningfulness" with interactive
user feedback for model training and fine-tuning.

Architecture:
- GUI Layer: Tkinter-based interface for file loading, string display, and labeling
- Data Layer: String extraction from binary files using elftools
- Feature Engineering: Comprehensive feature extraction from strings
- ML Layer: Scikit-learn based classification with feedback-driven learning
- Persistence Layer: Save/load models and labels
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import queue
import os
import re
import string
import math
import pickle
import json
import sys
import argparse
from collections import Counter, defaultdict
from datetime import datetime
import numpy as np
from typing import List, Dict, Tuple, Optional, Any
import time

# Binary parsing
try:
    import lief
    print("[Parser] lief library found. Advanced binary parsing enabled.")
except ImportError:
    print("lief library not found. This is a required dependency.")
    print("Please install it with: pip install lief")
    raise

# Machine Learning
try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report
except ImportError:
    print("Please install scikit-learn: pip install scikit-learn")
    raise

# GPU-accelerated ML (optional)
try:
    import xgboost as xgb
    XGB_AVAILABLE = True
    print("[ML] XGBoost available - GPU acceleration possible")
except ImportError:
    XGB_AVAILABLE = False
    print("[ML] XGBoost not available - install with: pip install xgboost")

try:
    import cupy as cp
    CUPY_AVAILABLE = True
    print("[ML] CuPy available - GPU array operations possible")
except ImportError:
    CUPY_AVAILABLE = False
    print("[ML] CuPy not available - install with: pip install cupy-cuda12x")

# Tokenization
try:
    import nltk
    from nltk.tokenize import word_tokenize
    from nltk.corpus import stopwords
    NLTK_AVAILABLE = True
    print("[NLP] NLTK available - tokenization possible")

    print("[NLP] Downloading NLTK data...")
    nltk.download('punkt', quiet=True)
    nltk.download('punkt_tab', quiet=True)
    nltk.download('stopwords', quiet=True)
    nltk.data.find('tokenizers/punkt')
    nltk.data.find('corpora/stopwords')

except ImportError:
    NLTK_AVAILABLE = False
    print("[NLP] NLTK not available - install with: pip install nltk")

# Google Gemini API (optional)
try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
    print("[LLM] Google Gemini API available")
except ImportError:
    GEMINI_AVAILABLE = False
    print("[LLM] Google Gemini API not available - install with: pip install google-generativeai")


class StringInfo:
    """Container for extracted string information"""
    def __init__(self, raw_bytes: bytes, decoded_text: str, offset: int,
                 section: str, encoding: str = 'utf-8'):
        self.raw_bytes = raw_bytes
        self.decoded_text = decoded_text
        self.offset = offset
        self.section = section
        self.encoding = encoding
        self.features = {}
        self.ml_score = 0.5  # Default neutral score
        self.user_label = None  # None, True (meaningful), or False (not meaningful)
        self.feedback_weight = 1.0  # Weight for training
        self.timestamp = datetime.now()


class StringExtractor:
    """Handles extraction of strings from binary files"""

    def __init__(self, min_length: int = 4, encodings: List[str] = None):
        self.min_length = min_length
        self.encodings = encodings or ['utf-8', 'latin-1', 'utf-16']

    def extract_from_file(self, filepath: str) -> List[StringInfo]:
        """
        Extract strings from a binary file using lief.
        It intelligently handles various formats like ELF, PE, Mach-O, and Android binaries.
        If a format is not recognized, it falls back to a raw scan of the file.
        """
        print(f"[StringExtractor] Starting extraction from: {filepath}")
        all_strings = []

        try:
            # lief.parse can handle lists of binaries (e.g., fat Mach-O)
            binaries = lief.parse(filepath)
            if not binaries:
                print(f"[StringExtractor] lief could not parse file, falling back to raw scan.")
                return self._perform_raw_scan(filepath)

            # Ensure we have a list to iterate over
            if not isinstance(binaries, list):
                binaries = [binaries]

            for binary in binaries:
                binary_name = os.path.basename(filepath)
                print(f"[StringExtractor] Processing binary: {binary_name} (type: {type(binary).__name__})")

                # Handle ELF files
                if isinstance(binary, lief.ELF.Binary):
                    for section in binary.sections:
                        if section.content and section.type != lief.ELF.Section.TYPE.NOBITS:
                            print(f"[StringExtractor]  - Scanning ELF section: {section.name} (size: {section.size})")
                            data = bytes(section.content)
                            all_strings.extend(self._extract_strings_from_data(data, str(section.name), section.offset))

                # Handle PE files
                elif isinstance(binary, lief.PE.Binary):
                    for section in binary.sections:
                        if section.content and section.sizeof_raw_data > 0:
                            print(f"[StringExtractor]  - Scanning PE section: {section.name} (size: {section.size})")
                            data = bytes(section.content)
                            all_strings.extend(self._extract_strings_from_data(data, str(section.name), section.pointerto_raw_data))

                # Handle Mach-O files
                elif isinstance(binary, lief.MachO.Binary):
                    for section in binary.sections:
                        if section.size > 0 and not (section.type == lief.MachO.Section.TYPE.ZEROFILL):
                            print(f"[StringExtractor]  - Scanning Mach-O section: {section.name} (size: {section.size})")
                            data = bytes(section.content)
                            all_strings.extend(self._extract_strings_from_data(data, str(section.name), section.offset))

                # Handle DEX files (Android)
                elif isinstance(binary, lief.DEX.File):
                    print(f"[StringExtractor]  - Extracting from DEX string table")
                    for i, s in enumerate(binary.strings):
                        try:
                            raw_bytes = s.encode('utf-8', errors='ignore')
                            if len(raw_bytes) >= self.min_length:
                                all_strings.append(StringInfo(
                                    raw_bytes=raw_bytes,
                                    decoded_text=s,
                                    offset=i,  # Use index as a pseudo-offset
                                    section="dex.strings"
                                ))
                        except Exception:
                            continue # Ignore decoding errors for individual strings

                # Handle OAT files (Android)
                elif isinstance(binary, lief.OAT.Binary):
                    print(f"[StringExtractor]  - Extracting from OAT container")
                    for dex_file in binary.dex_files:
                        for i, s in enumerate(dex_file.strings):
                            try:
                                raw_bytes = s.encode('utf-8', errors='ignore')
                                if len(raw_bytes) >= self.min_length:
                                    all_strings.append(StringInfo(
                                        raw_bytes=raw_bytes,
                                        decoded_text=s,
                                        offset=i,
                                        section="oat.dex.strings"
                                    ))
                            except Exception:
                                continue
                else:
                    print(f"[StringExtractor] Unhandled lief format: {type(binary).__name__}, falling back to raw scan for this part.")
                    # This part is tricky as we don't have raw bytes easily.
                    # The main fallback will handle the whole file if parsing fails initially.
                    return self._perform_raw_scan(filepath)
        except Exception as e:
            print(f"[StringExtractor] An unexpected error occurred during parsing: {e}")
            return self._perform_raw_scan(filepath)

        print(f"[StringExtractor] Total strings extracted: {len(all_strings)}")
        return all_strings

    def _perform_raw_scan(self, filepath: str) -> List[StringInfo]:
        """Performs a raw string extraction on the entire file."""
        print(f"[StringExtractor] Performing raw string extraction on {filepath}")
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            strings = self._extract_strings_from_data(data, "file_raw", 0)
            print(f"[StringExtractor] Total strings extracted from raw scan: {len(strings)}")
            return strings
        except Exception as e:
            print(f"[StringExtractor] Error reading file for raw extraction: {e}")
            return []

    def _extract_strings_from_data(self, data: bytes, section: str,
                                   base_offset: int) -> List[StringInfo]:
        """Extract printable strings from binary data"""
        strings = []
        current_string = bytearray()
        start_offset = 0
        candidates_found = 0

        for i, byte in enumerate(data):
            if 32 <= byte < 127 or byte in [9, 10, 13]:  # Printable + tab/newline
                if not current_string:
                    start_offset = i
                current_string.append(byte)
            else:
                if len(current_string) >= self.min_length:
                    candidates_found += 1
                    # Try to decode the string
                    decoded = self._try_decode(bytes(current_string))
                    if decoded:
                        strings.append(StringInfo(
                            raw_bytes=bytes(current_string),
                            decoded_text=decoded,
                            offset=base_offset + start_offset,
                            section=section
                        ))
                current_string = bytearray()

        # Handle last string
        if len(current_string) >= self.min_length:
            candidates_found += 1
            decoded = self._try_decode(bytes(current_string))
            if decoded:
                strings.append(StringInfo(
                    raw_bytes=bytes(current_string),
                    decoded_text=decoded,
                    offset=base_offset + start_offset,
                    section=section
                ))

        if candidates_found > 0:
            print(f"[StringExtractor] Section {section}: {candidates_found} candidates, {len(strings)} valid strings")

        return strings

    def _try_decode(self, data: bytes) -> Optional[str]:
        """Try to decode bytes with multiple encodings"""
        for encoding in self.encodings:
            try:
                return data.decode(encoding)
            except:
                continue
        return None


class FeatureExtractor:
    """Extract meaningful features from strings for ML classification"""

    def __init__(self):
        # Common programming/system keywords
        self.keywords = set(['function', 'error', 'warning', 'debug', 'info',
                            'init', 'main', 'start', 'stop', 'open', 'close',
                            'read', 'write', 'get', 'set', 'load', 'save'])

        # Common meaningful patterns
        self.patterns = {
            'path': re.compile(r'^[/\\]?(?:[a-zA-Z0-9_-]+[/\\])*[a-zA-Z0-9_.-]+$'),
            'url': re.compile(r'^https?://|www\.'),
            'email': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
            'function': re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*\(\)$'),
            'variable': re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$'),
            'version': re.compile(r'\d+\.\d+(?:\.\d+)?'),
        }

        # Load basic English word list (you could expand this)
        self.common_words = set(['the', 'be', 'to', 'of', 'and', 'a', 'in',
                                'that', 'have', 'i', 'it', 'for', 'not', 'on',
                                'with', 'he', 'as', 'you', 'do', 'at'])

        # Initialize tokenization
        if NLTK_AVAILABLE:
            try:
                self.stop_words = set(stopwords.words('english'))
            except:
                self.stop_words = set()
        else:
            self.stop_words = set()

    def extract_features(self, string_info: StringInfo) -> Dict[str, float]:
        """Extract features from a string"""
        text = string_info.decoded_text
        features = {}

        # Length features
        features['length'] = len(text)
        features['length_log'] = math.log(len(text) + 1)

        # Character type ratios
        alpha_count = sum(c.isalpha() for c in text)
        digit_count = sum(c.isdigit() for c in text)
        space_count = sum(c.isspace() for c in text)
        special_count = len(text) - alpha_count - digit_count - space_count

        features['alpha_ratio'] = alpha_count / len(text) if len(text) > 0 else 0
        features['digit_ratio'] = digit_count / len(text) if len(text) > 0 else 0
        features['space_ratio'] = space_count / len(text) if len(text) > 0 else 0
        features['special_ratio'] = special_count / len(text) if len(text) > 0 else 0

        # Case features
        features['has_upper'] = int(any(c.isupper() for c in text))
        features['has_lower'] = int(any(c.islower() for c in text))
        features['mixed_case'] = int(features['has_upper'] and features['has_lower'])

        # Entropy (randomness measure)
        features['entropy'] = self._calculate_entropy(text)

        # Pattern matching
        pattern_matches = 0
        for pattern_name, pattern in self.patterns.items():
            match = int(bool(pattern.search(text)))
            features[f'matches_{pattern_name}'] = match
            pattern_matches += match

        # Word-based features
        words = text.lower().split()
        features['word_count'] = len(words)
        features['avg_word_length'] = sum(len(w) for w in words) / len(words) if words else 0

        # Keyword presence
        text_lower = text.lower()
        features['has_keywords'] = int(any(kw in text_lower for kw in self.keywords))
        features['keyword_count'] = sum(kw in text_lower for kw in self.keywords)

        # Common word ratio
        if words:
            common_count = sum(w in self.common_words for w in words)
            features['common_word_ratio'] = common_count / len(words)
        else:
            features['common_word_ratio'] = 0

        # N-gram features
        features['has_repeating_chars'] = int(self._has_repeating_chars(text, 3))
        features['has_consonant_cluster'] = int(self._has_consonant_cluster(text))

        # Section-based features
        section_lower = string_info.section.lower()
        features['from_text_section'] = int('.text' in section_lower or '__text' in section_lower)
        features['from_data_section'] = int('.data' in section_lower or '__data' in section_lower)
        features['from_rodata_section'] = int('.rodata' in section_lower or 'const' in section_lower or '__cstring' in section_lower)
        features['from_rsrc_section'] = int('.rsrc' in section_lower)  # PE resources
        features['from_dex_strings'] = int('dex.strings' in section_lower or 'oat.dex.strings' in section_lower)  # Android DEX

        # Tokenization features
        if NLTK_AVAILABLE:
            token_features = self._extract_token_features(text)
            features.update(token_features)
        else:
            # Basic tokenization fallback
            features['token_count'] = len(text.split())
            features['unique_token_ratio'] = 0.0
            features['stop_word_ratio'] = 0.0
            features['avg_token_length'] = 0.0

        # Verbose output for interesting strings
        if (pattern_matches > 0 or features['keyword_count'] > 0 or
            features['common_word_ratio'] > 0.5 or len(text) > 50):
            print(f"[FeatureExtractor] Interesting string: '{text[:50]}...' "
                  f"(patterns: {pattern_matches}, keywords: {features['keyword_count']}, "
                  f"entropy: {features['entropy']:.2f})")

        # Store features in StringInfo
        string_info.features = features
        return features

    def _extract_token_features(self, text: str) -> Dict[str, float]:
        """Extract tokenization-based features"""
        features = {}

        try:
            # Tokenize the text
            tokens = word_tokenize(text.lower())

            # Basic token statistics
            features['token_count'] = len(tokens)

            if tokens:
                # Unique token ratio
                unique_tokens = set(tokens)
                features['unique_token_ratio'] = len(unique_tokens) / len(tokens)

                # Stop word ratio
                stop_word_count = sum(1 for token in tokens if token in self.stop_words)
                features['stop_word_ratio'] = stop_word_count / len(tokens)

                # Average token length
                features['avg_token_length'] = sum(len(token) for token in tokens) / len(tokens)

                # Alphabetic token ratio
                alpha_tokens = sum(1 for token in tokens if token.isalpha())
                features['alpha_token_ratio'] = alpha_tokens / len(tokens)

                # Numeric token ratio
                numeric_tokens = sum(1 for token in tokens if token.isdigit())
                features['numeric_token_ratio'] = numeric_tokens / len(tokens)

                # Mixed alphanumeric token ratio
                mixed_tokens = sum(1 for token in tokens if any(c.isalpha() for c in token) and any(c.isdigit() for c in token))
                features['mixed_token_ratio'] = mixed_tokens / len(tokens)

            else:
                features['unique_token_ratio'] = 0.0
                features['stop_word_ratio'] = 0.0
                features['avg_token_length'] = 0.0
                features['alpha_token_ratio'] = 0.0
                features['numeric_token_ratio'] = 0.0
                features['mixed_token_ratio'] = 0.0

        except Exception as e:
            print(f"[FeatureExtractor] Tokenization error: {e}")
            # Fallback to basic features
            features['token_count'] = len(text.split())
            features['unique_token_ratio'] = 0.0
            features['stop_word_ratio'] = 0.0
            features['avg_token_length'] = 0.0
            features['alpha_token_ratio'] = 0.0
            features['numeric_token_ratio'] = 0.0
            features['mixed_token_ratio'] = 0.0

        return features

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of string"""
        if not text:
            return 0

        char_counts = Counter(text)
        entropy = 0
        for count in char_counts.values():
            probability = count / len(text)
            entropy -= probability * math.log2(probability)

        return entropy

    def _has_repeating_chars(self, text: str, min_repeat: int) -> bool:
        """Check if string has repeating characters"""
        for i in range(len(text) - min_repeat + 1):
            if text[i:i+min_repeat] == text[i] * min_repeat:
                return True
        return False

    def _has_consonant_cluster(self, text: str) -> bool:
        """Check for unlikely consonant clusters (indicates random data)"""
        consonants = 'bcdfghjklmnpqrstvwxyz'
        consonant_run = 0

        for char in text.lower():
            if char in consonants:
                consonant_run += 1
                if consonant_run >= 5:  # 5+ consonants in a row is unusual
                    return True
            else:
                consonant_run = 0

        return False


class MLModelManager:
    """Manages the machine learning model for string classification"""

    def __init__(self, use_gpu=True):
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names = None
        self.is_trained = False
        self.training_history = []
        self.use_gpu = use_gpu and XGB_AVAILABLE
        self.gpu_available = self._check_gpu_availability()

        if self.use_gpu and self.gpu_available:
            print(f"[MLModelManager] GPU acceleration enabled")
        else:
            print(f"[MLModelManager] Using CPU-only mode")

    def _check_gpu_availability(self):
        """Check if GPU is available for XGBoost"""
        if not XGB_AVAILABLE:
            return False

        try:
            # Try to create a simple XGBoost model with GPU
            import subprocess
            result = subprocess.run(['nvidia-smi'], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"[MLModelManager] NVIDIA GPU detected")
                return True
        except:
            pass

        print(f"[MLModelManager] No compatible GPU found")
        return False

    def train_model(self, string_infos: List[StringInfo],
                   min_samples: int = 10) -> Tuple[bool, str]:
        """Train the ML model on labeled strings"""
        print(f"[MLModelManager] Starting model training...")

        # Filter for labeled strings
        labeled_strings = [s for s in string_infos if s.user_label is not None]
        print(f"[MLModelManager] Found {len(labeled_strings)} labeled strings out of {len(string_infos)} total")

        if len(labeled_strings) < min_samples:
            print(f"[MLModelManager] Insufficient labeled data: {len(labeled_strings)} < {min_samples}")
            return False, f"Need at least {min_samples} labeled examples (have {len(labeled_strings)})"

        # Prepare features and labels
        X = []
        y = []
        weights = []
        positive_count = 0
        negative_count = 0

        for string_info in labeled_strings:
            if string_info.features:
                feature_vector = [string_info.features[fname]
                                for fname in sorted(string_info.features.keys())]
                X.append(feature_vector)
                label = 1 if string_info.user_label else 0
                y.append(label)
                weights.append(string_info.feedback_weight)

                if label == 1:
                    positive_count += 1
                else:
                    negative_count += 1

        print(f"[MLModelManager] Training data: {positive_count} positive, {negative_count} negative samples")
        print(f"[MLModelManager] Feature vector size: {len(X[0]) if X else 0}")

        X = np.array(X)
        y = np.array(y)
        weights = np.array(weights)

        # Store feature names
        self.feature_names = sorted(labeled_strings[0].features.keys())
        print(f"[MLModelManager] Feature names: {self.feature_names[:5]}... (showing first 5)")

        # Scale features
        print(f"[MLModelManager] Scaling features...")
        X_scaled = self.scaler.fit_transform(X)

        # Train model with sample weights for RLHF-style learning
        if self.use_gpu and self.gpu_available:
            print(f"[MLModelManager] Training XGBoost model with GPU acceleration...")
            self.model = xgb.XGBClassifier(
                n_estimators=200,
                max_depth=8,
                learning_rate=0.1,
                random_state=42,
                tree_method='gpu_hist',  # GPU acceleration
                gpu_id=0,
                eval_metric='logloss',
                use_label_encoder=False
            )
        else:
            print(f"[MLModelManager] Training RandomForest model (CPU)...")
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                class_weight='balanced'  # Handle class imbalance
            )

        self.model.fit(X_scaled, y, sample_weight=weights)
        self.is_trained = True
        print(f"[MLModelManager] Model training completed")

        # Record training history
        self.training_history.append({
            'timestamp': datetime.now(),
            'n_samples': len(labeled_strings),
            'n_positive': sum(y),
            'n_negative': len(y) - sum(y)
        })

        # Evaluate on training data (in practice, should use validation set)
        predictions = self.model.predict(X_scaled)
        accuracy = np.mean(predictions == y)

        # Feature importance
        if hasattr(self.model, 'feature_importances_'):
            feature_importance = self.model.feature_importances_
            top_features = sorted(zip(self.feature_names, feature_importance),
                                 key=lambda x: x[1], reverse=True)[:5]
            print(f"[MLModelManager] Top 5 important features:")
            for fname, importance in top_features:
                print(f"  {fname}: {importance:.4f}")

        print(f"[MLModelManager] Training accuracy: {accuracy:.4f}")
        return True, f"Model trained successfully. Accuracy: {accuracy:.2f}"

    def predict_scores(self, string_infos: List[StringInfo]) -> None:
        """Predict meaningfulness scores for all strings"""
        if not self.is_trained:
            print(f"[MLModelManager] Cannot predict: model not trained")
            return

        print(f"[MLModelManager] Predicting scores for {len(string_infos)} strings...")

        # Collect all feature vectors and corresponding string_infos
        feature_vectors = []
        valid_strings = []

        for string_info in string_infos:
            if string_info.features:
                # Ensure features match training features
                feature_vector = [string_info.features.get(fname, 0)
                                for fname in self.feature_names]
                feature_vectors.append(feature_vector)
                valid_strings.append(string_info)

        if not feature_vectors:
            print(f"[MLModelManager] No valid feature vectors found")
            return

        # Batch prediction - much faster than individual predictions
        X = np.array(feature_vectors)
        X_scaled = self.scaler.transform(X)

        # Use GPU arrays if available and beneficial for large datasets
        if CUPY_AVAILABLE and len(feature_vectors) > 1000:
            print(f"[MLModelManager] Using GPU arrays for large dataset ({len(feature_vectors)} samples)")
            try:
                X_scaled_gpu = cp.asarray(X_scaled)
                # Convert back to CPU for sklearn/xgboost compatibility
                X_scaled = cp.asnumpy(X_scaled_gpu)
            except Exception as e:
                print(f"[MLModelManager] GPU array conversion failed, using CPU: {e}")

        # Get probabilities for all strings at once
        probabilities = self.model.predict_proba(X_scaled)

        # Assign scores back to string_infos
        predictions_made = 0
        high_confidence_predictions = 0

        for i, string_info in enumerate(valid_strings):
            string_info.ml_score = probabilities[i][1]  # Probability of class 1 (meaningful)
            predictions_made += 1

            # Count high confidence predictions
            if abs(string_info.ml_score - 0.5) > 0.3:  # >80% or <20% confidence
                high_confidence_predictions += 1

        print(f"[MLModelManager] Made {predictions_made} predictions, "
              f"{high_confidence_predictions} high confidence (>80% or <20%)")

    def update_feedback_weights(self, string_info: StringInfo,
                               was_correct: bool) -> None:
        """Update feedback weight based on model's previous prediction"""
        if was_correct:
            # Reduce weight for correct predictions
            string_info.feedback_weight *= 0.9
        else:
            # Increase weight for corrections, especially confident wrong predictions
            confidence = abs(string_info.ml_score - 0.5) * 2  # 0 to 1
            string_info.feedback_weight *= (1.5 + confidence)

        # Cap weights to prevent extreme values
        string_info.feedback_weight = min(max(string_info.feedback_weight, 0.1), 10.0)

    def save_model(self, filepath: str) -> None:
        """Save model and scaler to file"""
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'is_trained': self.is_trained,
            'training_history': self.training_history,
            'use_gpu': self.use_gpu,
            'model_type': 'xgboost' if isinstance(self.model, xgb.XGBClassifier) else 'sklearn'
        }
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)

    def load_model(self, filepath: str) -> None:
        """Load model and scaler from file"""
        with open(filepath, 'rb') as f:
            model_data = pickle.load(f)

        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.feature_names = model_data['feature_names']
        self.is_trained = model_data['is_trained']
        self.training_history = model_data.get('training_history', [])

        model_type = model_data.get('model_type', 'sklearn')
        print(f"[MLModelManager] Loaded {model_type} model")

        # Update GPU usage based on loaded model and current capabilities
        if model_type == 'xgboost' and not XGB_AVAILABLE:
            print(f"[MLModelManager] Warning: Model was trained with XGBoost but XGBoost not available")


class GeminiLabelingService:
    """Service for automated labeling using Google Gemini LLM"""

    def __init__(self):
        self.api_key = None
        self.model = None
        self.is_configured = False
        self.config_file = os.path.expanduser("~/.eminence_config.json")
        self._load_config()

    def configure(self, api_key: str) -> bool:
        """Configure the Gemini API"""
        if not GEMINI_AVAILABLE:
            return False

        try:
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel('gemini-2.0-flash-lite')
            self.api_key = api_key
            self.is_configured = True
            self._save_config()
            print("[GeminiService] Successfully configured Gemini API")
            return True
        except Exception as e:
            print(f"[GeminiService] Configuration failed: {e}")
            return False

    def _load_config(self):
        """Load API key from config file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    api_key = config.get('gemini_api_key')
                    if api_key:
                        self.configure(api_key)
                        print("[GeminiService] Loaded API key from config file")
        except Exception as e:
            print(f"[GeminiService] Error loading config: {e}")

    def _save_config(self):
        """Save API key to config file"""
        try:
            config = {}
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)

            config['gemini_api_key'] = self.api_key

            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            print(f"[GeminiService] Saved API key to {self.config_file}")
        except Exception as e:
            print(f"[GeminiService] Error saving config: {e}")

    def label_strings(self, strings: List[StringInfo]) -> List[Tuple[StringInfo, bool, str]]:
        """Label multiple strings using Gemini. Returns list of (string_info, is_meaningful, reasoning)"""
        if not self.is_configured:
            return []

        import concurrent.futures
        import json

        # Split into batches of 50
        batch_size = 50
        batches = [strings[i:i+batch_size] for i in range(0, len(strings), batch_size)]

        print(f"[GeminiService] Processing {len(strings)} strings in {len(batches)} parallel batches of {batch_size}")

        all_results = []

        def process_batch(batch_data):
            batch_idx, batch_strings = batch_data

            # Prepare batch prompt with JSON format
            prompt = """You are an expert reverse engineer analyzing strings extracted from binary files.
For each string below, determine if it is "meaningful" or "meaningless" for reverse engineering purposes.

Meaningful strings include:
- Function names, variable names, class names
- Error messages, debug messages, log messages
- File paths, URLs, configuration keys
- Human-readable text, documentation
- API endpoints, protocol strings
- Version information, build information

Meaningless strings include:
- Random data, encrypted/encoded data
- Binary artifacts, padding, alignment data
- Compiler-generated symbols without semantic meaning
- Memory addresses, raw pointers
- Gibberish, corrupted data

Respond with a JSON array where each object has:
- "index": the string index number
- "meaningful": true or false
- "reasoning": brief explanation

Example response:
[
  {"index": 0, "meaningful": true, "reasoning": "Function name pattern"},
  {"index": 1, "meaningful": false, "reasoning": "Random binary data"}
]

Here are the strings to analyze:

"""

            # Add strings to prompt
            for i, string_info in enumerate(batch_strings):
                # Truncate very long strings
                text = string_info.decoded_text
                if len(text) > 200:
                    text = text[:197] + "..."
                prompt += f"{i}: {repr(text)}\n"

            prompt += "\nRespond with only the JSON array, no other text:"

            try:
                print(f"[GeminiService] Batch {batch_idx + 1}/{len(batches)}: Sending {len(batch_strings)} strings...")
                response = self.model.generate_content(prompt)

                # Parse JSON response
                response_text = response.text.strip()

                # Try to extract JSON from response (in case there's extra text)
                start_idx = response_text.find('[')
                end_idx = response_text.rfind(']') + 1

                batch_results = []
                if start_idx != -1 and end_idx != 0:
                    json_text = response_text[start_idx:end_idx]

                    try:
                        parsed_results = json.loads(json_text)

                        for result in parsed_results:
                            if isinstance(result, dict) and all(key in result for key in ['index', 'meaningful', 'reasoning']):
                                index = int(result['index'])

                                if 0 <= index < len(batch_strings):
                                    is_meaningful = bool(result['meaningful'])
                                    reasoning = str(result['reasoning'])
                                    batch_results.append((batch_strings[index], is_meaningful, reasoning))

                    except json.JSONDecodeError as e:
                        print(f"[GeminiService] Batch {batch_idx + 1} JSON parsing failed: {e}")
                        print(f"[GeminiService] Response text: {response_text[:500]}...")
                else:
                    print(f"[GeminiService] Batch {batch_idx + 1} No JSON array found in response")
                    print(f"[GeminiService] Response text: {response_text[:500]}...")

                print(f"[GeminiService] Batch {batch_idx + 1} processed {len(batch_results)} out of {len(batch_strings)} strings")
                return batch_results

            except Exception as e:
                print(f"[GeminiService] Batch {batch_idx + 1} API call failed: {e}")
                return []

        # Process batches in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            # Submit all batches
            future_to_batch = {
                executor.submit(process_batch, (i, batch)): i
                for i, batch in enumerate(batches)
            }

            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_batch):
                batch_idx = future_to_batch[future]
                try:
                    batch_results = future.result()
                    all_results.extend(batch_results)
                except Exception as e:
                    print(f"[GeminiService] Batch {batch_idx + 1} failed with exception: {e}")

        print(f"[GeminiService] Total processed {len(all_results)} out of {len(strings)} strings across all batches")
        return all_results


class StringAnalyzerGUI:
    """Main GUI application for string analysis"""

    def __init__(self, root, initial_file=None):
        self.root = root
        self.root.title("String Meaningfulness Analyzer")
        self.root.geometry("1200x800")

        # Initialize components
        self.string_extractor = StringExtractor()
        self.feature_extractor = FeatureExtractor()
        self.model_manager = MLModelManager(use_gpu=True)  # Enable GPU by default
        self.gemini_service = GeminiLabelingService()

        # Data storage
        self.current_file = None
        self.strings: List[StringInfo] = []
        self.filtered_strings: List[StringInfo] = []

        # Threading
        self.task_queue = queue.Queue()

        # Build GUI
        self._build_gui()

        # Bind keyboard shortcuts
        self.root.bind('<Key-m>', lambda e: self._label_string(True))
        self.root.bind('<Key-n>', lambda e: self._label_string(False))
        self.root.bind('<Key-c>', lambda e: self._label_string(None))
        self.root.bind('<Key-space>', lambda e: self._select_next_unlabeled())

        # Start background task processor
        self.root.after(100, self._process_tasks)

        # Auto-load file if provided
        if initial_file:
            self.root.after(500, lambda: self._load_initial_file(initial_file))

    def _build_gui(self):
        """Build the GUI layout"""
        # Menu bar
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open Binary File...", command=self._open_file)
        file_menu.add_separator()
        file_menu.add_command(label="Save Labels...", command=self._save_labels)
        file_menu.add_command(label="Load Labels...", command=self._load_labels)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)

        # Model menu
        model_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Model", menu=model_menu)
        model_menu.add_command(label="Train Model", command=self._train_model)
        model_menu.add_command(label="Save Model...", command=self._save_model)
        model_menu.add_command(label="Load Model...", command=self._load_model)
        model_menu.add_separator()

        # GPU settings submenu
        gpu_menu = tk.Menu(model_menu, tearoff=0)
        model_menu.add_cascade(label="GPU Settings", menu=gpu_menu)

        self.gpu_enabled_var = tk.BooleanVar(value=XGB_AVAILABLE)
        gpu_menu.add_checkbutton(label="Enable GPU Acceleration",
                                variable=self.gpu_enabled_var,
                                command=self._toggle_gpu)

        gpu_status = "Available" if XGB_AVAILABLE else "Not Available"
        gpu_menu.add_command(label=f"GPU Status: {gpu_status}", state='disabled')

        model_menu.add_separator()
        model_menu.add_command(label="Clear All Labels", command=self._clear_labels)

        # LLM menu
        llm_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="LLM", menu=llm_menu)
        llm_menu.add_command(label="Configure Gemini API...", command=self._configure_gemini)
        llm_menu.add_command(label="Label Selected with Gemini", command=self._label_with_gemini)
        llm_menu.add_separator()

        gemini_status = "Available" if GEMINI_AVAILABLE else "Not Available"
        llm_menu.add_command(label=f"Gemini Status: {gemini_status}", state='disabled')

        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        # Top info panel
        info_frame = ttk.Frame(main_frame)
        info_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        self.file_label = ttk.Label(info_frame, text="No file loaded")
        self.file_label.grid(row=0, column=0, sticky=tk.W)

        self.stats_label = ttk.Label(info_frame, text="")
        self.stats_label.grid(row=0, column=1, sticky=tk.E, padx=(20, 0))

        info_frame.columnconfigure(1, weight=1)

        # Filter/search frame
        filter_frame = ttk.Frame(main_frame)
        filter_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Label(filter_frame, text="Filter:").grid(row=0, column=0, padx=(0, 5))

        self.filter_var = tk.StringVar()
        self.filter_var.trace('w', lambda *args: self._apply_filter())
        filter_entry = ttk.Entry(filter_frame, textvariable=self.filter_var, width=30)
        filter_entry.grid(row=0, column=1, padx=(0, 10))

        ttk.Label(filter_frame, text="Min Score:").grid(row=0, column=2, padx=(0, 5))
        self.min_score_var = tk.DoubleVar(value=0.0)
        score_scale = ttk.Scale(filter_frame, from_=0.0, to=1.0,
                               variable=self.min_score_var,
                               command=lambda v: self._apply_filter())
        score_scale.grid(row=0, column=3, padx=(0, 5))

        self.score_label = ttk.Label(filter_frame, text="0.00")
        self.score_label.grid(row=0, column=4)

        self.show_labeled_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(filter_frame, text="Show Labeled",
                       variable=self.show_labeled_var,
                       command=self._apply_filter).grid(row=0, column=5, padx=(10, 5))

        self.show_unlabeled_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(filter_frame, text="Show Unlabeled",
                       variable=self.show_unlabeled_var,
                       command=self._apply_filter).grid(row=0, column=6)

        self.training_mode_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(filter_frame, text="Training Mode",
                       variable=self.training_mode_var,
                       command=self._apply_filter).grid(row=0, column=7, padx=(10, 0))

        # String list
        list_frame = ttk.Frame(main_frame)
        list_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        main_frame.rowconfigure(2, weight=1)
        main_frame.columnconfigure(0, weight=3)

        # Treeview for strings
        columns = ('String', 'Length', 'Entropy', 'Score', 'Label', 'Section', 'Offset')
        self.tree = ttk.Treeview(list_frame, columns=columns, show='headings',
                                selectmode='extended')

        # Configure columns with sorting
        self.tree.heading('String', text='String')
        self.tree.heading('Length', text='Length', command=lambda: self._sort_by_column('Length'))
        self.tree.heading('Entropy', text='Entropy', command=lambda: self._sort_by_column('Entropy'))
        self.tree.heading('Score', text='ML Score', command=lambda: self._sort_by_column('Score'))
        self.tree.heading('Label', text='User Label')
        self.tree.heading('Section', text='Section')
        self.tree.heading('Offset', text='Offset')

        self.tree.column('String', width=300)
        self.tree.column('Length', width=60)
        self.tree.column('Entropy', width=70)
        self.tree.column('Score', width=80)
        self.tree.column('Label', width=100)
        self.tree.column('Section', width=100)
        self.tree.column('Offset', width=80)

        # Sorting state
        self.sort_column = None
        self.sort_reverse = False

        # Scrollbars
        vsb = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(list_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        vsb.grid(row=0, column=1, sticky=(tk.N, tk.S))
        hsb.grid(row=1, column=0, sticky=(tk.W, tk.E))

        list_frame.rowconfigure(0, weight=1)
        list_frame.columnconfigure(0, weight=1)

        # Bind selection event
        self.tree.bind('<<TreeviewSelect>>', self._on_string_select)

        # Right panel - Details and labeling
        right_frame = ttk.Frame(main_frame, padding="10")
        right_frame.grid(row=2, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(10, 0))
        main_frame.columnconfigure(1, weight=1)

        ttk.Label(right_frame, text="String Details",
                 font=('TkDefaultFont', 12, 'bold')).grid(row=0, column=0,
                                                          columnspan=2, pady=(0, 10))

        # Details text
        self.details_text = tk.Text(right_frame, height=10, width=40, wrap=tk.WORD)
        self.details_text.grid(row=1, column=0, columnspan=2,
                              sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))

        details_scroll = ttk.Scrollbar(right_frame, orient="vertical",
                                      command=self.details_text.yview)
        details_scroll.grid(row=1, column=2, sticky=(tk.N, tk.S))
        self.details_text.configure(yscrollcommand=details_scroll.set)

        right_frame.rowconfigure(1, weight=1)

        # Labeling buttons
        ttk.Label(right_frame, text="Label Selected String:").grid(row=2, column=0,
                                                                   columnspan=2, pady=(10, 5))

        button_frame = ttk.Frame(right_frame)
        button_frame.grid(row=3, column=0, columnspan=2)

        self.meaningful_btn = ttk.Button(button_frame, text="Meaningful",
                                        command=lambda: self._label_string(True),
                                        state='disabled')
        self.meaningful_btn.grid(row=0, column=0, padx=5)

        self.not_meaningful_btn = ttk.Button(button_frame, text="Not Meaningful",
                                            command=lambda: self._label_string(False),
                                            state='disabled')
        self.not_meaningful_btn.grid(row=0, column=1, padx=5)

        self.clear_label_btn = ttk.Button(button_frame, text="Clear Label",
                                         command=lambda: self._label_string(None),
                                         state='disabled')
        self.clear_label_btn.grid(row=0, column=2, padx=5)

        # Model actions
        ttk.Separator(right_frame, orient='horizontal').grid(row=4, column=0,
                                                            columnspan=2,
                                                            sticky=(tk.W, tk.E),
                                                            pady=20)

        ttk.Label(right_frame, text="Model Actions:").grid(row=5, column=0,
                                                           columnspan=2, pady=(0, 5))

        model_button_frame = ttk.Frame(right_frame)
        model_button_frame.grid(row=6, column=0, columnspan=2)

        ttk.Button(model_button_frame, text="Train/Retrain Model",
                  command=self._train_model).grid(row=0, column=0, padx=5, pady=2)

        ttk.Button(model_button_frame, text="Apply to All",
                  command=self._apply_model_to_all).grid(row=1, column=0, padx=5, pady=2)

        # Keyboard shortcuts info
        ttk.Separator(right_frame, orient='horizontal').grid(row=7, column=0,
                                                            columnspan=2,
                                                            sticky=(tk.W, tk.E),
                                                            pady=10)

        ttk.Label(right_frame, text="Keyboard Shortcuts:",
                 font=('TkDefaultFont', 10, 'bold')).grid(row=8, column=0,
                                                          columnspan=2, pady=(0, 5))

        shortcuts_text = """M - Mark as Meaningful
N - Mark as Not Meaningful
C - Clear Label
Space - Next Unlabeled"""

        shortcuts_label = ttk.Label(right_frame, text=shortcuts_text,
                                   font=('TkDefaultFont', 8))
        shortcuts_label.grid(row=9, column=0, columnspan=2, sticky=tk.W)

        # Status bar with progress
        status_frame = ttk.Frame(self.root)
        status_frame.grid(row=1, column=0, sticky=(tk.W, tk.E))
        status_frame.columnconfigure(0, weight=1)

        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(status_frame, textvariable=self.status_var,
                              relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=0, column=0, sticky=(tk.W, tk.E))

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(status_frame, variable=self.progress_var,
                                           maximum=100, length=200)
        self.progress_bar.grid(row=0, column=1, padx=(5, 0))
        self.progress_bar.grid_remove()  # Hide initially

    def _toggle_gpu(self):
        """Toggle GPU acceleration setting"""
        gpu_enabled = self.gpu_enabled_var.get()

        if gpu_enabled and not XGB_AVAILABLE:
            messagebox.showwarning("GPU Not Available",
                                 "XGBoost is required for GPU acceleration.\n"
                                 "Install with: pip install xgboost")
            self.gpu_enabled_var.set(False)
            return

        # Create new model manager with updated GPU setting
        self.model_manager = MLModelManager(use_gpu=gpu_enabled)

        status = "enabled" if gpu_enabled else "disabled"
        print(f"[GUI] GPU acceleration {status}")
        self.status_var.set(f"GPU acceleration {status}")

    def _open_file(self):
        """Open a binary file for analysis"""
        filename = filedialog.askopenfilename(
            title="Select Binary File",
            filetypes=[
                ("All Supported Files", "*.exe *.dll *.sys *.so *.o *.elf *.macho *.dylib *.a *.lib *.dex *.odex *.art *.vdex"),
                ("Windows Executables", "*.exe *.dll *.sys"),
                ("ELF Files", "*.elf *.so *.o"),
                ("Mach-O Files", "*.macho *.dylib"),
                ("Static Libraries", "*.a *.lib"),
                ("Android Files", "*.dex *.odex *.art *.vdex"),
                ("All files", "*.*")
            ]
        )

        if filename:
            self.current_file = filename
            self.file_label.config(text=f"File: {os.path.basename(filename)}")
            self.status_var.set("Extracting strings...")

            # Extract strings in background
            threading.Thread(target=self._extract_strings_thread,
                           args=(filename,), daemon=True).start()

    def _extract_strings_thread(self, filename):
        """Extract strings in background thread"""
        try:
            print(f"[GUI] Starting string extraction thread for: {filename}")

            # Show progress bar
            self.task_queue.put(('show_progress', True))
            self.task_queue.put(('update_progress', 10))

            # Extract strings
            print(f"[GUI] Calling string extractor...")
            strings = self.string_extractor.extract_from_file(filename)
            print(f"[GUI] String extraction completed, got {len(strings)} strings")
            self.task_queue.put(('update_progress', 50))

            # Extract features for each string
            print(f"[GUI] Starting feature extraction for {len(strings)} strings...")
            total_strings = len(strings)
            for i, string_info in enumerate(strings):
                self.feature_extractor.extract_features(string_info)
                if i % 100 == 0:  # Update progress every 100 strings
                    progress = 50 + (i / total_strings) * 40
                    self.task_queue.put(('update_progress', progress))
                    if i % 500 == 0:  # Log every 500 strings
                        print(f"[GUI] Feature extraction progress: {i}/{total_strings}")

            print(f"[GUI] Feature extraction completed")
            self.task_queue.put(('update_progress', 100))

            # Queue GUI update
            self.task_queue.put(('strings_extracted', strings))
            self.task_queue.put(('show_progress', False))

        except Exception as e:
            print(f"[GUI] Error in extraction thread: {str(e)}")
            self.task_queue.put(('show_progress', False))
            self.task_queue.put(('error', f"Error extracting strings: {str(e)}"))

    def _process_tasks(self):
        """Process tasks from background threads"""
        try:
            while True:
                task, data = self.task_queue.get_nowait()

                if task == 'strings_extracted':
                    self.strings = data
                    self.filtered_strings = data.copy()
                    self._update_string_list()
                    self._update_stats()
                    self.status_var.set(f"Extracted {len(self.strings)} strings")

                    # Apply model if trained
                    if self.model_manager.is_trained:
                        self._apply_model_to_all()

                elif task == 'show_progress':
                    if data:
                        self.progress_bar.grid()
                        self.progress_var.set(0)
                    else:
                        self.progress_bar.grid_remove()

                elif task == 'update_progress':
                    self.progress_var.set(data)

                elif task == 'model_trained':
                    success, message = data
                    if success:
                        messagebox.showinfo("Training Complete", message)
                        self.status_var.set("Model trained successfully")
                        # Apply model to all strings
                        self._apply_model_to_all()
                    else:
                        messagebox.showwarning("Training Failed", message)

                elif task == 'model_applied':
                    self._update_string_list()
                    self.status_var.set("Model applied to all strings")
                    # Unselect training mode after inference
                    if self.training_mode_var.get():
                        self.training_mode_var.set(False)
                        self._apply_filter()  # Refresh the display

                elif task == 'error':
                    messagebox.showerror("Error", data)
                    self.status_var.set("Error occurred")

        except queue.Empty:
            pass

        # Schedule next check
        self.root.after(100, self._process_tasks)

    def _update_string_list(self):
        """Update the treeview with current filtered strings"""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Add filtered strings
        for i, string_info in enumerate(self.filtered_strings):
            # Determine label text
            if string_info.user_label is True:
                label_text = "Meaningful"
            elif string_info.user_label is False:
                label_text = "Not Meaningful"
            else:
                label_text = ""

            # Format score
            score_text = f"{string_info.ml_score:.3f}"

            # Truncate long strings for display
            display_text = string_info.decoded_text
            if len(display_text) > 100:
                display_text = display_text[:97] + "..."

            # Insert into tree
            entropy_text = f"{string_info.features.get('entropy', 0):.3f}" if string_info.features else "0.000"

            self.tree.insert('', 'end', values=(
                display_text,
                len(string_info.decoded_text),
                entropy_text,
                score_text,
                label_text,
                string_info.section,
                f"0x{string_info.offset:08x}"
            ))

    def _update_stats(self):
        """Update statistics label"""
        total = len(self.strings)
        labeled = sum(1 for s in self.strings if s.user_label is not None)
        meaningful = sum(1 for s in self.strings if s.user_label is True)
        not_meaningful = sum(1 for s in self.strings if s.user_label is False)

        if self.training_mode_var.get():
            stats_text = (f"Training Mode: {len(self.filtered_strings)} selected | "
                         f"Total: {total} | Labeled: {labeled}")
        else:
            stats_text = (f"Total: {total} | Labeled: {labeled} | "
                         f"Meaningful: {meaningful} | Not Meaningful: {not_meaningful}")
        self.stats_label.config(text=stats_text)

    def _apply_filter(self):
        """Apply current filter settings"""
        filter_text = self.filter_var.get().lower()
        min_score = self.min_score_var.get()
        show_labeled = self.show_labeled_var.get()
        show_unlabeled = self.show_unlabeled_var.get()
        training_mode = self.training_mode_var.get()

        # Update score label
        self.score_label.config(text=f"{min_score:.2f}")

        # Filter strings
        if training_mode:
            self.filtered_strings = self._get_training_mode_strings()
            # Sort training mode strings by ML score in descending order
            self.filtered_strings.sort(key=lambda s: s.ml_score, reverse=True)
        else:
            self.filtered_strings = []

            for string_info in self.strings:
                # Check filter text
                if filter_text and filter_text not in string_info.decoded_text.lower():
                    continue

                # Check score
                if string_info.ml_score < min_score:
                    continue

                # Check label status
                if string_info.user_label is None and not show_unlabeled:
                    continue
                if string_info.user_label is not None and not show_labeled:
                    continue

                self.filtered_strings.append(string_info)

        self._update_string_list()

    def _get_training_mode_strings(self):
        """Get 100 unlabeled strings focusing on potential misclassifications"""
        import random
        import numpy as np

        # Step 1: Filter all unlabeled entries
        unlabeled_strings = [s for s in self.strings if s.user_label is None]

        if len(unlabeled_strings) < 100:
            print(f"[GUI] Training mode: Only {len(unlabeled_strings)} unlabeled strings available")
            return unlabeled_strings

        # Ensure features are extracted for all unlabeled strings
        for string_info in unlabeled_strings:
            if not string_info.features:
                self.feature_extractor.extract_features(string_info)

        unlabeled_scores = [s.ml_score for s in unlabeled_strings]
        mean_score = np.mean(unlabeled_scores)
        std_score = np.std(unlabeled_scores)

        print(f"[GUI] Training mode: {len(unlabeled_strings)} unlabeled strings")
        print(f"[GUI] Training mode: ML score stats - mean: {mean_score:.3f}, std: {std_score:.3f}")
        print(f"[GUI] Training mode: Score range: {min(unlabeled_scores):.3f} to {max(unlabeled_scores):.3f}")

        # Step 2: Prioritize strings likely to be misclassified
        training_strings = []

        # Category 1: Decision boundary (40 strings) - most uncertain predictions
        boundary_strings = [s for s in unlabeled_strings if 0.3 <= s.ml_score <= 0.7]
        if boundary_strings:
            sample_size = min(40, len(boundary_strings))
            sampled_boundary = random.sample(boundary_strings, sample_size)
            training_strings.extend(sampled_boundary)
            print(f"[GUI] Training mode: Decision boundary (0.3-0.7): {len(boundary_strings)} available, sampled {sample_size}")

        # Category 2: High-confidence low scores (20 strings) - potential false negatives
        # These might be meaningful strings the model thinks are meaningless
        low_conf_strings = [s for s in unlabeled_strings if s.ml_score <= 0.2]
        if low_conf_strings:
            # Prioritize strings with features that suggest meaningfulness
            meaningful_features = []
            for s in low_conf_strings:
                score = 0
                if s.features:
                    # Look for features that suggest meaningfulness
                    score += s.features.get('has_keywords', 0) * 3
                    score += s.features.get('common_word_ratio', 0) * 2
                    score += s.features.get('matches_path', 0) * 2
                    score += s.features.get('matches_url', 0) * 2
                    score += s.features.get('matches_email', 0) * 2
                    score += s.features.get('word_count', 0) * 0.1
                    score += (1 - s.features.get('entropy', 0) / 8) * 2  # Lower entropy = more meaningful
                meaningful_features.append((s, score))

            # Sort by meaningfulness features and take top candidates
            meaningful_features.sort(key=lambda x: x[1], reverse=True)
            sample_size = min(20, len(meaningful_features))
            sampled_low = [item[0] for item in meaningful_features[:sample_size]]
            training_strings.extend(sampled_low)
            print(f"[GUI] Training mode: Low confidence (≤0.2): {len(low_conf_strings)} available, sampled {sample_size}")

        # Category 3: High-confidence high scores (20 strings) - potential false positives
        # These might be meaningless strings the model thinks are meaningful
        high_conf_strings = [s for s in unlabeled_strings if s.ml_score >= 0.8]
        if high_conf_strings:
            # Prioritize strings with features that suggest randomness/meaninglessness
            random_features = []
            for s in high_conf_strings:
                score = 0
                if s.features:
                    # Look for features that suggest randomness
                    score += s.features.get('entropy', 0) / 8 * 3  # Higher entropy = more random
                    score += s.features.get('has_repeating_chars', 0) * 2
                    score += s.features.get('has_consonant_cluster', 0) * 2
                    score += s.features.get('special_ratio', 0) * 2
                    score += (1 - s.features.get('alpha_ratio', 0)) * 1  # Less alphabetic = more random
                    if s.features.get('word_count', 0) == 0:  # No recognizable words
                        score += 2
                random_features.append((s, score))

            # Sort by randomness features and take top candidates
            random_features.sort(key=lambda x: x[1], reverse=True)
            sample_size = min(20, len(random_features))
            sampled_high = [item[0] for item in random_features[:sample_size]]
            training_strings.extend(sampled_high)
            print(f"[GUI] Training mode: High confidence (≥0.8): {len(high_conf_strings)} available, sampled {sample_size}")

        # Category 4: Fill remaining slots with diverse samples (up to 20 strings)
        remaining_slots = 100 - len(training_strings)
        if remaining_slots > 0:
            # Get strings not already selected
            selected_offsets = {s.offset for s in training_strings}
            remaining_strings = [s for s in unlabeled_strings if s.offset not in selected_offsets]

            if remaining_strings:
                # Sample from different score ranges to ensure diversity
                ranges = [
                    (0.0, 0.1, "very low"),
                    (0.1, 0.3, "low"),
                    (0.7, 0.9, "high"),
                    (0.9, 1.0, "very high")
                ]

                per_range = remaining_slots // len(ranges)
                for min_s, max_s, label in ranges:
                    range_strings = [s for s in remaining_strings if min_s <= s.ml_score <= max_s]
                    if range_strings:
                        sample_size = min(per_range, len(range_strings))
                        sampled = random.sample(range_strings, sample_size)
                        training_strings.extend(sampled)
                        print(f"[GUI] Training mode: Diversity {label} ({min_s}-{max_s}): sampled {sample_size}")

        print(f"[GUI] Training mode: Selected {len(training_strings)} strings total")

        # Show final distribution
        if training_strings:
            selected_scores = [s.ml_score for s in training_strings]
            boundary_count = sum(1 for s in selected_scores if 0.3 <= s <= 0.7)
            low_count = sum(1 for s in selected_scores if s <= 0.2)
            high_count = sum(1 for s in selected_scores if s >= 0.8)

            print(f"[GUI] Training mode: Final distribution:")
            print(f"  Decision boundary (0.3-0.7): {boundary_count} strings")
            print(f"  Low confidence (≤0.2): {low_count} strings")
            print(f"  High confidence (≥0.8): {high_count} strings")
            print(f"  Other ranges: {len(training_strings) - boundary_count - low_count - high_count} strings")

        return training_strings

    def _on_string_select(self, event):
        """Handle string selection in treeview"""
        selection = self.tree.selection()
        if not selection:
            self.meaningful_btn.config(state='disabled')
            self.not_meaningful_btn.config(state='disabled')
            self.clear_label_btn.config(state='disabled')
            return

        # Enable labeling buttons for any selection
        self.meaningful_btn.config(state='normal')
        self.not_meaningful_btn.config(state='normal')
        self.clear_label_btn.config(state='normal')

        # Show details for first selected item
        index = self.tree.index(selection[0])
        if 0 <= index < len(self.filtered_strings):
            string_info = self.filtered_strings[index]

            # If multiple items selected, show count in details
            if len(selection) > 1:
                self._show_multi_selection_details(len(selection))
            else:
                self._show_string_details(string_info)

    def _show_string_details(self, string_info: StringInfo):
        """Display detailed information about selected string"""
        self.details_text.delete(1.0, tk.END)

        details = f"""String: {string_info.decoded_text}

Length: {len(string_info.decoded_text)}
Section: {string_info.section}
Offset: 0x{string_info.offset:08x}
Encoding: {string_info.encoding}

ML Score: {string_info.ml_score:.4f}
User Label: {string_info.user_label}
Feedback Weight: {string_info.feedback_weight:.2f}

Features:
"""

        # Add feature values
        if string_info.features:
            for fname, fvalue in sorted(string_info.features.items()):
                if isinstance(fvalue, float):
                    details += f"  {fname}: {fvalue:.4f}\n"
                else:
                    details += f"  {fname}: {fvalue}\n"

        self.details_text.insert(1.0, details)

    def _show_multi_selection_details(self, count: int):
        """Display information about multiple selected strings"""
        self.details_text.delete(1.0, tk.END)

        details = f"""Multiple Selection

Selected Items: {count}

Use the labeling buttons below to apply
the same label to all selected strings.

This is useful for batch labeling of
similar strings.
"""

        self.details_text.insert(1.0, details)

    def _label_string(self, label: Optional[bool]):
        """Label the selected string(s)"""
        selection = self.tree.selection()
        if not selection:
            return

        # Get all selected string indices
        selected_indices = [self.tree.index(item) for item in selection]
        selected_strings = [self.filtered_strings[i] for i in selected_indices
                           if 0 <= i < len(self.filtered_strings)]

        if not selected_strings:
            return

        label_text = "meaningful" if label is True else "not meaningful" if label is False else "cleared"
        print(f"[GUI] Labeling {len(selected_strings)} strings as {label_text}")

        # Label all selected strings
        corrections = 0
        for string_info in selected_strings:
            # Check if this is a correction
            was_correct = False
            if string_info.user_label is not None:
                # User is changing existing label
                if self.model_manager.is_trained:
                    # Check if model was correct
                    predicted_meaningful = string_info.ml_score >= 0.5
                    actual_meaningful = string_info.user_label
                    was_correct = (predicted_meaningful == actual_meaningful)
                    if not was_correct:
                        corrections += 1

            # Update label
            old_label = string_info.user_label
            string_info.user_label = label

            # Update feedback weight if this is a correction
            if old_label != label and self.model_manager.is_trained:
                self.model_manager.update_feedback_weights(string_info, was_correct)

        if corrections > 0:
            print(f"[GUI] {corrections} corrections made (model was wrong)")

        # Update display
        self._update_string_list()
        self._update_stats()

        # Show details for first selected item or multi-selection info
        if len(selected_strings) == 1:
            self._show_string_details(selected_strings[0])
            # Auto-advance to next unlabeled string for single selection
            if label is not None:
                self._select_next_unlabeled()
        else:
            self._show_multi_selection_details(len(selected_strings))

    def _sort_by_column(self, column):
        """Sort the filtered strings by the specified column"""
        if self.sort_column == column:
            # Toggle sort direction if same column
            self.sort_reverse = not self.sort_reverse
        else:
            # New column, start with ascending
            self.sort_column = column
            self.sort_reverse = False

        print(f"[GUI] Sorting by {column}, reverse={self.sort_reverse}")

        if column == 'Length':
            self.filtered_strings.sort(
                key=lambda s: len(s.decoded_text),
                reverse=self.sort_reverse
            )
        elif column == 'Entropy':
            self.filtered_strings.sort(
                key=lambda s: s.features.get('entropy', 0) if s.features else 0,
                reverse=self.sort_reverse
            )
        elif column == 'Score':
            self.filtered_strings.sort(
                key=lambda s: s.ml_score,
                reverse=self.sort_reverse
            )

        # Update the display
        self._update_string_list()

        # Update column heading to show sort direction
        direction = " ↓" if self.sort_reverse else " ↑"
        if column == 'Length':
            self.tree.heading('Length', text=f'Length{direction}')
            self.tree.heading('Entropy', text='Entropy')
            self.tree.heading('Score', text='ML Score')
        elif column == 'Entropy':
            self.tree.heading('Length', text='Length')
            self.tree.heading('Entropy', text=f'Entropy{direction}')
            self.tree.heading('Score', text='ML Score')
        elif column == 'Score':
            self.tree.heading('Length', text='Length')
            self.tree.heading('Entropy', text='Entropy')
            self.tree.heading('Score', text=f'ML Score{direction}')

    def _select_next_unlabeled(self):
        """Select the next unlabeled string in the list"""
        current_selection = self.tree.selection()
        if not current_selection:
            return

        current_index = self.tree.index(current_selection[0])

        # Look for next unlabeled starting from current position
        for i in range(current_index + 1, len(self.filtered_strings)):
            if self.filtered_strings[i].user_label is None:
                item_id = self.tree.get_children()[i]
                self.tree.selection_set(item_id)
                self.tree.see(item_id)
                self._on_string_select(None)
                break

    def _train_model(self):
        """Train or retrain the ML model"""
        self.status_var.set("Training model...")
        self.task_queue.put(('show_progress', True))

        # Run training in background thread
        threading.Thread(target=self._train_model_thread, daemon=True).start()

    def _train_model_thread(self):
        """Train model in background thread"""
        try:
            print(f"[GUI] Starting model training thread...")
            self.task_queue.put(('update_progress', 20))
            success, message = self.model_manager.train_model(self.strings)
            print(f"[GUI] Model training thread completed: success={success}")
            self.task_queue.put(('update_progress', 100))
            self.task_queue.put(('show_progress', False))
            self.task_queue.put(('model_trained', (success, message)))
        except Exception as e:
            print(f"[GUI] Error in model training thread: {str(e)}")
            self.task_queue.put(('show_progress', False))
            self.task_queue.put(('error', f"Error training model: {str(e)}"))

    def _apply_model_to_all(self):
        """Apply trained model to all strings"""
        if not self.model_manager.is_trained:
            messagebox.showwarning("No Model", "Please train a model first")
            return

        self.status_var.set("Applying model...")
        self.task_queue.put(('show_progress', True))

        # Run prediction in background thread
        threading.Thread(target=self._apply_model_thread, daemon=True).start()

    def _apply_model_thread(self):
        """Apply model in background thread"""
        try:
            print(f"[GUI] Starting model application thread for {len(self.strings)} strings...")
            self.task_queue.put(('update_progress', 10))

            # Apply model with progress updates
            total_strings = len(self.strings)
            batch_size = max(1, total_strings // 10)  # Update progress 10 times

            for i in range(0, total_strings, batch_size):
                batch = self.strings[i:i+batch_size]
                self.model_manager.predict_scores(batch)
                progress = 10 + (i / total_strings) * 80
                self.task_queue.put(('update_progress', progress))
                if i % (batch_size * 3) == 0:  # Log every 3 batches
                    print(f"[GUI] Model application progress: {i}/{total_strings}")

            print(f"[GUI] Model application thread completed")
            self.task_queue.put(('update_progress', 100))
            self.task_queue.put(('show_progress', False))
            self.task_queue.put(('model_applied', None))

        except Exception as e:
            print(f"[GUI] Error in model application thread: {str(e)}")
            self.task_queue.put(('show_progress', False))
            self.task_queue.put(('error', f"Error applying model: {str(e)}"))

    def _save_model(self):
        """Save the trained model"""
        if not self.model_manager.is_trained:
            messagebox.showwarning("No Model", "No trained model to save")
            return

        filename = filedialog.asksaveasfilename(
            title="Save Model",
            defaultextension=".pkl",
            filetypes=[("Pickle files", "*.pkl"), ("All files", "*.*")]
        )

        if filename:
            try:
                self.model_manager.save_model(filename)
                messagebox.showinfo("Success", "Model saved successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save model: {str(e)}")

    def _load_model(self):
        """Load a trained model"""
        filename = filedialog.askopenfilename(
            title="Load Model",
            filetypes=[("Pickle files", "*.pkl"), ("All files", "*.*")]
        )

        if filename:
            try:
                self.model_manager.load_model(filename)
                messagebox.showinfo("Success", "Model loaded successfully")

                # Apply to current strings if any
                if self.strings:
                    self._apply_model_to_all()

            except Exception as e:
                messagebox.showerror("Error", f"Failed to load model: {str(e)}")

    def _save_labels(self):
        """Save user labels to file"""
        if not self.strings:
            messagebox.showwarning("No Data", "No strings to save")
            return

        filename = filedialog.asksaveasfilename(
            title="Save Labels",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )

        if filename:
            try:
                labels_data = []
                for string_info in self.strings:
                    if string_info.user_label is not None:
                        labels_data.append({
                            'text': string_info.decoded_text,
                            'offset': int(string_info.offset),
                            'section': string_info.section,
                            'label': bool(string_info.user_label),
                            'feedback_weight': float(string_info.feedback_weight)
                        })

                with open(filename, 'w') as f:
                    json.dump(labels_data, f, indent=2)

                messagebox.showinfo("Success",
                                  f"Saved {len(labels_data)} labels")

            except Exception as e:
                messagebox.showerror("Error", f"Failed to save labels: {str(e)}")

    def _load_labels(self):
        """Load user labels from file"""
        filename = filedialog.askopenfilename(
            title="Load Labels",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )

        if filename:
            try:
                with open(filename, 'r') as f:
                    labels_data = json.load(f)

                # Apply labels to matching strings
                applied = 0
                for label_info in labels_data:
                    for string_info in self.strings:
                        if (string_info.decoded_text == label_info['text'] and
                            string_info.offset == label_info['offset']):
                            string_info.user_label = label_info['label']
                            string_info.feedback_weight = label_info.get('feedback_weight', 1.0)
                            applied += 1
                            break

                self._update_string_list()
                self._update_stats()
                messagebox.showinfo("Success", f"Applied {applied} labels")

            except Exception as e:
                messagebox.showerror("Error", f"Failed to load labels: {str(e)}")

    def _clear_labels(self):
        """Clear all user labels"""
        if messagebox.askyesno("Confirm", "Clear all user labels?"):
            for string_info in self.strings:
                string_info.user_label = None
                string_info.feedback_weight = 1.0

            self._update_string_list()
            self._update_stats()
            self.status_var.set("All labels cleared")

    def _load_initial_file(self, filepath):
        """Load initial file specified via command line"""
        if os.path.exists(filepath):
            print(f"[GUI] Auto-loading file: {filepath}")
            self.current_file = filepath
            self.file_label.config(text=f"File: {os.path.basename(filepath)}")
            self.status_var.set("Extracting strings...")

            # Extract strings in background
            threading.Thread(target=self._extract_strings_thread,
                           args=(filepath,), daemon=True).start()
        else:
            print(f"[GUI] Error: File not found: {filepath}")
            messagebox.showerror("File Not Found", f"Could not find file: {filepath}")

    def _load_initial_model(self, filepath):
        """Load initial model specified via command line"""
        if os.path.exists(filepath):
            print(f"[GUI] Auto-loading model: {filepath}")
            try:
                self.model_manager.load_model(filepath)
                self.status_var.set("Model loaded from command line")
                print(f"[GUI] Model loaded successfully from: {filepath}")

                # Apply to current strings if any
                if self.strings:
                    self._apply_model_to_all()

            except Exception as e:
                print(f"[GUI] Error loading model: {str(e)}")
                messagebox.showerror("Model Load Error", f"Failed to load model: {str(e)}")
        else:
            print(f"[GUI] Error: Model file not found: {filepath}")
            messagebox.showerror("Model Not Found", f"Could not find model file: {filepath}")

    def _load_initial_labels(self, filepath):
        """Load initial labels specified via command line"""
        if os.path.exists(filepath):
            print(f"[GUI] Auto-loading labels: {filepath}")
            try:
                with open(filepath, 'r') as f:
                    labels_data = json.load(f)

                # Apply labels to matching strings
                applied = 0
                for label_info in labels_data:
                    for string_info in self.strings:
                        if (string_info.decoded_text == label_info['text'] and
                            string_info.offset == label_info['offset']):
                            string_info.user_label = label_info['label']
                            string_info.feedback_weight = label_info.get('feedback_weight', 1.0)
                            applied += 1
                            break

                self._update_string_list()
                self._update_stats()
                self.status_var.set(f"Labels loaded from command line: {applied} applied")
                print(f"[GUI] Labels loaded successfully: {applied} applied from {filepath}")

            except Exception as e:
                print(f"[GUI] Error loading labels: {str(e)}")
                messagebox.showerror("Labels Load Error", f"Failed to load labels: {str(e)}")
        else:
            print(f"[GUI] Error: Labels file not found: {filepath}")
            messagebox.showerror("Labels Not Found", f"Could not find labels file: {filepath}")

    def _configure_gemini(self):
        """Configure Google Gemini API"""
        if not GEMINI_AVAILABLE:
            messagebox.showerror("Gemini Not Available",
                               "Google Gemini API is not available.\n"
                               "Install with: pip install google-generativeai")
            return

        # Create API key input dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Configure Gemini API")
        dialog.geometry("400x150")
        dialog.transient(self.root)
        dialog.grab_set()

        # Center the dialog
        dialog.geometry("+%d+%d" % (self.root.winfo_rootx() + 50, self.root.winfo_rooty() + 50))

        ttk.Label(dialog, text="Enter your Google Gemini API Key:").pack(pady=10)

        api_key_var = tk.StringVar()
        entry = ttk.Entry(dialog, textvariable=api_key_var, width=50, show="*")
        entry.pack(pady=5)
        entry.focus()

        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=10)

        def on_ok():
            api_key = api_key_var.get().strip()
            if api_key:
                if self.gemini_service.configure(api_key):
                    messagebox.showinfo("Success", "Gemini API configured successfully!")
                    dialog.destroy()
                else:
                    messagebox.showerror("Error", "Failed to configure Gemini API. Check your API key.")
            else:
                messagebox.showwarning("Warning", "Please enter an API key.")

        def on_cancel():
            dialog.destroy()

        ttk.Button(button_frame, text="OK", command=on_ok).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=on_cancel).pack(side=tk.LEFT, padx=5)

        # Bind Enter key
        entry.bind('<Return>', lambda e: on_ok())

    def _label_with_gemini(self):
        """Label selected strings using Google Gemini"""
        if not self.gemini_service.is_configured:
            messagebox.showwarning("Gemini Not Configured",
                                 "Please configure the Gemini API first.")
            return

        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select strings to label.")
            return

        # Get selected strings
        selected_indices = [self.tree.index(item) for item in selection]
        selected_strings = [self.filtered_strings[i] for i in selected_indices
                           if 0 <= i < len(self.filtered_strings)]

        if not selected_strings:
            return

        # Limit batch size to avoid API limits
        if len(selected_strings) > 20:
            if not messagebox.askyesno("Large Selection",
                                     f"You selected {len(selected_strings)} strings. "
                                     f"This may take a while and use API quota. Continue?"):
                return

        self.status_var.set(f"Labeling {len(selected_strings)} strings with Gemini...")
        self.task_queue.put(('show_progress', True))

        # Run labeling in background thread
        threading.Thread(target=self._gemini_labeling_thread,
                        args=(selected_strings,), daemon=True).start()

    def _gemini_labeling_thread(self, strings: List[StringInfo]):
        """Run Gemini labeling in background thread"""
        try:
            self.task_queue.put(('update_progress', 20))

            # Process in batches to avoid API limits
            batch_size = 100
            total_labeled = 0

            for i in range(0, len(strings), batch_size):
                batch = strings[i:i+batch_size]

                # Get labels from Gemini
                results = self.gemini_service.label_strings(batch)

                # Apply labels
                for string_info, is_meaningful, reasoning in results:
                    string_info.user_label = is_meaningful
                    # Store reasoning in a comment-like way (could extend StringInfo for this)
                    total_labeled += 1

                progress = 20 + ((i + len(batch)) / len(strings)) * 70
                self.task_queue.put(('update_progress', progress))

                # Small delay to be respectful to API
                time.sleep(0.5)

            self.task_queue.put(('update_progress', 100))
            self.task_queue.put(('show_progress', False))
            self.task_queue.put(('gemini_labeling_complete', total_labeled))

        except Exception as e:
            self.task_queue.put(('show_progress', False))
            self.task_queue.put(('error', f"Error in Gemini labeling: {str(e)}"))


def main():
    """Main entry point"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="String Meaningfulness Analyzer")
    parser.add_argument("binary", nargs="?", help="Binary file to analyze (optional)")
    parser.add_argument("--gpu", action="store_true", help="Enable GPU acceleration")
    parser.add_argument("--no-gpu", action="store_true", help="Disable GPU acceleration")
    parser.add_argument("--model", help="Model file to load (.pkl)")
    parser.add_argument("--labels", help="Labels file to load (.json)")

    args = parser.parse_args()

    print("=" * 60)
    print("String Meaningfulness Analyzer - Starting")
    print("=" * 60)

    if args.binary:
        print(f"[Main] Binary file specified: {args.binary}")

    if args.gpu and args.no_gpu:
        print("[Main] Warning: Both --gpu and --no-gpu specified, using default")
    elif args.gpu:
        print("[Main] GPU acceleration explicitly enabled")
    elif args.no_gpu:
        print("[Main] GPU acceleration explicitly disabled")

    print("[Main] Initializing GUI...")

    root = tk.Tk()
    app = StringAnalyzerGUI(root, initial_file=args.binary)

    # Auto-load model and labels if provided
    if args.model:
        app.root.after(1000, lambda: app._load_initial_model(args.model))
    if args.labels:
        app.root.after(1500, lambda: app._load_initial_labels(args.labels))

    print("[Main] GUI initialized, starting main loop...")
    root.mainloop()
    print("[Main] Application closed")


if __name__ == "__main__":
    main()
