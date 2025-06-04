#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import struct
import re
import math
import string
import zlib
from collections import Counter, defaultdict
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError
import unicodedata
from typing import List, Dict, Tuple, Optional, Set
import threading
import time
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, as_completed

class ProgressDialog:
    """Progress dialog for long-running operations"""

    def __init__(self, parent, title="Processing..."):
        self.parent = parent
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.geometry("400x120")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()

        # Center the dialog
        self.dialog.geometry("+%d+%d" % (parent.winfo_rootx() + 50, parent.winfo_rooty() + 50))

        # Progress frame
        frame = ttk.Frame(self.dialog)
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        self.status_label = ttk.Label(frame, text="Initializing...")
        self.status_label.pack(pady=(0, 10))

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=(0, 10))

        self.cancel_var = tk.BooleanVar()
        ttk.Button(frame, text="Cancel", command=self.cancel).pack()

    def update_progress(self, value, status="Processing..."):
        """Update progress bar and status"""
        self.progress_var.set(value)
        self.status_label.config(text=status)
        self.dialog.update()

    def cancel(self):
        """Cancel the operation"""
        self.cancel_var.set(True)

    def is_cancelled(self):
        """Check if operation was cancelled"""
        return self.cancel_var.get()

    def close(self):
        """Close the dialog"""
        self.dialog.destroy()


class StringGroup:
    """Container for a group of related strings"""
    def __init__(self, group_id: int, section: str):
        self.group_id = group_id
        self.section = section
        self.strings = []
        self.start_offset = None
        self.end_offset = None
        self.size = 0
        self.avg_meaningfulness = 0.0
        self.avg_shannon_entropy = 0.0
        self.avg_compression_entropy = 0.0
        self.avg_ngram_entropy = 0.0
        self.dominant_category = None

    def add_string(self, string_info):
        """Add a string to this group"""
        self.strings.append(string_info)

        if self.start_offset is None or string_info.offset < self.start_offset:
            self.start_offset = string_info.offset

        string_end = string_info.offset + len(string_info.raw_data)
        if self.end_offset is None or string_end > self.end_offset:
            self.end_offset = string_end

        self.size = self.end_offset - self.start_offset if self.start_offset and self.end_offset else 0

        # Update statistics
        self._update_statistics()

    def _update_statistics(self):
        """Update group statistics"""
        if not self.strings:
            return

        # Average meaningfulness
        self.avg_meaningfulness = sum(s.meaningfulness_score for s in self.strings) / len(self.strings)

        # Average entropies
        self.avg_shannon_entropy = sum(s.entropy_shannon for s in self.strings) / len(self.strings)
        self.avg_compression_entropy = sum(s.entropy_compression for s in self.strings) / len(self.strings)
        self.avg_ngram_entropy = sum(s.entropy_ngram for s in self.strings) / len(self.strings)

        # Dominant category
        categories = [s.category for s in self.strings]
        category_counts = Counter(categories)
        self.dominant_category = category_counts.most_common(1)[0][0] if category_counts else "Mixed"

    def get_summary(self) -> str:
        """Get a summary description of this group"""
        return f"Group {self.group_id}: {len(self.strings)} strings, {self.dominant_category}, avg score: {self.avg_meaningfulness:.1f}"

class StringInfo:
    """Container for string information"""
    def __init__(self, data: bytes, offset: int, section: str, encoding: str):
        self.raw_data = data
        self.offset = offset
        self.section = section
        self.encoding = encoding
        self.decoded_string = self._decode_string()
        self.length = len(self.decoded_string)
        self.category = None
        self.entropy_shannon = 0.0
        self.entropy_compression = 0.0
        self.entropy_ngram = 0.0
        self.meaningfulness_score = 0.0
        self.group_id = None  # Will be assigned during grouping

    def _decode_string(self) -> str:
        """Safely decode the string"""
        try:
            if self.encoding == 'utf-8':
                return self.raw_data.decode('utf-8', errors='replace')
            elif self.encoding == 'utf-16le':
                return self.raw_data.decode('utf-16le', errors='replace')
            elif self.encoding == 'utf-16be':
                return self.raw_data.decode('utf-16be', errors='replace')
            else:  # ascii
                return self.raw_data.decode('ascii', errors='replace')
        except:
            return repr(self.raw_data)[2:-1]  # fallback to repr

class StringGrouper:
    """Handles grouping of strings by proximity and other criteria"""

    def __init__(self):
        self.groups = []

    def group_strings(self, strings: List[StringInfo],
                     proximity_threshold: int = 512,
                     group_by_section: bool = True,
                     semantic_grouping: bool = True,
                     progress_callback=None) -> List[StringGroup]:
        """Group strings based on various criteria"""
        self.groups = []

        if not strings:
            return self.groups

        if progress_callback:
            progress_callback(0, "Sorting strings...")

        # Sort strings by section and offset
        sorted_strings = sorted(strings, key=lambda x: (x.section, x.offset))

        if progress_callback:
            progress_callback(20, "Creating proximity groups...")

        if group_by_section:
            # Group by section first, then by proximity within sections
            sections = {}
            for string_info in sorted_strings:
                if string_info.section not in sections:
                    sections[string_info.section] = []
                sections[string_info.section].append(string_info)

            group_id = 0
            total_sections = len(sections)
            for i, (section_name, section_strings) in enumerate(sections.items()):
                if progress_callback:
                    progress = 20 + (i / total_sections) * 40  # 20-60%
                    progress_callback(progress, f"Grouping section: {section_name}")

                section_groups = self._group_by_proximity(
                    section_strings, proximity_threshold, group_id, section_name
                )
                self.groups.extend(section_groups)
                group_id += len(section_groups)
        else:
            # Group all strings together by proximity
            self.groups = self._group_by_proximity(
                sorted_strings, proximity_threshold, 0, "mixed"
            )

        if progress_callback:
            progress_callback(70, "Applying semantic grouping...")

        # Apply semantic grouping if enabled
        if semantic_grouping:
            self._apply_semantic_grouping()

        if progress_callback:
            progress_callback(90, "Assigning group IDs...")

        # Assign group IDs to strings
        for group in self.groups:
            for string_info in group.strings:
                string_info.group_id = group.group_id

        if progress_callback:
            progress_callback(100, "Grouping complete!")

        return self.groups

    def _group_by_proximity(self, strings: List[StringInfo],
                           threshold: int, start_group_id: int,
                           section: str) -> List[StringGroup]:
        """Group strings by proximity in offsets"""
        if not strings:
            return []

        groups = []
        current_group = StringGroup(start_group_id, section)

        for i, string_info in enumerate(strings):
            if i == 0:
                current_group.add_string(string_info)
            else:
                # Calculate distance from last string in current group
                last_string = current_group.strings[-1]
                last_end = last_string.offset + len(last_string.raw_data)
                distance = string_info.offset - last_end

                if distance <= threshold:
                    # Add to current group
                    current_group.add_string(string_info)
                else:
                    # Start new group
                    groups.append(current_group)
                    current_group = StringGroup(start_group_id + len(groups), section)
                    current_group.add_string(string_info)

        # Add the last group
        if current_group.strings:
            groups.append(current_group)

        return groups

    def _apply_semantic_grouping(self):
        """Apply semantic grouping to merge groups with similar content"""
        # This could merge groups that have similar categories, similar meaningfulness scores, etc.
        # For now, we'll implement a simple category-based merging

        category_groups = defaultdict(list)

        # Group by dominant category
        for group in self.groups:
            if len(group.strings) < 3:  # Only merge small groups
                category_groups[group.dominant_category].append(group)

        # Merge groups with same category if they're close enough
        for category, cat_groups in category_groups.items():
            if len(cat_groups) > 1:
                # Sort by start offset
                cat_groups.sort(key=lambda g: g.start_offset)

                merged_groups = []
                i = 0
                while i < len(cat_groups):
                    current_group = cat_groups[i]

                    # Try to merge with next groups
                    j = i + 1
                    while j < len(cat_groups):
                        next_group = cat_groups[j]

                        # Check if groups are close enough to merge (within 2KB)
                        if next_group.start_offset - current_group.end_offset <= 2048:
                            # Merge groups
                            for string_info in next_group.strings:
                                current_group.add_string(string_info)
                            j += 1
                        else:
                            break

                    merged_groups.append(current_group)
                    i = j

                # Replace original groups with merged ones
                for old_group in cat_groups:
                    if old_group in self.groups:
                        self.groups.remove(old_group)

                self.groups.extend(merged_groups)

        # Re-assign group IDs
        for i, group in enumerate(self.groups):
            group.group_id = i

class StringExtractor:
    """Main string extraction and analysis engine"""

    def __init__(self, min_length: int = 4):
        self.min_length = min_length
        self.sections_data = {}
        self.strings = []
        self.grouper = StringGrouper()

        # Encoding settings (ASCII enabled by default, UTF disabled)
        self.extract_ascii = True
        self.extract_utf8 = False
        self.extract_utf16le = False
        self.extract_utf16be = False

    def set_encoding_options(self, ascii=True, utf8=False, utf16le=False, utf16be=False):
        """Set which encodings to extract"""
        self.extract_ascii = ascii
        self.extract_utf8 = utf8
        self.extract_utf16le = utf16le
        self.extract_utf16be = utf16be

    def extract_from_elf(self, filepath: str, progress_callback=None) -> List[StringInfo]:
        """Extract strings from ELF file with progress reporting"""
        self.strings = []

        try:
            with open(filepath, 'rb') as f:
                elf = ELFFile(f)

                # Get all sections first for progress calculation
                sections = list(elf.iter_sections())
                total_sections = len([s for s in sections if s.data_size > 0])
                processed_sections = 0

                if progress_callback:
                    progress_callback(0, "Reading ELF sections...")

                # Extract section data
                for section in sections:
                    if section.data_size > 0:
                        section_data = section.data()
                        section_name = section.name
                        base_offset = section['sh_offset']

                        if progress_callback:
                            status = f"Processing section: {section_name}"
                            progress = (processed_sections / total_sections) * 80  # 80% for extraction
                            progress_callback(progress, status)

                            # Check for cancellation
                            if hasattr(progress_callback, '__self__') and hasattr(progress_callback.__self__, 'is_cancelled'):
                                if progress_callback.__self__.is_cancelled():
                                    return []

                        # Extract strings from this section
                        section_strings = self._extract_strings_from_data(
                            section_data, base_offset, section_name
                        )
                        self.strings.extend(section_strings)

                        processed_sections += 1

                if progress_callback:
                    progress_callback(80, "Removing duplicates...")

                # Remove duplicates
                self._remove_duplicates()


                if progress_callback:
                    progress_callback(90, "Analyzing strings...")

                # Analyze all extracted strings
                self._analyze_strings(progress_callback)

        except (ELFError, Exception) as e:
            raise Exception(f"Error parsing ELF file: {e}")

        if progress_callback:
            progress_callback(100, "Complete!")

        return self.strings

    def _remove_duplicates(self):
        """Remove duplicate strings based on decoded content"""
        seen = set()
        unique_strings = []

        for string_info in self.strings:
            # Use decoded string + section as key to avoid false positives
            key = (string_info.decoded_string, string_info.section)
            if key not in seen:
                seen.add(key)
                unique_strings.append(string_info)

        self.strings = unique_strings


    def group_strings(self, proximity_threshold: int = 512,
                     group_by_section: bool = True,
                     semantic_grouping: bool = True,
                     progress_callback=None) -> List[StringGroup]:
        """Group the extracted strings"""
        return self.grouper.group_strings(
            self.strings, proximity_threshold, group_by_section, semantic_grouping, progress_callback
        )

    def _extract_strings_from_data(self, data: bytes, base_offset: int, section: str) -> List[StringInfo]:
        """Extract strings from binary data using selected encoding strategies"""
        strings = []

        # ASCII strings
        if self.extract_ascii:
            strings.extend(self._find_ascii_strings(data, base_offset, section))

        # UTF-8 strings
        if self.extract_utf8:
            strings.extend(self._find_utf8_strings(data, base_offset, section))

        # UTF-16 strings
        if self.extract_utf16le:
            strings.extend(self._find_utf16_encoding(data, base_offset, section, 'utf-16le'))

        if self.extract_utf16be:
            strings.extend(self._find_utf16_encoding(data, base_offset, section, 'utf-16be'))

        return strings

    def _find_ascii_strings(self, data: bytes, base_offset: int, section: str) -> List[StringInfo]:
        """Find ASCII strings"""
        strings = []
        pattern = rb'[\x20-\x7e]{' + str(self.min_length).encode() + rb',}'

        for match in re.finditer(pattern, data):
            offset = base_offset + match.start()
            string_data = match.group()
            strings.append(StringInfo(string_data, offset, section, 'ascii'))

        return strings

    def _find_utf8_strings(self, data: bytes, base_offset: int, section: str) -> List[StringInfo]:
        """Find UTF-8 strings"""
        strings = []
        i = 0
        current_string = bytearray()
        start_pos = 0

        while i < len(data):
            byte = data[i]

            if byte < 0x80:  # ASCII
                if 0x20 <= byte <= 0x7e or byte in [0x09, 0x0a, 0x0d]:  # printable or whitespace
                    if not current_string:
                        start_pos = i
                    current_string.append(byte)
                else:
                    if len(current_string) >= self.min_length:
                        try:
                            decoded = current_string.decode('utf-8')
                            if self._is_meaningful_string(decoded):
                                offset = base_offset + start_pos
                                strings.append(StringInfo(bytes(current_string), offset, section, 'utf-8'))
                        except:
                            pass
                    current_string = bytearray()
                i += 1
            elif byte < 0xc0:  # Invalid start byte
                if len(current_string) >= self.min_length:
                    try:
                        decoded = current_string.decode('utf-8')
                        if self._is_meaningful_string(decoded):
                            offset = base_offset + start_pos
                            strings.append(StringInfo(bytes(current_string), offset, section, 'utf-8'))
                    except:
                        pass
                current_string = bytearray()
                i += 1
            else:  # Multi-byte UTF-8
                if not current_string:
                    start_pos = i

                # Determine sequence length
                if byte < 0xe0:
                    seq_len = 2
                elif byte < 0xf0:
                    seq_len = 3
                elif byte < 0xf8:
                    seq_len = 4
                else:
                    seq_len = 1  # Invalid

                if i + seq_len <= len(data):
                    sequence = data[i:i+seq_len]
                    try:
                        sequence.decode('utf-8')
                        current_string.extend(sequence)
                        i += seq_len
                    except:
                        if len(current_string) >= self.min_length:
                            try:
                                decoded = current_string.decode('utf-8')
                                if self._is_meaningful_string(decoded):
                                    offset = base_offset + start_pos
                                    strings.append(StringInfo(bytes(current_string), offset, section, 'utf-8'))
                            except:
                                pass
                        current_string = bytearray()
                        i += 1
                else:
                    if len(current_string) >= self.min_length:
                        try:
                            decoded = current_string.decode('utf-8')
                            if self._is_meaningful_string(decoded):
                                offset = base_offset + start_pos
                                strings.append(StringInfo(bytes(current_string), offset, section, 'utf-8'))
                        except:
                            pass
                    current_string = bytearray()
                    i += 1

        # Handle final string
        if len(current_string) >= self.min_length:
            try:
                decoded = current_string.decode('utf-8')
                if self._is_meaningful_string(decoded):
                    offset = base_offset + start_pos
                    strings.append(StringInfo(bytes(current_string), offset, section, 'utf-8'))
            except:
                pass

        return strings

    def _find_utf16_encoding(self, data: bytes, base_offset: int, section: str, encoding: str) -> List[StringInfo]:
        """Find UTF-16 strings for specific endianness"""
        strings = []
        i = 0

        while i < len(data) - 1:
            current_string = bytearray()
            start_pos = i
            char_count = 0

            while i < len(data) - 1:
                if encoding == 'utf-16le':
                    char_bytes = data[i:i+2]
                    char_code = struct.unpack('<H', char_bytes)[0]
                else:
                    char_bytes = data[i:i+2]
                    char_code = struct.unpack('>H', char_bytes)[0]

                # Check if it's a printable character or common control character
                if (0x20 <= char_code <= 0x7e or
                    char_code in [0x09, 0x0a, 0x0d] or
                    (0x80 <= char_code <= 0xffff and char_code != 0xfffe and char_code != 0xffff)):
                    current_string.extend(char_bytes)
                    char_count += 1
                    i += 2
                else:
                    break

            if char_count >= self.min_length:
                try:
                    decoded = current_string.decode(encoding, errors='strict')
                    if self._is_meaningful_string(decoded):
                        offset = base_offset + start_pos
                        strings.append(StringInfo(bytes(current_string), offset, section, encoding))
                except:
                    pass

            if i == start_pos:  # No progress made
                i += 2

        return strings

    def _is_meaningful_string(self, s: str) -> bool:
        """Determine if a string appears meaningful"""
        if len(s) < self.min_length:
            return False

        # Remove common escape sequences for analysis
        clean_s = s.replace('\\n', '\n').replace('\\t', '\t').replace('\\r', '\r')

        # Count printable characters
        printable_count = sum(1 for c in clean_s if c.isprintable() or c in '\t\n\r')
        printable_ratio = printable_count / len(clean_s) if clean_s else 0

        # Must be mostly printable
        if printable_ratio < 0.7:
            return False

        # Check for some structure (not just repeated characters)
        unique_chars = len(set(clean_s.lower()))
        if unique_chars < 2:
            return False

        return True

    def _analyze_strings(self, progress_callback=None):
        """Analyze all extracted strings with progress reporting"""
        total_strings = len(self.strings)

        for i, string_info in enumerate(self.strings):
            if progress_callback and i % 100 == 0:  # Update every 100 strings
                progress = 90 + (i / total_strings) * 10  # 90-100% range
                progress_callback(progress, f"Analyzing strings... ({i}/{total_strings})")

                # Check for cancellation
                if hasattr(progress_callback, '__self__') and hasattr(progress_callback.__self__, 'is_cancelled'):
                    if progress_callback.__self__.is_cancelled():
                        return

            string_info.entropy_shannon = self._calculate_shannon_entropy(string_info.decoded_string)
            string_info.entropy_compression = self._calculate_compression_entropy(string_info.raw_data)
            string_info.entropy_ngram = self._calculate_ngram_entropy(string_info.decoded_string)

            # Calculate base meaningfulness score
            base_score = self._calculate_meaningfulness_score(string_info.decoded_string)

            # Incorporate entropy into meaningfulness score
            # Higher entropy generally indicates more meaningful/structured content
            # Shannon entropy: weight it positively but cap it
            entropy_bonus = min(string_info.entropy_shannon * 2, 10)

            # Compression entropy: higher values suggest less redundancy
            compression_bonus = min(string_info.entropy_compression * 1.5, 8)

            # N-gram entropy: higher values suggest more varied character patterns
            ngram_bonus = min(string_info.entropy_ngram * 1.5, 8)

            # Combine base score with entropy bonuses
            string_info.meaningfulness_score = base_score + entropy_bonus + compression_bonus + ngram_bonus

            string_info.category = self._categorize_string(string_info.decoded_string)

    def _calculate_shannon_entropy(self, s: str) -> float:
        """Calculate Shannon entropy"""
        if not s:
            return 0.0

        counts = Counter(s)
        length = len(s)
        entropy = 0.0

        for count in counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def _calculate_compression_entropy(self, data: bytes) -> float:
        """Calculate entropy based on compression ratio"""
        if not data:
            return 0.0

        compressed = zlib.compress(data)
        ratio = len(compressed) / len(data)

        # Convert compression ratio to entropy-like measure
        return -math.log2(ratio) if ratio > 0 else 0.0

    def _calculate_ngram_entropy(self, s: str, n: int = 2) -> float:
        """Calculate n-gram entropy"""
        if len(s) < n:
            return 0.0

        ngrams = [s[i:i+n] for i in range(len(s) - n + 1)]
        counts = Counter(ngrams)
        length = len(ngrams)
        entropy = 0.0

        for count in counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def _calculate_meaningfulness_score(self, s: str) -> float:
        """Calculate a meaningfulness score for the string"""
        score = 0.0

        # Length bonus (longer strings are often more meaningful)
        score += min(len(s) / 50.0, 1.0) * 10

        # Dictionary word bonus
        words = re.findall(r'[a-zA-Z]+', s.lower())
        common_words = {'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'had', 'her', 'was', 'one', 'our', 'out', 'day', 'get', 'has', 'him', 'his', 'how', 'man', 'new', 'now', 'old', 'see', 'two', 'who', 'boy', 'did', 'its', 'let', 'put', 'say', 'she', 'too', 'use'}
        word_score = sum(5 if word in common_words else 1 for word in words if len(word) > 2)
        score += min(word_score, 20)

        # Path-like structure bonus
        if re.search(r'[/\\][a-zA-Z0-9_.-]+', s):
            score += 5

        # Error message patterns
        error_patterns = ['error', 'warning', 'exception', 'failed', 'cannot', 'invalid', 'missing']
        if any(pattern in s.lower() for pattern in error_patterns):
            score += 10

        # URL-like patterns
        if re.search(r'https?://', s) or re.search(r'www\.', s):
            score += 15

        # Version patterns
        if re.search(r'\d+\.\d+', s):
            score += 5

        # Repetition penalty
        unique_chars = len(set(s.lower()))
        repetition_ratio = unique_chars / len(s) if s else 0
        score *= (0.5 + repetition_ratio * 0.5)

        return score

    def _categorize_string(self, s: str) -> str:
        """Categorize the string by content type"""
        s_lower = s.lower()

        # Error messages
        error_keywords = ['error', 'warning', 'exception', 'failed', 'cannot', 'invalid', 'missing', 'denied']
        if any(keyword in s_lower for keyword in error_keywords):
            return 'Error Message'

        # File paths
        if re.search(r'[/\\][a-zA-Z0-9_.-]+', s) or s.startswith('/') or re.search(r'^[A-Z]:\\', s):
            return 'File Path'

        # URLs
        if re.search(r'https?://', s) or re.search(r'www\.', s):
            return 'URL'

        # Version strings
        if re.search(r'\d+\.\d+\.\d+', s):
            return 'Version'

        # Format strings
        if '%' in s and any(c in s for c in 'sdifoxX'):
            return 'Format String'

        # Debug/Log messages
        debug_keywords = ['debug', 'trace', 'log', 'info', 'verbose']
        if any(keyword in s_lower for keyword in debug_keywords):
            return 'Debug/Log'

        # Control characters / escape sequences
        if any(ord(c) < 32 for c in s) or '\\' in s:
            return 'Control/Escape'

        # Alphanumeric sequences (possible keys, hashes, etc.)
        if re.match(r'^[a-fA-F0-9]{8,}$', s):
            return 'Hex Sequence'

        # Mixed case with numbers (possible identifiers)
        if re.search(r'[A-Z]', s) and re.search(r'[a-z]', s) and re.search(r'\d', s):
            return 'Identifier'

        # Mostly alphabetic
        alpha_ratio = sum(1 for c in s if c.isalpha()) / len(s) if s else 0
        if alpha_ratio > 0.7:
            return 'Text'

        return 'Other'


class StringExtractorGUI:
    """GUI for the string extractor tool"""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Advanced ELF String Extractor with Grouping")

        # Set a large default size but keep it resizable
        self.root.geometry("1400x900")
        self.root.minsize(800, 600)  # Set minimum size

        self.extractor = StringExtractor()
        self.current_strings = []
        self.current_groups = []
        self.show_grouped = tk.BooleanVar(value=True)
        self.is_processing = False
        self.current_sort_column = "meaning"
        self.sort_reverse = True

        self.setup_ui()

    def setup_ui(self):
        """Set up the user interface"""
        # Main menu
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open ELF File", command=self.open_file)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)


        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Left panel - filters and options
        left_frame = ttk.LabelFrame(main_frame, text="Filters & Options", width=350)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 5))
        left_frame.pack_propagate(False)

        # Minimum length setting
        ttk.Label(left_frame, text="Minimum Length:").pack(anchor=tk.W, padx=5, pady=2)
        self.min_length_var = tk.IntVar(value=4)
        min_length_spin = ttk.Spinbox(left_frame, from_=1, to=50, textvariable=self.min_length_var, width=10)
        min_length_spin.pack(anchor=tk.W, padx=5, pady=2)
        self._create_tooltip(min_length_spin, "Minimum number of characters required for a string to be extracted")

        # Encoding options
        encoding_frame = ttk.LabelFrame(left_frame, text="Encoding Options")
        encoding_frame.pack(fill=tk.X, padx=5, pady=10)

        self.extract_ascii_var = tk.BooleanVar(value=True)
        self.extract_utf8_var = tk.BooleanVar(value=False)
        self.extract_utf16le_var = tk.BooleanVar(value=False)
        self.extract_utf16be_var = tk.BooleanVar(value=False)

        ascii_cb = ttk.Checkbutton(encoding_frame, text="ASCII", variable=self.extract_ascii_var, command=self.apply_filters)
        ascii_cb.pack(anchor=tk.W, padx=5, pady=2)
        self._create_tooltip(ascii_cb, "Extract ASCII strings (7-bit characters)")

        utf8_cb = ttk.Checkbutton(encoding_frame, text="UTF-8", variable=self.extract_utf8_var, command=self.apply_filters)
        utf8_cb.pack(anchor=tk.W, padx=5, pady=2)
        self._create_tooltip(utf8_cb, "Extract UTF-8 encoded strings (Unicode)")

        utf16le_cb = ttk.Checkbutton(encoding_frame, text="UTF-16 LE", variable=self.extract_utf16le_var, command=self.apply_filters)
        utf16le_cb.pack(anchor=tk.W, padx=5, pady=2)
        self._create_tooltip(utf16le_cb, "Extract UTF-16 Little Endian strings")

        utf16be_cb = ttk.Checkbutton(encoding_frame, text="UTF-16 BE", variable=self.extract_utf16be_var, command=self.apply_filters)
        utf16be_cb.pack(anchor=tk.W, padx=5, pady=2)
        self._create_tooltip(utf16be_cb, "Extract UTF-16 Big Endian strings")

        # Grouping options
        grouping_frame = ttk.LabelFrame(left_frame, text="Grouping Options")
        grouping_frame.pack(fill=tk.X, padx=5, pady=10)

        # Enable grouping checkbox
        grouping_cb = ttk.Checkbutton(grouping_frame, text="Enable Grouping",
                       variable=self.show_grouped, command=self._on_grouping_changed)
        grouping_cb.pack(anchor=tk.W, padx=5, pady=2)
        self._create_tooltip(grouping_cb, "Group nearby strings together for better organization")

        # Proximity threshold
        ttk.Label(grouping_frame, text="Proximity Threshold (bytes):").pack(anchor=tk.W, padx=5, pady=2)
        self.proximity_threshold_var = tk.IntVar(value=1024)
        proximity_spin = ttk.Spinbox(grouping_frame, from_=64, to=4096, textvariable=self.proximity_threshold_var, width=10)
        proximity_spin.pack(anchor=tk.W, padx=5, pady=2)
        proximity_spin.bind('<Return>', lambda e: self.apply_filters())
        self._create_tooltip(proximity_spin, "Maximum distance in bytes between strings to group them together")

        # Group by section
        self.group_by_section_var = tk.BooleanVar(value=True)
        section_cb = ttk.Checkbutton(grouping_frame, text="Group by Section",
                       variable=self.group_by_section_var, command=self.apply_filters)
        section_cb.pack(anchor=tk.W, padx=5, pady=2)
        self._create_tooltip(section_cb, "Keep strings from different ELF sections in separate groups")

        # Semantic grouping
        self.semantic_grouping_var = tk.BooleanVar(value=True)
        semantic_cb = ttk.Checkbutton(grouping_frame, text="Semantic Grouping",
                       variable=self.semantic_grouping_var, command=self.apply_filters)
        semantic_cb.pack(anchor=tk.W, padx=5, pady=2)
        self._create_tooltip(semantic_cb, "Merge groups with similar content types and categories")

        # Group sort options
        ttk.Label(grouping_frame, text="Sort Groups by:").pack(anchor=tk.W, padx=5, pady=(10, 2))
        self.group_sort_var = tk.StringVar(value="meaningfulness")
        group_sort_options = ["Offset", "Length", "String Count", "Shannon Entropy", "Compression Entropy", "N-gram Entropy", "Meaningfulness", "Group ID"]
        group_sort_combo = ttk.Combobox(grouping_frame, textvariable=self.group_sort_var, values=group_sort_options, state="readonly")
        group_sort_combo.pack(fill=tk.X, padx=5, pady=2)
        group_sort_combo.bind('<<ComboboxSelected>>', self.apply_filters)
        self._create_tooltip(group_sort_combo, "Choose how to sort groups when grouping is enabled")

        # Section filter
        ttk.Label(left_frame, text="Sections:").pack(anchor=tk.W, padx=5, pady=(10, 2))
        self.section_frame = ttk.Frame(left_frame)
        self.section_frame.pack(fill=tk.X, padx=5, pady=2)
        self.section_vars = {}

        # Category filter
        ttk.Label(left_frame, text="Categories:").pack(anchor=tk.W, padx=5, pady=(10, 2))
        self.category_frame = ttk.Frame(left_frame)
        self.category_frame.pack(fill=tk.X, padx=5, pady=2)
        self.category_vars = {}


        # Right panel - results
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Results tree
        tree_frame = ttk.LabelFrame(right_frame, text="Extracted Strings")
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))

        # Treeview with scrollbars
        tree_container = ttk.Frame(tree_frame)
        tree_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.tree = ttk.Treeview(tree_container, columns=("group", "offset", "section", "encoding", "category", "length", "shannon", "compression", "ngram", "meaning"), show="tree headings")

        # Configure columns
        self.tree.heading("#0", text="String")
        self.tree.heading("group", text="Group")
        self.tree.heading("offset", text="Offset")
        self.tree.heading("section", text="Section")
        self.tree.heading("encoding", text="Encoding")
        self.tree.heading("category", text="Category")
        self.tree.heading("length", text="Length")
        self.tree.heading("shannon", text="Shannon")
        self.tree.heading("compression", text="Compression")
        self.tree.heading("ngram", text="N-gram")
        self.tree.heading("meaning", text="Meaning ▼")

        self.tree.column("#0", width=300)
        self.tree.column("group", width=60)
        self.tree.column("offset", width=100)
        self.tree.column("section", width=80)
        self.tree.column("encoding", width=80)
        self.tree.column("category", width=100)
        self.tree.column("length", width=60)
        self.tree.column("shannon", width=70)
        self.tree.column("compression", width=90)
        self.tree.column("ngram", width=70)
        self.tree.column("meaning", width=70)

        # Scrollbars
        v_scroll = ttk.Scrollbar(tree_container, orient=tk.VERTICAL, command=self.tree.yview)
        h_scroll = ttk.Scrollbar(tree_container, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        h_scroll.pack(side=tk.BOTTOM, fill=tk.X)

        # Bind events
        self.tree.bind("<Double-1>", self.show_string_details)
        self.tree.bind("<Button-3>", self.show_context_menu)  # Right-click

        # Bind column header clicks for sorting
        for col in ("group", "offset", "section", "encoding", "category", "length", "shannon", "compression", "ngram", "meaning"):
            self.tree.heading(col, command=lambda c=col: self.sort_by_column(c))

        # Create context menu
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Copy String", command=self.copy_string)

        # Status bar with integrated progress bar
        status_frame = ttk.Frame(right_frame)
        status_frame.pack(fill=tk.X, pady=(5, 0))

        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(status_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Progress bar (initially hidden)
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(status_frame, variable=self.progress_var, maximum=100, length=200)
        # Don't pack initially - will be shown when needed

    def show_context_menu(self, event):
        """Show context menu on right-click"""
        # Select the item under cursor
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)


    def copy_string(self):
        """Copy selected string to clipboard"""
        selection = self.tree.selection()
        if not selection:
            return

        item = selection[0]
        tags = self.tree.item(item, "tags")
        if not tags or tags[0] == "group_header":
            return

        string_info = tags[0]
        if isinstance(string_info, str):
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(string_info.decoded_string)
        self.root.update()  # Ensure clipboard is updated

    def sort_by_column(self, column):
        """Sort tree by column header click"""
        if self.current_sort_column == column:
            self.sort_reverse = not self.sort_reverse
        else:
            self.current_sort_column = column
            self.sort_reverse = False

        self._update_column_headers()
        self.apply_filters()

    def _on_grouping_changed(self):
        """Handle grouping mode change"""
        self._update_group_column_visibility()
        self.apply_filters()

    def _update_column_headers(self):
        """Update column headers to show sort indicators"""
        # Clear all headers first
        self.tree.heading("#0", text="String")
        self.tree.heading("group", text="Group")
        self.tree.heading("offset", text="Offset")
        self.tree.heading("section", text="Section")
        self.tree.heading("encoding", text="Encoding")
        self.tree.heading("category", text="Category")
        self.tree.heading("length", text="Length")
        self.tree.heading("shannon", text="Shannon")
        self.tree.heading("compression", text="Compression")
        self.tree.heading("ngram", text="N-gram")
        self.tree.heading("meaning", text="Meaning")

        # Add sort indicator to current column
        if self.current_sort_column:
            arrow = " ▼" if self.sort_reverse else " ▲"
            current_text = self.tree.heading(self.current_sort_column, "text")
            if current_text:
                self.tree.heading(self.current_sort_column, text=current_text + arrow)

    def _update_group_column_visibility(self):
        """Show/hide group column based on grouping mode"""
        if self.show_grouped.get():
            self.tree["displaycolumns"] = ("group", "offset", "section", "encoding", "category", "length", "shannon", "compression", "ngram", "meaning")
        else:
            self.tree["displaycolumns"] = ("offset", "section", "encoding", "category", "length", "shannon", "compression", "ngram", "meaning")


    def show_progress(self, show=True):
        """Show or hide the progress bar"""
        if show:
            self.progress_bar.pack(side=tk.RIGHT, padx=(5, 0))
        else:
            self.progress_bar.pack_forget()
        self.root.update_idletasks()

    def update_progress(self, value, status="Processing..."):
        """Update progress bar and status"""
        self.progress_var.set(value)
        self.status_var.set(status)
        self.root.update_idletasks()

    def open_file(self):
        """Open and analyze an ELF file"""
        if self.is_processing:
            return

        filename = filedialog.askopenfilename(
            title="Select ELF File",
            filetypes=[("ELF files", "*.elf *.so *.o"), ("All files", "*.*")]
        )

        if filename:
            self.is_processing = True
            self.show_progress(True)

            # Run extraction in a separate thread to keep UI responsive
            def extract_worker():
                try:
                    # Set extraction options
                    self.extractor.min_length = self.min_length_var.get()
                    self.extractor.set_encoding_options(
                        ascii=self.extract_ascii_var.get(),
                        utf8=self.extract_utf8_var.get(),
                        utf16le=self.extract_utf16le_var.get(),
                        utf16be=self.extract_utf16be_var.get()
                    )

                    # Extract strings with progress reporting
                    self.current_strings = self.extractor.extract_from_elf(
                        filename, self.update_progress
                    )

                    # Update UI in main thread
                    self.root.after(0, self.update_ui_after_extraction)

                except Exception as e:
                    self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to analyze file: {e}"))
                    self.root.after(0, self.finish_processing)

            threading.Thread(target=extract_worker, daemon=True).start()

    def finish_processing(self):
        """Clean up after processing is complete"""
        self.is_processing = False
        self.show_progress(False)
        self.status_var.set("Ready")

    def update_ui_after_extraction(self):
        """Update UI after string extraction is complete"""
        def ui_update_worker():
            try:
                # Update filter options
                self.root.after(0, lambda: self.update_progress(95, "Updating filter options..."))
                self.root.after(0, self.update_filter_options)

                # Display results
                self.root.after(0, lambda: self.update_progress(98, "Applying filters and displaying results..."))

                # Apply filters automatically after loading
                def apply_and_finish():
                    self.apply_filters()
                    self.status_var.set(f"Extracted {len(self.current_strings)} strings")
                    self.finish_processing()

                self.root.after(0, apply_and_finish)

            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to update UI: {e}"))
                self.root.after(0, self.finish_processing)

        threading.Thread(target=ui_update_worker, daemon=True).start()

    def update_filter_options(self):
        """Update filter checkboxes based on extracted strings"""
        # Clear existing filters
        for widget in self.section_frame.winfo_children():
            widget.destroy()
        for widget in self.category_frame.winfo_children():
            widget.destroy()

        self.section_vars.clear()
        self.category_vars.clear()

        # Get unique values
        sections = set(s.section for s in self.current_strings)
        categories = set(s.category for s in self.current_strings)

        # Create section checkboxes
        for section in sorted(sections):
            var = tk.BooleanVar(value=True)
            self.section_vars[section] = var
            cb = ttk.Checkbutton(self.section_frame, text=section, variable=var, command=self.apply_filters)
            cb.pack(anchor=tk.W)
            self._create_tooltip(cb, f"Show/hide strings from ELF section '{section}'")

        # Create category checkboxes
        for category in sorted(categories):
            var = tk.BooleanVar(value=True)
            self.category_vars[category] = var
            cb = ttk.Checkbutton(self.category_frame, text=category, variable=var, command=self.apply_filters)
            cb.pack(anchor=tk.W)
            self._create_tooltip(cb, f"Show/hide strings categorized as '{category}'")

    def apply_filters(self, event=None):
        """Apply current filters and update the tree view"""
        if self.is_processing:
            return

        # Clear tree
        for item in self.tree.get_children():
            self.tree.delete(item)

        if not self.current_strings:
            return

        # Show progress for filtering operations
        show_progress = len(self.current_strings) > 1000  # Only show for large datasets

        if show_progress:
            self.show_progress(True)
            self.update_progress(0, "Applying UI filters...")

        # Filter strings by UI filters
        filtered_strings = []
        for i, string_info in enumerate(self.current_strings):
            if show_progress and i % 500 == 0:
                progress = (i / len(self.current_strings)) * 60  # 0-60% for UI filtering
                self.update_progress(progress, f"Applying UI filters... ({i}/{len(self.current_strings)})")

            # Check section filter
            if string_info.section in self.section_vars and not self.section_vars[string_info.section].get():
                continue

            # Check category filter
            if string_info.category in self.category_vars and not self.category_vars[string_info.category].get():
                continue

            filtered_strings.append(string_info)

        # Group strings if enabled
        if self.show_grouped.get() and filtered_strings:
            if show_progress:
                self.update_progress(65, "Grouping strings...")

            # Create temporary grouper with filtered strings
            temp_grouper = StringGrouper()
            self.current_groups = temp_grouper.group_strings(
                filtered_strings,
                proximity_threshold=self.proximity_threshold_var.get(),
                group_by_section=self.group_by_section_var.get(),
                semantic_grouping=self.semantic_grouping_var.get()
            )

            if show_progress:
                self.update_progress(85, "Populating grouped view...")

            self._populate_grouped_tree(self.current_groups)
        else:
            if show_progress:
                self.update_progress(85, "Populating flat view...")

            self._populate_flat_tree(filtered_strings)

        if show_progress:
            self.update_progress(100, "Complete!")
            # Hide progress bar after a short delay
            self.root.after(500, lambda: self.show_progress(False))

    def _populate_grouped_tree(self, groups):
        """Populate tree with grouped strings"""
        # Show progress for group sorting if there are many groups
        show_sort_progress = len(groups) > 100

        if show_sort_progress:
            self.show_progress(True)
            self.update_progress(0, "Sorting groups...")

        # Sort groups based on selected group sort criteria
        group_sort_key = self.group_sort_var.get().lower()
        if group_sort_key == "offset":
            groups.sort(key=lambda g: g.start_offset or 0)
        elif group_sort_key == "length":
            groups.sort(key=lambda g: sum(s.length for s in g.strings), reverse=True)
        elif group_sort_key == "string count":
            groups.sort(key=lambda g: len(g.strings), reverse=True)
        elif group_sort_key == "shannon entropy":
            groups.sort(key=lambda g: g.avg_shannon_entropy, reverse=True)
        elif group_sort_key == "compression entropy":
            groups.sort(key=lambda g: g.avg_compression_entropy, reverse=True)
        elif group_sort_key == "n-gram entropy":
            groups.sort(key=lambda g: g.avg_ngram_entropy, reverse=True)
        elif group_sort_key == "meaningfulness":
            groups.sort(key=lambda g: g.avg_meaningfulness, reverse=True)
        elif group_sort_key == "group id":
            groups.sort(key=lambda g: g.group_id)
        else:
            groups.sort(key=lambda g: g.start_offset or 0)

        if show_sort_progress:
            self.update_progress(20, "Populating tree...")

        # Calculate padding for group names
        max_group_id = max(g.group_id for g in groups) if groups else 0
        max_string_count = max(len(g.strings) for g in groups) if groups else 0
        group_id_width = len(str(max_group_id))
        string_count_width = len(str(max_string_count))

        for i, group in enumerate(groups):
            if show_sort_progress and i % 50 == 0:
                progress = 20 + (i / len(groups)) * 60  # 20-80% for tree population
                self.update_progress(progress, f"Populating tree... ({i}/{len(groups)} groups)")

            # Create formatted group name
            group_id_padded = str(group.group_id).rjust(group_id_width)
            string_count_padded = str(len(group.strings)).rjust(string_count_width)
            group_name = f"📁 Group {group_id_padded}: {string_count_padded} strings"

            # Create group header
            group_item = self.tree.insert("", tk.END,
                text=f"{string_count_padded} strings",
                values=(
                    str(group.group_id),
                    f"0x{group.start_offset:x}-0x{group.end_offset:x}" if group.start_offset else "",
                    group.section,
                    "mixed" if len(set(s.encoding for s in group.strings)) > 1 else group.strings[0].encoding,
                    group.dominant_category,
                    f"{group.size} bytes",
                    f"{group.avg_shannon_entropy:.2f}",
                    f"{group.avg_compression_entropy:.2f}",
                    f"{group.avg_ngram_entropy:.2f}",
                    f"{group.avg_meaningfulness:.1f}"
                ),
                tags=("group_header",)
            )

            # Sort strings within group based on column header clicks
            strings_to_sort = group.strings.copy()
            if self.current_sort_column:
                if self.current_sort_column == "offset":
                    strings_to_sort.sort(key=lambda x: x.offset, reverse=self.sort_reverse)
                elif self.current_sort_column == "section":
                    strings_to_sort.sort(key=lambda x: x.section, reverse=self.sort_reverse)
                elif self.current_sort_column == "encoding":
                    strings_to_sort.sort(key=lambda x: x.encoding, reverse=self.sort_reverse)
                elif self.current_sort_column == "category":
                    strings_to_sort.sort(key=lambda x: x.category, reverse=self.sort_reverse)
                elif self.current_sort_column == "length":
                    strings_to_sort.sort(key=lambda x: x.length, reverse=self.sort_reverse)
                elif self.current_sort_column == "shannon":
                    strings_to_sort.sort(key=lambda x: x.entropy_shannon, reverse=self.sort_reverse)
                elif self.current_sort_column == "compression":
                    strings_to_sort.sort(key=lambda x: x.entropy_compression, reverse=self.sort_reverse)
                elif self.current_sort_column == "ngram":
                    strings_to_sort.sort(key=lambda x: x.entropy_ngram, reverse=self.sort_reverse)
                elif self.current_sort_column == "meaning":
                    strings_to_sort.sort(key=lambda x: x.meaningfulness_score, reverse=self.sort_reverse)
                elif self.current_sort_column == "group":
                    strings_to_sort.sort(key=lambda x: x.group_id if x.group_id is not None else -1, reverse=self.sort_reverse)

            # Add strings to group
            for string_info in strings_to_sort:
                display_string = repr(string_info.decoded_string)[1:-1]
                if len(display_string) > 60:
                    display_string = display_string[:57] + "..."

                self.tree.insert(group_item, tk.END,
                    text=f"  {display_string}",
                    values=(
                        str(string_info.group_id) if string_info.group_id is not None else "",
                        f"0x{string_info.offset:x}",
                        string_info.section,
                        string_info.encoding,
                        string_info.category,
                        string_info.length,
                        f"{string_info.entropy_shannon:.2f}",
                        f"{string_info.entropy_compression:.2f}",
                        f"{string_info.entropy_ngram:.2f}",
                        f"{string_info.meaningfulness_score:.1f}"
                    ),
                    tags=(string_info,)
                )

        # Configure group header styling
        self.tree.tag_configure("group_header", background="#e8f4fd", font=("TkDefaultFont", 9, "bold"))

        if show_sort_progress:
            self.update_progress(100, "Complete!")
            # Hide progress bar after a short delay
            self.root.after(500, lambda: self.show_progress(False))

        # Update status
        total_strings = sum(len(g.strings) for g in groups)
        if not self.is_processing:
            self.status_var.set(f"Showing {len(groups)} groups with {total_strings} strings")

    def _populate_flat_tree(self, filtered_strings):
        """Populate tree with flat string list"""
        # Sort strings based on column header clicks
        strings_to_sort = filtered_strings.copy()
        if self.current_sort_column:
            if self.current_sort_column == "offset":
                strings_to_sort.sort(key=lambda x: x.offset, reverse=self.sort_reverse)
            elif self.current_sort_column == "section":
                strings_to_sort.sort(key=lambda x: x.section, reverse=self.sort_reverse)
            elif self.current_sort_column == "encoding":
                strings_to_sort.sort(key=lambda x: x.encoding, reverse=self.sort_reverse)
            elif self.current_sort_column == "category":
                strings_to_sort.sort(key=lambda x: x.category, reverse=self.sort_reverse)
            elif self.current_sort_column == "length":
                strings_to_sort.sort(key=lambda x: x.length, reverse=self.sort_reverse)
            elif self.current_sort_column == "shannon":
                strings_to_sort.sort(key=lambda x: x.entropy_shannon, reverse=self.sort_reverse)
            elif self.current_sort_column == "compression":
                strings_to_sort.sort(key=lambda x: x.entropy_compression, reverse=self.sort_reverse)
            elif self.current_sort_column == "ngram":
                strings_to_sort.sort(key=lambda x: x.entropy_ngram, reverse=self.sort_reverse)
            elif self.current_sort_column == "meaning":
                strings_to_sort.sort(key=lambda x: x.meaningfulness_score, reverse=self.sort_reverse)
            elif self.current_sort_column == "group":
                strings_to_sort.sort(key=lambda x: x.group_id if x.group_id is not None else -1, reverse=self.sort_reverse)

        # Populate tree
        for string_info in strings_to_sort:
            # Escape string for display
            display_string = repr(string_info.decoded_string)[1:-1]  # Remove quotes
            if len(display_string) > 80:
                display_string = display_string[:77] + "..."

            self.tree.insert("", tk.END,
                text=display_string,
                values=(
                    str(string_info.group_id) if string_info.group_id is not None else "",
                    f"0x{string_info.offset:x}",
                    string_info.section,
                    string_info.encoding,
                    string_info.category,
                    string_info.length,
                    f"{string_info.entropy_shannon:.2f}",
                    f"{string_info.entropy_compression:.2f}",
                    f"{string_info.entropy_ngram:.2f}",
                    f"{string_info.meaningfulness_score:.1f}"
                ),
                tags=(string_info,)
            )

        # Update status
        if not self.is_processing:
            self.status_var.set(f"Showing {len(filtered_strings)} strings")

    def show_string_details(self, event):
        """Show detailed information about selected string"""
        selection = self.tree.selection()
        if not selection:
            return

        item = selection[0]
        tags = self.tree.item(item, "tags")
        if not tags or tags[0] == "group_header":
            return

        string_info = tags[0]
        if isinstance(string_info, str):
            return

        # Create detail window
        detail_window = tk.Toplevel(self.root)
        detail_window.title("String Details")
        detail_window.geometry("600x500")

        # Create notebook for tabs
        notebook = ttk.Notebook(detail_window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # General info tab
        info_frame = ttk.Frame(notebook)
        notebook.add(info_frame, text="General Info")

        info_text = tk.Text(info_frame, wrap=tk.WORD)
        info_text.pack(fill=tk.BOTH, expand=True)

        info_content = f"""Offset: 0x{string_info.offset:x}
Section: {string_info.section}
Encoding: {string_info.encoding}
Category: {string_info.category}
Length: {string_info.length}
Group ID: {string_info.group_id if string_info.group_id is not None else "None"}
Shannon Entropy: {string_info.entropy_shannon:.4f}
Compression Entropy: {string_info.entropy_compression:.4f}
N-gram Entropy: {string_info.entropy_ngram:.4f}
Meaningfulness Score: {string_info.meaningfulness_score:.2f}

Raw String:
{string_info.decoded_string}
"""
        info_text.insert(tk.END, info_content)
        info_text.config(state=tk.DISABLED)

        # Hex dump tab
        hex_frame = ttk.Frame(notebook)
        notebook.add(hex_frame, text="Hex Dump")

        hex_text = tk.Text(hex_frame, wrap=tk.NONE, font=("Courier", 10))
        hex_text.pack(fill=tk.BOTH, expand=True)

        # Create hex dump
        hex_dump = ""
        for i in range(0, len(string_info.raw_data), 16):
            chunk = string_info.raw_data[i:i+16]
            hex_bytes = ' '.join(f'{b:02x}' for b in chunk)
            ascii_chars = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            hex_dump += f"{string_info.offset + i:08x}: {hex_bytes:<48} {ascii_chars}\n"

        hex_text.insert(tk.END, hex_dump)
        hex_text.config(state=tk.DISABLED)

        # Group info tab (if string belongs to a group)
        if string_info.group_id is not None and hasattr(self, 'current_groups'):
            group_frame = ttk.Frame(notebook)
            notebook.add(group_frame, text="Group Info")

            group_text = tk.Text(group_frame, wrap=tk.WORD)
            group_text.pack(fill=tk.BOTH, expand=True)

            # Find the group
            group = None
            for g in self.current_groups:
                if g.group_id == string_info.group_id:
                    group = g
                    break

            if group:
                group_info = f"""Group ID: {group.group_id}
Section: {group.section}
Strings Count: {len(group.strings)}
Address Range: 0x{group.start_offset:x} - 0x{group.end_offset:x}
Size: {group.size} bytes
Dominant Category: {group.dominant_category}
Average Meaningfulness: {group.avg_meaningfulness:.2f}

Other strings in this group:
"""
                for other_string in group.strings:
                    if other_string != string_info:
                        preview = repr(other_string.decoded_string)[1:-1]
                        if len(preview) > 60:
                            preview = preview[:57] + "..."
                        group_info += f"• 0x{other_string.offset:x}: {preview}\n"

                group_text.insert(tk.END, group_info)
            else:
                group_text.insert(tk.END, "Group information not available.")

            group_text.config(state=tk.DISABLED)

    def _create_tooltip(self, widget, text):
        """Create a tooltip for a widget"""
        def on_enter(event):
            tooltip = tk.Toplevel()
            tooltip.wm_overrideredirect(True)
            tooltip.wm_geometry(f"+{event.x_root+10}+{event.y_root+10}")

            label = tk.Label(tooltip, text=text, background="lightyellow",
                           relief="solid", borderwidth=1, font=("Arial", 9))
            label.pack()

            widget.tooltip = tooltip

        def on_leave(event):
            if hasattr(widget, 'tooltip'):
                widget.tooltip.destroy()
                del widget.tooltip

        widget.bind("<Enter>", on_enter)
        widget.bind("<Leave>", on_leave)

    def run(self):
        """Start the GUI"""
        self.root.mainloop()

def _extract_strings_worker(args):
    """Worker function for parallel string extraction"""
    (section_data, base_offset, section_name, min_length,
     extract_ascii, extract_utf8, extract_utf16le, extract_utf16be) = args

    # Create a temporary extractor for this worker
    extractor = StringExtractor(min_length)
    extractor.set_encoding_options(extract_ascii, extract_utf8, extract_utf16le, extract_utf16be)

    # Extract strings from this section
    return extractor._extract_strings_from_data(section_data, base_offset, section_name)

def _group_strings_worker(args):
    """Worker function for parallel string grouping"""
    (section_strings, proximity_threshold, group_id_offset, section_name) = args

    # Create a temporary grouper for this worker
    grouper = StringGrouper()

    # Group strings by proximity
    groups = grouper._group_by_proximity(section_strings, proximity_threshold, group_id_offset, section_name)

    return groups

def _analyze_strings_worker(string_chunk):
    """Worker function for parallel string analysis"""
    # Create a temporary extractor for analysis methods
    extractor = StringExtractor()

    analyzed_strings = []
    for string_info in string_chunk:
        # Analyze the string
        string_info.entropy_shannon = extractor._calculate_shannon_entropy(string_info.decoded_string)
        string_info.entropy_compression = extractor._calculate_compression_entropy(string_info.raw_data)
        string_info.entropy_ngram = extractor._calculate_ngram_entropy(string_info.decoded_string)

        # Calculate base meaningfulness score
        base_score = extractor._calculate_meaningfulness_score(string_info.decoded_string)

        # Incorporate entropy into meaningfulness score
        entropy_bonus = min(string_info.entropy_shannon * 2, 10)
        compression_bonus = min(string_info.entropy_compression * 1.5, 8)
        ngram_bonus = min(string_info.entropy_ngram * 1.5, 8)

        # Combine base score with entropy bonuses
        string_info.meaningfulness_score = base_score + entropy_bonus + compression_bonus + ngram_bonus
        string_info.category = extractor._categorize_string(string_info.decoded_string)

        analyzed_strings.append(string_info)

    return analyzed_strings

def main():
    """Main entry point"""
    try:
        # Set multiprocessing start method for better compatibility
        if hasattr(multiprocessing, 'set_start_method'):
            try:
                multiprocessing.set_start_method('spawn', force=True)
            except RuntimeError:
                pass  # Already set

        app = StringExtractorGUI()
        app.run()
    except Exception as e:
        print(f"Error starting application: {e}")

if __name__ == "__main__":
    main()
