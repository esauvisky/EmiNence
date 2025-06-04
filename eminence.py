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
from typing import List, Dict, Tuple, Optional
import threading

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

class StringExtractor:
    """Main string extraction and analysis engine"""

    def __init__(self, min_length: int = 4):
        self.min_length = min_length
        self.sections_data = {}
        self.strings = []

    def extract_from_elf(self, filepath: str) -> List[StringInfo]:
        """Extract strings from ELF file"""
        self.strings = []

        try:
            with open(filepath, 'rb') as f:
                elf = ELFFile(f)

                # Extract section data
                for section in elf.iter_sections():
                    if section.data_size > 0:
                        section_data = section.data()
                        section_name = section.name
                        base_offset = section['sh_offset']

                        # Extract strings from this section
                        section_strings = self._extract_strings_from_data(
                            section_data, base_offset, section_name
                        )
                        self.strings.extend(section_strings)

        except (ELFError, Exception) as e:
            raise Exception(f"Error parsing ELF file: {e}")

        # Analyze all extracted strings
        self._analyze_strings()

        return self.strings

    def _extract_strings_from_data(self, data: bytes, base_offset: int, section: str) -> List[StringInfo]:
        """Extract strings from binary data using multiple encoding strategies"""
        strings = []

        # ASCII strings
        strings.extend(self._find_ascii_strings(data, base_offset, section))

        # UTF-8 strings
        strings.extend(self._find_utf8_strings(data, base_offset, section))

        # UTF-16 strings (both little and big endian)
        strings.extend(self._find_utf16_strings(data, base_offset, section))

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

    def _find_utf16_strings(self, data: bytes, base_offset: int, section: str) -> List[StringInfo]:
        """Find UTF-16 strings (both LE and BE)"""
        strings = []

        # UTF-16 LE
        strings.extend(self._find_utf16_encoding(data, base_offset, section, 'utf-16le'))

        # UTF-16 BE
        strings.extend(self._find_utf16_encoding(data, base_offset, section, 'utf-16be'))

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

    def _analyze_strings(self):
        """Analyze all extracted strings"""
        for string_info in self.strings:
            string_info.entropy_shannon = self._calculate_shannon_entropy(string_info.decoded_string)
            string_info.entropy_compression = self._calculate_compression_entropy(string_info.raw_data)
            string_info.entropy_ngram = self._calculate_ngram_entropy(string_info.decoded_string)
            string_info.meaningfulness_score = self._calculate_meaningfulness_score(string_info.decoded_string)
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
            score += 15

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
        self.root.title("Advanced ELF String Extractor")
        self.root.geometry("1200x800")

        self.extractor = StringExtractor()
        self.current_strings = []

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
        left_frame = ttk.LabelFrame(main_frame, text="Filters & Options", width=300)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 5))
        left_frame.pack_propagate(False)

        # Minimum length setting
        ttk.Label(left_frame, text="Minimum Length:").pack(anchor=tk.W, padx=5, pady=2)
        self.min_length_var = tk.IntVar(value=4)
        min_length_spin = ttk.Spinbox(left_frame, from_=1, to=50, textvariable=self.min_length_var, width=10)
        min_length_spin.pack(anchor=tk.W, padx=5, pady=2)

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

        # Encoding filter
        ttk.Label(left_frame, text="Encodings:").pack(anchor=tk.W, padx=5, pady=(10, 2))
        self.encoding_frame = ttk.Frame(left_frame)
        self.encoding_frame.pack(fill=tk.X, padx=5, pady=2)
        self.encoding_vars = {}

        # Sort options
        ttk.Label(left_frame, text="Sort by:").pack(anchor=tk.W, padx=5, pady=(10, 2))
        self.sort_var = tk.StringVar(value="offset")
        sort_options = ["Offset", "Length", "Shannon Entropy", "Compression Entropy", "N-gram Entropy", "Meaningfulness"]
        sort_combo = ttk.Combobox(left_frame, textvariable=self.sort_var, values=sort_options, state="readonly")
        sort_combo.pack(fill=tk.X, padx=5, pady=2)
        sort_combo.bind('<<ComboboxSelected>>', self.apply_filters)

        # Apply filters button
        ttk.Button(left_frame, text="Apply Filters", command=self.apply_filters).pack(fill=tk.X, padx=5, pady=10)

        # Right panel - results
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Results tree
        tree_frame = ttk.LabelFrame(right_frame, text="Extracted Strings")
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))

        # Treeview with scrollbars
        tree_container = ttk.Frame(tree_frame)
        tree_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.tree = ttk.Treeview(tree_container, columns=("offset", "section", "encoding", "category", "length", "shannon", "compression", "ngram", "meaning"), show="tree headings")

        # Configure columns
        self.tree.heading("#0", text="String")
        self.tree.heading("offset", text="Offset")
        self.tree.heading("section", text="Section")
        self.tree.heading("encoding", text="Encoding")
        self.tree.heading("category", text="Category")
        self.tree.heading("length", text="Length")
        self.tree.heading("shannon", text="Shannon")
        self.tree.heading("compression", text="Compression")
        self.tree.heading("ngram", text="N-gram")
        self.tree.heading("meaning", text="Meaning")

        self.tree.column("#0", width=300)
        self.tree.column("offset", width=80)
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

        # Bind double-click for detail view
        self.tree.bind("<Double-1>", self.show_string_details)

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(right_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.pack(fill=tk.X, pady=(5, 0))

    def open_file(self):
        """Open and analyze an ELF file"""
        filename = filedialog.askopenfilename(
            title="Select ELF File",
            filetypes=[("ELF files", "*.elf *.so *.o"), ("All files", "*.*")]
        )

        if filename:
            self.status_var.set("Analyzing file...")
            self.root.update()

            # Run extraction in a separate thread to keep UI responsive
            def extract_worker():
                try:
                    self.extractor.min_length = self.min_length_var.get()
                    self.current_strings = self.extractor.extract_from_elf(filename)

                    # Update UI in main thread
                    self.root.after(0, self.update_ui_after_extraction)

                except Exception as e:
                    self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to analyze file: {e}"))
                    self.root.after(0, lambda: self.status_var.set("Ready"))

            threading.Thread(target=extract_worker, daemon=True).start()

    def update_ui_after_extraction(self):
        """Update UI after string extraction is complete"""
        # Update filter options
        self.update_filter_options()

        # Display results
        self.apply_filters()

        self.status_var.set(f"Extracted {len(self.current_strings)} strings")

    def update_filter_options(self):
        """Update filter checkboxes based on extracted strings"""
        # Clear existing filters
        for widget in self.section_frame.winfo_children():
            widget.destroy()
        for widget in self.category_frame.winfo_children():
            widget.destroy()
        for widget in self.encoding_frame.winfo_children():
            widget.destroy()

        self.section_vars.clear()
        self.category_vars.clear()
        self.encoding_vars.clear()

        # Get unique values
        sections = set(s.section for s in self.current_strings)
        categories = set(s.category for s in self.current_strings)
        encodings = set(s.encoding for s in self.current_strings)

        # Create section checkboxes
        for section in sorted(sections):
            var = tk.BooleanVar(value=True)
            self.section_vars[section] = var
            cb = ttk.Checkbutton(self.section_frame, text=section, variable=var, command=self.apply_filters)
            cb.pack(anchor=tk.W)

        # Create category checkboxes
        for category in sorted(categories):
            var = tk.BooleanVar(value=True)
            self.category_vars[category] = var
            cb = ttk.Checkbutton(self.category_frame, text=category, variable=var, command=self.apply_filters)
            cb.pack(anchor=tk.W)

        # Create encoding checkboxes
        for encoding in sorted(encodings):
            var = tk.BooleanVar(value=True)
            self.encoding_vars[encoding] = var
            cb = ttk.Checkbutton(self.encoding_frame, text=encoding, variable=var, command=self.apply_filters)
            cb.pack(anchor=tk.W)

    def apply_filters(self, event=None):
        """Apply current filters and update the tree view"""
        # Clear tree
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Filter strings
        filtered_strings = []
        for string_info in self.current_strings:
            # Check section filter
            if string_info.section in self.section_vars and not self.section_vars[string_info.section].get():
                continue

            # Check category filter
            if string_info.category in self.category_vars and not self.category_vars[string_info.category].get():
                continue

            # Check encoding filter
            if string_info.encoding in self.encoding_vars and not self.encoding_vars[string_info.encoding].get():
                continue

            filtered_strings.append(string_info)

        # Sort strings
        sort_key = self.sort_var.get().lower()
        if sort_key == "offset":
            filtered_strings.sort(key=lambda x: x.offset)
        elif sort_key == "length":
            filtered_strings.sort(key=lambda x: x.length, reverse=True)
        elif sort_key == "shannon entropy":
            filtered_strings.sort(key=lambda x: x.entropy_shannon, reverse=True)
        elif sort_key == "compression entropy":
            filtered_strings.sort(key=lambda x: x.entropy_compression, reverse=True)
        elif sort_key == "n-gram entropy":
            filtered_strings.sort(key=lambda x: x.entropy_ngram, reverse=True)
        elif sort_key == "meaningfulness":
            filtered_strings.sort(key=lambda x: x.meaningfulness_score, reverse=True)

        # Populate tree
        for string_info in filtered_strings:
            # Escape string for display
            display_string = repr(string_info.decoded_string)[1:-1]  # Remove quotes
            if len(display_string) > 80:
                display_string = display_string[:77] + "..."

            self.tree.insert("", tk.END,
                text=display_string,
                values=(
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

    def show_string_details(self, event):
        """Show detailed information about selected string"""
        selection = self.tree.selection()
        if not selection:
            return

        item = selection[0]
        tags = self.tree.item(item, "tags")
        if not tags:
            return

        string_info = tags[0]

        # Create detail window
        detail_window = tk.Toplevel(self.root)
        detail_window.title("String Details")
        detail_window.geometry("600x400")

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

    def run(self):
        """Start the GUI"""
        self.root.mainloop()

def main():
    """Main entry point"""
    try:
        app = StringExtractorGUI()
        app.run()
    except Exception as e:
        print(f"Error starting application: {e}")

if __name__ == "__main__":
    main()
