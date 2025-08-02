import os
import sys
import struct
import binascii
import threading
from typing import List, Dict, Tuple, Optional
from PIL import Image, ImageTk, ImageDraw, ImageFont
import io
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext


class FileRecoveryTool:
    """
    File Recovery Tool - Module 1
    Recovers deleted files from disk images using file signatures (magic bytes)
    """

    # Common file signatures (magic bytes)
    FILE_SIGNATURES = {
        'JPEG': [b'\xFF\xD8\xFF'],
        'PNG': [b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'],
        'GIF': [b'GIF87a', b'GIF89a'],
        'PDF': [b'%PDF-'],
        'ZIP': [b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08'],
        'RAR': [b'Rar!\x1A\x07\x00', b'Rar!\x1A\x07\x01\x00'],
        'DOC': [b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'],
        'DOCX': [b'PK\x03\x04\x14\x00\x06\x00'],
        'MP3': [b'ID3', b'\xFF\xFB', b'\xFF\xF3', b'\xFF\xF2'],
        'MP4': [b'\x00\x00\x00\x18ftypmp4', b'\x00\x00\x00\x20ftypmp4'],
        'AVI': [b'RIFF', b'AVI LIST'],
        'EXE': [b'MZ'],
        'BMP': [b'BM'],
        'TIFF': [b'II\x2A\x00', b'MM\x00\x2A'],
        'RTF': [b'{\\rtf1'],
        'SQLite': [b'SQLite format 3\x00'],
        'WAV': [b'RIFF'],
        'FLAC': [b'fLaC'],
        'OGG': [b'OggS'],
        'MKV': [b'\x1A\x45\xDF\xA3'],
        'WEBM': [b'\x1A\x45\xDF\xA3'],
        'ICO': [b'\x00\x00\x01\x00'],
        'TAR': [b'ustar\x00', b'ustar\x20\x20\x00']
    }

    def __init__(self, output_dir: str = "recovered_files", progress_callback=None, log_callback=None):
        self.output_dir = output_dir
        self.recovered_files = []
        self.stats = {
            'total_files': 0,
            'file_types': {},
            'total_size': 0
        }
        self.progress_callback = progress_callback
        self.log_callback = log_callback

    def log(self, message):
        """Log message with callback support"""
        if self.log_callback:
            self.log_callback(message)
        else:
            print(message)

    def update_progress(self, value):
        """Update progress with callback support"""
        if self.progress_callback:
            self.progress_callback(value)

    def create_output_directory(self):
        """Create output directory for recovered files"""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            self.log(f"[INFO] Created output directory: {self.output_dir}")

    def identify_file_type(self, data: bytes) -> Optional[str]:
        """Identify file type based on magic bytes"""
        for file_type, signatures in self.FILE_SIGNATURES.items():
            for signature in signatures:
                if data.startswith(signature):
                    return file_type
        return None

    def get_file_extension(self, file_type: str) -> str:
        """Get appropriate file extension for file type"""
        extensions = {
            'JPEG': '.jpg',
            'PNG': '.png',
            'GIF': '.gif',
            'PDF': '.pdf',
            'ZIP': '.zip',
            'RAR': '.rar',
            'DOC': '.doc',
            'DOCX': '.docx',
            'MP3': '.mp3',
            'MP4': '.mp4',
            'AVI': '.avi',
            'EXE': '.exe',
            'BMP': '.bmp',
            'TIFF': '.tiff',
            'RTF': '.rtf',
            'SQLite': '.db',
            'WAV': '.wav',
            'FLAC': '.flac',
            'OGG': '.ogg',
            'MKV': '.mkv',
            'WEBM': '.webm',
            'ICO': '.ico',
            'TAR': '.tar'
        }
        return extensions.get(file_type, '.bin')

    def extract_file_content(self, data: bytes, start_pos: int, file_type: str) -> bytes:
        """Extract complete file content based on file type"""
        if file_type == 'JPEG':
            # Find JPEG end marker (FFD9)
            end_pos = data.find(b'\xFF\xD9', start_pos)
            if end_pos != -1:
                return data[start_pos:end_pos + 2]

        elif file_type == 'PNG':
            # Find PNG end marker (IEND)
            end_pos = data.find(b'IEND', start_pos)
            if end_pos != -1:
                return data[start_pos:end_pos + 8]

        elif file_type == 'GIF':
            # Find GIF trailer (00 3B)
            end_pos = data.find(b'\x00\x3B', start_pos)
            if end_pos != -1:
                return data[start_pos:end_pos + 2]

        elif file_type == 'PDF':
            # Find PDF end marker (%%EOF)
            end_pos = data.find(b'%%EOF', start_pos)
            if end_pos != -1:
                return data[start_pos:end_pos + 5]

        elif file_type == 'ZIP' or file_type == 'DOCX':
            # Find ZIP end of central directory
            end_pos = data.find(b'PK\x05\x06', start_pos)
            if end_pos != -1:
                # Read the central directory end record
                end_pos += 22  # Standard size of end record
                return data[start_pos:end_pos]

        elif file_type == 'MP3':
            # For MP3, try to find next frame or use heuristic
            # This is simplified - real implementation would parse frames
            max_size = min(5 * 1024 * 1024, len(data) - start_pos)  # 5MB max
            return data[start_pos:start_pos + max_size]

        # For other file types, extract a reasonable chunk
        chunk_size = min(1024 * 1024, len(data) - start_pos)  # 1MB max or remaining data
        return data[start_pos:start_pos + chunk_size]

    def validate_file_content(self, content: bytes, file_type: str) -> bool:
        """Validate if the extracted content is likely a valid file"""
        if len(content) < 10:  # Too small to be a valid file
            return False

        # Basic validation based on file type
        if file_type == 'JPEG':
            return content.startswith(b'\xFF\xD8\xFF') and content.endswith(b'\xFF\xD9')
        elif file_type == 'PNG':
            return content.startswith(b'\x89PNG') and b'IEND' in content
        elif file_type == 'GIF':
            return content.startswith(b'GIF') and content.endswith(b'\x00\x3B')
        elif file_type == 'PDF':
            return content.startswith(b'%PDF-') and b'%%EOF' in content

        return True  # For other types, assume valid if we got here

    def scan_disk_image(self, image_path: str, chunk_size: int = 1024 * 1024) -> List[Dict]:
        """Scan disk image for file signatures"""
        recovered_files = []
        file_size = os.path.getsize(image_path)

        self.log(f"[INFO] Scanning disk image: {image_path}")
        self.log(f"[INFO] Image size: {file_size / (1024*1024):.2f} MB")
        self.log(f"[INFO] Chunk size: {chunk_size / 1024:.0f} KB")
        self.log("[INFO] Starting scan...")

        try:
            with open(image_path, 'rb') as f:
                offset = 0
                processed_mb = 0

                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break

                    # Progress indicator
                    current_mb = offset / (1024 * 1024)
                    progress = (offset / file_size) * 100
                    self.update_progress(progress)

                    if current_mb - processed_mb >= 10:  # Show progress every 10MB
                        self.log(f"[PROGRESS] {progress:.1f}% - Processed {current_mb:.0f} MB")
                        processed_mb = current_mb

                    # Search for file signatures in chunk
                    for file_type, signatures in self.FILE_SIGNATURES.items():
                        for signature in signatures:
                            pos = 0
                            while True:
                                pos = chunk.find(signature, pos)
                                if pos == -1:
                                    break

                                # Calculate absolute position in file
                                abs_pos = offset + pos

                                # Extract file content
                                f.seek(abs_pos)
                                file_data = f.read(min(chunk_size * 2, file_size - abs_pos))
                                content = self.extract_file_content(file_data, 0, file_type)

                                if content and self.validate_file_content(content, file_type):
                                    recovered_files.append({
                                        'type': file_type,
                                        'offset': abs_pos,
                                        'size': len(content),
                                        'content': content
                                    })

                                    # Update statistics
                                    self.stats['file_types'][file_type] = self.stats['file_types'].get(file_type, 0) + 1
                                    self.stats['total_size'] += len(content)

                                pos += len(signature)  # Skip past this signature

                    offset += chunk_size

        except Exception as e:
            self.log(f"[ERROR] Error scanning disk image: {e}")
            return []

        self.log(f"[INFO] Scan complete. Found {len(recovered_files)} potential files")
        return recovered_files

    def save_recovered_files(self, recovered_files: List[Dict]):
        """Save recovered files to output directory"""
        self.create_output_directory()

        self.log(f"[INFO] Saving {len(recovered_files)} recovered files...")

        for i, file_info in enumerate(recovered_files):
            file_type = file_info['type']
            extension = self.get_file_extension(file_type)
            filename = f"recovered_{i:04d}_{file_type.lower()}_offset_{file_info['offset']:08x}{extension}"
            filepath = os.path.join(self.output_dir, filename)

            try:
                with open(filepath, 'wb') as f:
                    f.write(file_info['content'])
                self.log(f"[SAVED] {filename} ({file_info['size']} bytes)")
                self.stats['total_files'] += 1
            except Exception as e:
                self.log(f"[ERROR] Failed to save {filename}: {e}")

    def get_statistics(self) -> str:
        """Get recovery statistics as string"""
        stats_text = "="*50 + "\n"
        stats_text += "RECOVERY STATISTICS\n"
        stats_text += "="*50 + "\n"
        stats_text += f"Total files recovered: {self.stats['total_files']}\n"
        stats_text += f"Total size recovered: {self.stats['total_size'] / (1024*1024):.2f} MB\n"
        stats_text += "\nFile types found:\n"

        for file_type, count in sorted(self.stats['file_types'].items()):
            stats_text += f"  {file_type}: {count} files\n"

        stats_text += "="*50
        return stats_text

    def recover_files(self, image_path: str):
        """Main recovery function"""
        self.log(f"[INFO] Starting file recovery from: {image_path}")

        if not os.path.exists(image_path):
            self.log(f"[ERROR] File not found: {image_path}")
            return False

        self.log("[INFO] Scanning for file signatures...")
        recovered_files = self.scan_disk_image(image_path)

        if recovered_files:
            self.save_recovered_files(recovered_files)
            self.log(self.get_statistics())
            self.log(f"[SUCCESS] Recovery complete! Files saved to: {self.output_dir}")
            return True
        else:
            self.log("[WARNING] No recoverable files found")
            return False


class SteganographyTool:
    """
    Steganography Tool - Module 2
    Hide and extract text messages in images using LSB (Least Significant Bit) technique
    """

    def __init__(self, log_callback=None):
        self.delimiter = "####END####"  # Delimiter to mark end of message
        self.log_callback = log_callback

    def log(self, message):
        """Log message with callback support"""
        if self.log_callback:
            self.log_callback(message)
        else:
            print(message)

    def text_to_binary(self, text: str) -> str:
        """Convert text to binary string"""
        binary = ''.join(format(ord(char), '08b') for char in text)
        return binary

    def binary_to_text(self, binary: str) -> str:
        """Convert binary string to text"""
        text = ''
        for i in range(0, len(binary), 8):
            byte = binary[i:i+8]
            if len(byte) == 8:
                try:
                    text += chr(int(byte, 2))
                except ValueError:
                    continue  # Skip invalid characters
        return text

    def calculate_capacity(self, image_path: str) -> int:
        """Calculate maximum message capacity for an image"""
        try:
            image = Image.open(image_path)
            width, height = image.size

            # For RGB images, we can use 3 bits per pixel (1 per channel)
            # For grayscale, only 1 bit per pixel
            if image.mode == 'RGB':
                max_bits = width * height * 3
            elif image.mode in ['L', 'P']:
                max_bits = width * height
            else:
                # Convert to RGB and calculate
                image = image.convert('RGB')
                max_bits = width * height * 3

            # Account for delimiter
            delimiter_bits = len(self.text_to_binary(self.delimiter))
            usable_bits = max_bits - delimiter_bits

            # Convert to characters (8 bits each)
            max_chars = usable_bits // 8

            return max_chars

        except Exception as e:
            self.log(f"[ERROR] Error calculating capacity: {e}")
            return 0

    def encode_message(self, image_path: str, message: str, output_path: str) -> bool:
        """Encode message into image using LSB technique"""
        try:
            self.log(f"[INFO] Encoding message into: {image_path}")
            self.log(f"[INFO] Message length: {len(message)} characters")

            # Open and prepare image
            image = Image.open(image_path)
            original_mode = image.mode
            image = image.convert('RGB')  # Ensure RGB mode

            # Check capacity
            capacity = self.calculate_capacity(image_path)
            if len(message) > capacity:
                self.log(f"[ERROR] Message too long for image. Max capacity: {capacity} characters, Message: {len(message)} characters")
                return False

            self.log(f"[INFO] Image capacity: {capacity} characters")

            # Add delimiter to message
            message_with_delimiter = message + self.delimiter
            binary_message = self.text_to_binary(message_with_delimiter)

            self.log(f"[INFO] Binary message length: {len(binary_message)} bits")

            # Get image dimensions
            width, height = image.size

            # Convert image to list of pixels
            pixels = list(image.getdata())

            # Encode message
            bit_index = 0
            new_pixels = []

            for pixel in pixels:
                r, g, b = pixel

                # Modify LSB of each channel if we still have bits to encode
                if bit_index < len(binary_message):
                    r = (r & 0xFE) | int(binary_message[bit_index])
                    bit_index += 1

                if bit_index < len(binary_message):
                    g = (g & 0xFE) | int(binary_message[bit_index])
                    bit_index += 1

                if bit_index < len(binary_message):
                    b = (b & 0xFE) | int(binary_message[bit_index])
                    bit_index += 1

                new_pixels.append((r, g, b))

                # Break if all bits are encoded
                if bit_index >= len(binary_message):
                    # Add remaining unchanged pixels
                    new_pixels.extend(pixels[len(new_pixels):])
                    break

            # Create new image with encoded message
            stego_image = Image.new('RGB', (width, height))
            stego_image.putdata(new_pixels)

            # Save with appropriate format
            if output_path.lower().endswith('.png'):
                stego_image.save(output_path, 'PNG')
            elif output_path.lower().endswith('.jpg') or output_path.lower().endswith('.jpeg'):
                stego_image.save(output_path, 'JPEG', quality=95)
            else:
                stego_image.save(output_path)

            self.log(f"[SUCCESS] Message encoded successfully in: {output_path}")
            self.log(f"[INFO] Used {bit_index} bits out of {len(binary_message)} total message bits")

            return True

        except Exception as e:
            self.log(f"[ERROR] Error encoding message: {e}")
            return False

    def decode_message(self, image_path: str, verbose: bool = True) -> Optional[str]:
        """Decode message from image using LSB technique"""
        try:
            if verbose:
                self.log(f"[INFO] Decoding message from: {image_path}")

            # Open image
            image = Image.open(image_path)
            image = image.convert('RGB')

            # Get image data
            pixels = list(image.getdata())

            if verbose:
                self.log(f"[INFO] Image size: {image.size}")
                self.log(f"[INFO] Total pixels: {len(pixels)}")

            # Extract LSBs
            binary_message = ''
            for pixel in pixels:
                r, g, b = pixel
                binary_message += str(r & 1)
                binary_message += str(g & 1)
                binary_message += str(b & 1)

            if verbose:
                self.log(f"[INFO] Extracted {len(binary_message)} bits")

            # Convert binary to text
            full_message = self.binary_to_text(binary_message)

            # Find delimiter
            if self.delimiter in full_message:
                message = full_message.split(self.delimiter)[0]
                if verbose:
                    self.log(f"[SUCCESS] Hidden message found ({len(message)} characters)")
                return message
            else:
                if verbose:
                    self.log("[WARNING] No hidden message found or delimiter not detected")
                return None

        except Exception as e:
            if verbose:
                self.log(f"[ERROR] Error decoding message: {e}")
            return None

    def analyze_image(self, image_path: str) -> Dict:
        """Analyze image for steganographic properties"""
        try:
            image = Image.open(image_path)
            
            analysis = {
                'path': image_path,
                'format': image.format,
                'mode': image.mode,
                'size': image.size,
                'capacity': self.calculate_capacity(image_path),
                'has_message': False,
                'message': None,
                'message_length': 0
            }

            # Try to decode message
            message = self.decode_message(image_path, verbose=False)
            if message:
                analysis['has_message'] = True
                analysis['message'] = message
                analysis['message_length'] = len(message)

            return analysis

        except Exception as e:
            self.log(f"[ERROR] Error analyzing image: {e}")
            return None


class ForensicToolkitGUI:
    """Main GUI application for the Digital Forensic Toolkit"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Digital Forensic Toolkit")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        
        self.setup_gui()
        
    def setup_gui(self):
        """Setup the main GUI interface"""
        # Create notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # File Recovery Tab
        self.recovery_frame = ttk.Frame(notebook)
        notebook.add(self.recovery_frame, text="File Recovery")
        self.setup_recovery_tab()
        
        # Steganography Tab
        self.stego_frame = ttk.Frame(notebook)
        notebook.add(self.stego_frame, text="Steganography")
        self.setup_steganography_tab()
        
        # About Tab
        self.about_frame = ttk.Frame(notebook)
        notebook.add(self.about_frame, text="About")
        self.setup_about_tab()
        
    def setup_recovery_tab(self):
        """Setup file recovery tab"""
        # Main frame
        main_frame = ttk.Frame(self.recovery_frame)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Input section
        input_frame = ttk.LabelFrame(main_frame, text="Input", padding=10)
        input_frame.pack(fill='x', pady=(0, 10))
        
        # Disk image selection
        ttk.Label(input_frame, text="Disk Image File:").grid(row=0, column=0, sticky='w', pady=2)
        self.recovery_image_var = tk.StringVar()
        entry_frame = ttk.Frame(input_frame)
        entry_frame.grid(row=1, column=0, sticky='ew', pady=2)
        entry_frame.columnconfigure(0, weight=1)
        
        ttk.Entry(entry_frame, textvariable=self.recovery_image_var, width=50).grid(row=0, column=0, sticky='ew', padx=(0, 5))
        ttk.Button(entry_frame, text="Browse", command=self.browse_recovery_image).grid(row=0, column=1)
        
        # Output directory selection
        ttk.Label(input_frame, text="Output Directory:").grid(row=2, column=0, sticky='w', pady=(10, 2))
        self.recovery_output_var = tk.StringVar(value="recovered_files")
        entry_frame2 = ttk.Frame(input_frame)
        entry_frame2.grid(row=3, column=0, sticky='ew', pady=2)
        entry_frame2.columnconfigure(0, weight=1)
        
        ttk.Entry(entry_frame2, textvariable=self.recovery_output_var, width=50).grid(row=0, column=0, sticky='ew', padx=(0, 5))
        ttk.Button(entry_frame2, text="Browse", command=self.browse_recovery_output).grid(row=0, column=1)
        
        input_frame.columnconfigure(0, weight=1)
        
        # Progress section
        progress_frame = ttk.LabelFrame(main_frame, text="Progress", padding=10)
        progress_frame.pack(fill='x', pady=(0, 10))
        
        self.recovery_progress = ttk.Progressbar(progress_frame, mode='determinate')
        self.recovery_progress.pack(fill='x', pady=2)
        
        self.recovery_status_var = tk.StringVar(value="Ready")
        ttk.Label(progress_frame, textvariable=self.recovery_status_var).pack(anchor='w', pady=2)
        
        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill='x', pady=(0, 10))
        
        self.recovery_start_btn = ttk.Button(button_frame, text="Start Recovery", command=self.start_recovery)
        self.recovery_start_btn.pack(side='left', padx=(0, 5))
        
        ttk.Button(button_frame, text="Open Output Folder", command=self.open_recovery_output).pack(side='left')
        
        # Log output
        log_frame = ttk.LabelFrame(main_frame, text="Log Output", padding=10)
        log_frame.pack(fill='both', expand=True)
        
        self.recovery_log = scrolledtext.ScrolledText(log_frame, height=15, wrap=tk.WORD)
        self.recovery_log.pack(fill='both', expand=True)
        
    def setup_steganography_tab(self):
        """Setup steganography tab"""
        # Create sub-notebook for steganography operations
        stego_notebook = ttk.Notebook(self.stego_frame)
        stego_notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Encode tab
        encode_frame = ttk.Frame(stego_notebook)
        stego_notebook.add(encode_frame, text="Encode Message")
        self.setup_encode_tab(encode_frame)
        
        # Decode tab
        decode_frame = ttk.Frame(stego_notebook)
        stego_notebook.add(decode_frame, text="Decode Message")
        self.setup_decode_tab(decode_frame)
        
        # Analyze tab
        analyze_frame = ttk.Frame(stego_notebook)
        stego_notebook.add(analyze_frame, text="Analyze Image")
        self.setup_analyze_tab(analyze_frame)
        
        # Test Image tab
        test_frame = ttk.Frame(stego_notebook)
        stego_notebook.add(test_frame, text="Create Test Image")
        self.setup_test_image_tab(test_frame)
        
    def setup_encode_tab(self, parent):
        """Setup message encoding tab"""
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Input section
        input_frame = ttk.LabelFrame(main_frame, text="Input", padding=10)
        input_frame.pack(fill='x', pady=(0, 10))
        
        # Cover image selection
        ttk.Label(input_frame, text="Cover Image:").grid(row=0, column=0, sticky='w', pady=2)
        self.encode_image_var = tk.StringVar()
        entry_frame = ttk.Frame(input_frame)
        entry_frame.grid(row=1, column=0, sticky='ew', pady=2)
        entry_frame.columnconfigure(0, weight=1)
        
        ttk.Entry(entry_frame, textvariable=self.encode_image_var, width=50).grid(row=0, column=0, sticky='ew', padx=(0, 5))
        ttk.Button(entry_frame, text="Browse", command=self.browse_encode_image).grid(row=0, column=1)
        
        # Message input
        ttk.Label(input_frame, text="Secret Message:").grid(row=2, column=0, sticky='w', pady=(10, 2))
        self.encode_message_text = scrolledtext.ScrolledText(input_frame, height=5, wrap=tk.WORD)
        self.encode_message_text.grid(row=3, column=0, sticky='ew', pady=2)
        
        # Output file selection
        ttk.Label(input_frame, text="Output File:").grid(row=4, column=0, sticky='w', pady=(10, 2))
        self.encode_output_var = tk.StringVar()
        entry_frame2 = ttk.Frame(input_frame)
        entry_frame2.grid(row=5, column=0, sticky='ew', pady=2)
        entry_frame2.columnconfigure(0, weight=1)
        
        ttk.Entry(entry_frame2, textvariable=self.encode_output_var, width=50).grid(row=0, column=0, sticky='ew', padx=(0, 5))
        ttk.Button(entry_frame2, text="Browse", command=self.browse_encode_output).grid(row=0, column=1)
        
        input_frame.columnconfigure(0, weight=1)
        
        # Info section
        info_frame = ttk.LabelFrame(main_frame, text="Image Information", padding=10)
        info_frame.pack(fill='x', pady=(0, 10))
        
        self.encode_info_var = tk.StringVar(value="Select an image to see capacity information")
        ttk.Label(info_frame, textvariable=self.encode_info_var, wraplength=600).pack(anchor='w')
        
        ttk.Button(info_frame, text="Check Capacity", command=self.check_encode_capacity).pack(anchor='w', pady=(5, 0))
        
        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Button(button_frame, text="Encode Message", command=self.encode_message).pack(side='left', padx=(0, 5))
        
        # Log output
        log_frame = ttk.LabelFrame(main_frame, text="Log Output", padding=10)
        log_frame.pack(fill='both', expand=True)
        
        self.encode_log = scrolledtext.ScrolledText(log_frame, height=10, wrap=tk.WORD)
        self.encode_log.pack(fill='both', expand=True)
        
    def setup_decode_tab(self, parent):
        """Setup message decoding tab"""
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Input section
        input_frame = ttk.LabelFrame(main_frame, text="Input", padding=10)
        input_frame.pack(fill='x', pady=(0, 10))
        
        # Stego image selection
        ttk.Label(input_frame, text="Stego Image:").grid(row=0, column=0, sticky='w', pady=2)
        self.decode_image_var = tk.StringVar()
        entry_frame = ttk.Frame(input_frame)
        entry_frame.grid(row=1, column=0, sticky='ew', pady=2)
        entry_frame.columnconfigure(0, weight=1)
        
        ttk.Entry(entry_frame, textvariable=self.decode_image_var, width=50).grid(row=0, column=0, sticky='ew', padx=(0, 5))
        ttk.Button(entry_frame, text="Browse", command=self.browse_decode_image).grid(row=0, column=1)
        
        input_frame.columnconfigure(0, weight=1)
        
        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Button(button_frame, text="Decode Message", command=self.decode_message).pack(side='left', padx=(0, 5))
        ttk.Button(button_frame, text="Save Message", command=self.save_decoded_message).pack(side='left')
        
        # Output section
        output_frame = ttk.LabelFrame(main_frame, text="Decoded Message", padding=10)
        output_frame.pack(fill='both', expand=True)
        
        self.decode_output = scrolledtext.ScrolledText(output_frame, height=10, wrap=tk.WORD)
        self.decode_output.pack(fill='both', expand=True)
        
        # Log output
        log_frame = ttk.LabelFrame(main_frame, text="Log Output", padding=10)
        log_frame.pack(fill='both', expand=True)
        
        self.decode_log = scrolledtext.ScrolledText(log_frame, height=8, wrap=tk.WORD)
        self.decode_log.pack(fill='both', expand=True)
        
    def setup_analyze_tab(self, parent):
        """Setup image analysis tab"""
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Input section
        input_frame = ttk.LabelFrame(main_frame, text="Input", padding=10)
        input_frame.pack(fill='x', pady=(0, 10))
        
        # Image selection
        ttk.Label(input_frame, text="Image to Analyze:").grid(row=0, column=0, sticky='w', pady=2)
        self.analyze_image_var = tk.StringVar()
        entry_frame = ttk.Frame(input_frame)
        entry_frame.grid(row=1, column=0, sticky='ew', pady=2)
        entry_frame.columnconfigure(0, weight=1)
        
        ttk.Entry(entry_frame, textvariable=self.analyze_image_var, width=50).grid(row=0, column=0, sticky='ew', padx=(0, 5))
        ttk.Button(entry_frame, text="Browse", command=self.browse_analyze_image).grid(row=0, column=1)
        
        input_frame.columnconfigure(0, weight=1)
        
        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Button(button_frame, text="Analyze Image", command=self.analyze_image).pack(side='left')
        
        # Analysis results
        results_frame = ttk.LabelFrame(main_frame, text="Analysis Results", padding=10)
        results_frame.pack(fill='both', expand=True)
        
        self.analyze_results = scrolledtext.ScrolledText(results_frame, height=15, wrap=tk.WORD)
        self.analyze_results.pack(fill='both', expand=True)
        
    def setup_test_image_tab(self, parent):
        """Setup test image creation tab"""
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Input section
        input_frame = ttk.LabelFrame(main_frame, text="Test Image Parameters", padding=10)
        input_frame.pack(fill='x', pady=(0, 10))
        
        # Filename
        ttk.Label(input_frame, text="Output Filename:").grid(row=0, column=0, sticky='w', pady=2)
        self.test_filename_var = tk.StringVar(value="test_image.png")
        entry_frame = ttk.Frame(input_frame)
        entry_frame.grid(row=1, column=0, sticky='ew', pady=2)
        entry_frame.columnconfigure(0, weight=1)
        
        ttk.Entry(entry_frame, textvariable=self.test_filename_var, width=40).grid(row=0, column=0, sticky='ew', padx=(0, 5))
        ttk.Button(entry_frame, text="Browse", command=self.browse_test_output).grid(row=0, column=1)
        
        # Dimensions
        dim_frame = ttk.Frame(input_frame)
        dim_frame.grid(row=2, column=0, sticky='w', pady=(10, 2))
        
        ttk.Label(dim_frame, text="Width:").grid(row=0, column=0, sticky='w', padx=(0, 5))
        self.test_width_var = tk.IntVar(value=800)
        width_spin = ttk.Spinbox(dim_frame, from_=100, to=2000, textvariable=self.test_width_var, width=10)
        width_spin.grid(row=0, column=1, padx=(0, 10))
        
        ttk.Label(dim_frame, text="Height:").grid(row=0, column=2, sticky='w', padx=(0, 5))
        self.test_height_var = tk.IntVar(value=600)
        height_spin = ttk.Spinbox(dim_frame, from_=100, to=2000, textvariable=self.test_height_var, width=10)
        height_spin.grid(row=0, column=3)
        
        input_frame.columnconfigure(0, weight=1)
        
        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Button(button_frame, text="Create Test Image", command=self.create_test_image).pack(side='left', padx=(0, 5))
        ttk.Button(button_frame, text="Open Output Folder", command=self.open_test_output_folder).pack(side='left')
        
        # Log output
        log_frame = ttk.LabelFrame(main_frame, text="Log Output", padding=10)
        log_frame.pack(fill='both', expand=True)
        
        self.test_log = scrolledtext.ScrolledText(log_frame, height=10, wrap=tk.WORD)
        self.test_log.pack(fill='both', expand=True)
        
    def setup_about_tab(self):
        """Setup about tab"""
        main_frame = ttk.Frame(self.about_frame)
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Title
        title_label = ttk.Label(main_frame, text="Digital Forensic Toolkit", font=('Arial', 16, 'bold'))
        title_label.pack(pady=(0, 10))
        
        # Description
        about_text = """
This Digital Forensic Toolkit provides two main forensic analysis capabilities:

1. FILE RECOVERY MODULE
   • Recovers deleted files from disk images using file signature analysis
   • Supports multiple file types: JPEG, PNG, PDF, ZIP, DOC, MP3, MP4, and more
   • Uses magic bytes detection to identify file boundaries
   • Extracts and saves recovered files with detailed statistics

2. STEGANOGRAPHY MODULE
   • Hide secret messages in images using LSB (Least Significant Bit) technique
   • Decode hidden messages from suspicious images
   • Analyze images for steganographic content
   • Calculate image capacity for message hiding
   • Create test images for experimentation

FEATURES:
   • User-friendly GUI interface
   • Real-time progress monitoring
   • Detailed logging and error reporting
   • Support for multiple image formats
   • Batch processing capabilities

USAGE:
   • Select the appropriate tab for your analysis needs
   • Follow the step-by-step interface prompts
   • Review log outputs for detailed information
   • Save results for further investigation

This tool is designed for educational and legitimate forensic investigation purposes.
        """
        
        about_label = ttk.Label(main_frame, text=about_text.strip(), justify='left', wraplength=600)
        about_label.pack(pady=10)
        
        # Version info
        version_frame = ttk.Frame(main_frame)
        version_frame.pack(pady=(20, 0))
        
        ttk.Label(version_frame, text="Version: 2.0 GUI", font=('Arial', 10, 'italic')).pack()
        ttk.Label(version_frame, text="Author: Forensic Analysis Team", font=('Arial', 10, 'italic')).pack()
        
    # File Recovery Methods
    def browse_recovery_image(self):
        """Browse for disk image file"""
        filename = filedialog.askopenfilename(
            title="Select Disk Image File",
            filetypes=[("All files", "*.*"), ("Image files", "*.img *.iso *.dd"), ("Binary files", "*.bin")]
        )
        if filename:
            self.recovery_image_var.set(filename)
            
    def browse_recovery_output(self):
        """Browse for output directory"""
        directory = filedialog.askdirectory(title="Select Output Directory")
        if directory:
            self.recovery_output_var.set(directory)
            
    def open_recovery_output(self):
        """Open the recovery output folder"""
        output_dir = self.recovery_output_var.get()
        if os.path.exists(output_dir):
            if sys.platform == "win32":
                os.startfile(output_dir)
            elif sys.platform == "darwin":
                os.system(f"open '{output_dir}'")
            else:
                os.system(f"xdg-open '{output_dir}'")
        else:
            messagebox.showwarning("Warning", "Output directory doesn't exist yet.")
            
    def log_recovery_message(self, message):
        """Log message to recovery tab"""
        self.recovery_log.insert(tk.END, message + "\n")
        self.recovery_log.see(tk.END)
        self.root.update_idletasks()
        
    def update_recovery_progress(self, value):
        """Update recovery progress bar"""
        self.recovery_progress['value'] = value
        self.recovery_status_var.set(f"Processing... {value:.1f}%")
        self.root.update_idletasks()
        
    def start_recovery(self):
        """Start file recovery process"""
        image_path = self.recovery_image_var.get().strip()
        output_dir = self.recovery_output_var.get().strip()
        
        if not image_path:
            messagebox.showerror("Error", "Please select a disk image file.")
            return
            
        if not os.path.exists(image_path):
            messagebox.showerror("Error", "Disk image file not found.")
            return
            
        if not output_dir:
            messagebox.showerror("Error", "Please specify an output directory.")
            return
            
        # Clear log
        self.recovery_log.delete(1.0, tk.END)
        self.recovery_progress['value'] = 0
        self.recovery_status_var.set("Starting recovery...")
        
        # Disable button during recovery
        self.recovery_start_btn.config(state='disabled')
        
        def recovery_thread():
            try:
                recovery_tool = FileRecoveryTool(
                    output_dir=output_dir,
                    progress_callback=self.update_recovery_progress,
                    log_callback=self.log_recovery_message
                )
                
                success = recovery_tool.recover_files(image_path)
                
                self.root.after(0, lambda: self.recovery_complete(success))
                
            except Exception as e:
                self.root.after(0, lambda: self.recovery_error(str(e)))
                
        # Start recovery in separate thread
        thread = threading.Thread(target=recovery_thread, daemon=True)
        thread.start()
        
    def recovery_complete(self, success):
        """Handle recovery completion"""
        self.recovery_start_btn.config(state='normal')
        self.recovery_progress['value'] = 100
        
        if success:
            self.recovery_status_var.set("Recovery completed successfully!")
            messagebox.showinfo("Success", "File recovery completed! Check the log for details.")
        else:
            self.recovery_status_var.set("Recovery failed or no files found.")
            messagebox.showwarning("Warning", "Recovery completed but no files were recovered.")
            
    def recovery_error(self, error_msg):
        """Handle recovery error"""
        self.recovery_start_btn.config(state='normal')
        self.recovery_status_var.set("Recovery failed with error.")
        self.log_recovery_message(f"[ERROR] {error_msg}")
        messagebox.showerror("Error", f"Recovery failed: {error_msg}")
        
    # Steganography Encode Methods
    def browse_encode_image(self):
        """Browse for cover image"""
        filename = filedialog.askopenfilename(
            title="Select Cover Image",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.gif *.bmp *.tiff"), ("All files", "*.*")]
        )
        if filename:
            self.encode_image_var.set(filename)
            self.check_encode_capacity()
            
    def browse_encode_output(self):
        """Browse for output stego image"""
        filename = filedialog.asksaveasfilename(
            title="Save Stego Image As",
            defaultextension=".png",
            filetypes=[("PNG files", "*.png"), ("JPEG files", "*.jpg"), ("All files", "*.*")]
        )
        if filename:
            self.encode_output_var.set(filename)
            
    def check_encode_capacity(self):
        """Check encoding capacity of selected image"""
        image_path = self.encode_image_var.get().strip()
        if not image_path or not os.path.exists(image_path):
            self.encode_info_var.set("Select a valid image to see capacity information")
            return
            
        try:
            stego_tool = SteganographyTool()
            capacity = stego_tool.calculate_capacity(image_path)
            
            image = Image.open(image_path)
            info_text = f"Image: {os.path.basename(image_path)}\n"
            info_text += f"Format: {image.format}, Mode: {image.mode}\n"
            info_text += f"Size: {image.size[0]} x {image.size[1]} pixels\n"
            info_text += f"Maximum message capacity: {capacity} characters"
            
            self.encode_info_var.set(info_text)
            
        except Exception as e:
            self.encode_info_var.set(f"Error reading image: {e}")
            
    def log_encode_message(self, message):
        """Log message to encode tab"""
        self.encode_log.insert(tk.END, message + "\n")
        self.encode_log.see(tk.END)
        self.root.update_idletasks()
        
    def encode_message(self):
        """Encode message into image"""
        image_path = self.encode_image_var.get().strip()
        message = self.encode_message_text.get(1.0, tk.END).strip()
        output_path = self.encode_output_var.get().strip()
        
        if not image_path or not os.path.exists(image_path):
            messagebox.showerror("Error", "Please select a valid cover image.")
            return
            
        if not message:
            messagebox.showerror("Error", "Please enter a message to encode.")
            return
            
        if not output_path:
            messagebox.showerror("Error", "Please specify an output file.")
            return
            
        # Clear log
        self.encode_log.delete(1.0, tk.END)
        
        try:
            stego_tool = SteganographyTool(log_callback=self.log_encode_message)
            success = stego_tool.encode_message(image_path, message, output_path)
            
            if success:
                messagebox.showinfo("Success", f"Message encoded successfully!\nOutput saved to: {output_path}")
            else:
                messagebox.showerror("Error", "Failed to encode message. Check the log for details.")
                
        except Exception as e:
            self.log_encode_message(f"[ERROR] {e}")
            messagebox.showerror("Error", f"Encoding failed: {e}")
            
    # Steganography Decode Methods
    def browse_decode_image(self):
        """Browse for stego image"""
        filename = filedialog.askopenfilename(
            title="Select Stego Image",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.gif *.bmp *.tiff"), ("All files", "*.*")]
        )
        if filename:
            self.decode_image_var.set(filename)
            
    def log_decode_message(self, message):
        """Log message to decode tab"""
        self.decode_log.insert(tk.END, message + "\n")
        self.decode_log.see(tk.END)
        self.root.update_idletasks()
        
    def decode_message(self):
        """Decode message from image"""
        image_path = self.decode_image_var.get().strip()
        
        if not image_path or not os.path.exists(image_path):
            messagebox.showerror("Error", "Please select a valid stego image.")
            return
            
        # Clear logs and output
        self.decode_log.delete(1.0, tk.END)
        self.decode_output.delete(1.0, tk.END)
        
        try:
            stego_tool = SteganographyTool(log_callback=self.log_decode_message)
            message = stego_tool.decode_message(image_path)
            
            if message:
                self.decode_output.insert(tk.END, message)
                messagebox.showinfo("Success", f"Hidden message found!\nMessage length: {len(message)} characters")
            else:
                self.decode_output.insert(tk.END, "No hidden message found.")
                messagebox.showwarning("Warning", "No hidden message detected in the image.")
                
        except Exception as e:
            self.log_decode_message(f"[ERROR] {e}")
            messagebox.showerror("Error", f"Decoding failed: {e}")
            
    def save_decoded_message(self):
        """Save decoded message to file"""
        message = self.decode_output.get(1.0, tk.END).strip()
        
        if not message or message == "No hidden message found.":
            messagebox.showwarning("Warning", "No message to save.")
            return
            
        filename = filedialog.asksaveasfilename(
            title="Save Decoded Message",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(message)
                messagebox.showinfo("Success", f"Message saved to: {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save message: {e}")
                
    # Steganography Analyze Methods
    def browse_analyze_image(self):
        """Browse for image to analyze"""
        filename = filedialog.askopenfilename(
            title="Select Image to Analyze",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.gif *.bmp *.tiff"), ("All files", "*.*")]
        )
        if filename:
            self.analyze_image_var.set(filename)
            
    def analyze_image(self):
        """Analyze image for steganographic content"""
        image_path = self.analyze_image_var.get().strip()
        
        if not image_path or not os.path.exists(image_path):
            messagebox.showerror("Error", "Please select a valid image file.")
            return
            
        # Clear results
        self.analyze_results.delete(1.0, tk.END)
        
        try:
            stego_tool = SteganographyTool()
            analysis = stego_tool.analyze_image(image_path)
            
            if analysis:
                results_text = "="*50 + "\n"
                results_text += "IMAGE ANALYSIS RESULTS\n"
                results_text += "="*50 + "\n\n"
                results_text += f"File Path: {analysis['path']}\n"
                results_text += f"Format: {analysis['format']}\n"
                results_text += f"Mode: {analysis['mode']}\n"
                results_text += f"Size: {analysis['size'][0]} x {analysis['size'][1]} pixels\n"
                results_text += f"Capacity: {analysis['capacity']} characters\n\n"
                
                if analysis['has_message']:
                    results_text += "HIDDEN MESSAGE DETECTED!\n"
                    results_text += "="*30 + "\n"
                    results_text += f"Message Length: {analysis['message_length']} characters\n"
                    results_text += f"Message Preview: {analysis['message'][:100]}{'...' if len(analysis['message']) > 100 else ''}\n\n"
                    results_text += "Full Message:\n"
                    results_text += "-"*30 + "\n"
                    results_text += analysis['message'] + "\n"
                    results_text += "-"*30 + "\n"
                else:
                    results_text += "No hidden message detected.\n"
                
                results_text += "\n" + "="*50
                
                self.analyze_results.insert(tk.END, results_text)
                
                if analysis['has_message']:
                    messagebox.showinfo("Analysis Complete", "Hidden message detected! See results for details.")
                else:
                    messagebox.showinfo("Analysis Complete", "No hidden message found in the image.")
                    
            else:
                self.analyze_results.insert(tk.END, "Analysis failed. Please check the image file.")
                messagebox.showerror("Error", "Failed to analyze image.")
                
        except Exception as e:
            self.analyze_results.insert(tk.END, f"Analysis error: {e}")
            messagebox.showerror("Error", f"Analysis failed: {e}")
            
    # Test Image Methods
    def browse_test_output(self):
        """Browse for test image output location"""
        filename = filedialog.asksaveasfilename(
            title="Save Test Image As",
            defaultextension=".png",
            filetypes=[("PNG files", "*.png"), ("JPEG files", "*.jpg"), ("All files", "*.*")]
        )
        if filename:
            self.test_filename_var.set(filename)
            
    def log_test_message(self, message):
        """Log message to test image tab"""
        self.test_log.insert(tk.END, message + "\n")
        self.test_log.see(tk.END)
        self.root.update_idletasks()
        
    def create_test_image(self):
        """Create a test image for steganography"""
        filename = self.test_filename_var.get().strip()
        width = self.test_width_var.get()
        height = self.test_height_var.get()
        
        if not filename:
            messagebox.showerror("Error", "Please specify an output filename.")
            return
            
        if width < 100 or height < 100:
            messagebox.showerror("Error", "Image dimensions must be at least 100x100 pixels.")
            return
            
        # Clear log
        self.test_log.delete(1.0, tk.END)
        
        try:
            self.log_test_message(f"[INFO] Creating test image: {filename}")
            self.log_test_message(f"[INFO] Dimensions: {width} x {height}")
            
            # Create a simple test image
            image = Image.new('RGB', (width, height), color='lightblue')
            draw = ImageDraw.Draw(image)
            
            # Add grid pattern
            grid_size = 50
            for i in range(0, width, grid_size):
                draw.line([(i, 0), (i, height)], fill='white', width=1)
            for i in range(0, height, grid_size):
                draw.line([(0, i), (width, i)], fill='white', width=1)
                
            # Add some colored rectangles
            for i in range(5):
                x1 = (width // 6) * i
                y1 = height // 4
                x2 = x1 + (width // 8)
                y2 = y1 + (height // 8)
                colors = ['red', 'green', 'blue', 'yellow', 'purple']
                draw.rectangle([x1, y1, x2, y2], fill=colors[i % len(colors)])
                
            # Add text
            try:
                font = ImageFont.load_default()
                text = "Test Image for Steganography"
                text_bbox = draw.textbbox((0, 0), text, font=font)
                text_width = text_bbox[2] - text_bbox[0]
                text_height = text_bbox[3] - text_bbox[1]
                text_x = (width - text_width) // 2
                text_y = height // 2
                draw.text((text_x, text_y), text, fill='black', font=font)
                
                # Add additional info
                info_text = f"Size: {width}x{height}"
                info_bbox = draw.textbbox((0, 0), info_text, font=font)
                info_width = info_bbox[2] - info_bbox[0]
                info_x = (width - info_width) // 2
                info_y = text_y + text_height + 10
                draw.text((info_x, info_y), info_text, fill='darkblue', font=font)
                
            except Exception as font_error:
                self.log_test_message(f"[WARNING] Font loading failed: {font_error}")
                draw.text((width//2 - 50, height//2), "Test Image", fill='black')
                
            # Save image
            image.save(filename)
            
            # Calculate capacity
            stego_tool = SteganographyTool()
            capacity = stego_tool.calculate_capacity(filename)
            
            self.log_test_message(f"[SUCCESS] Test image created successfully!")
            self.log_test_message(f"[INFO] File saved: {filename}")
            self.log_test_message(f"[INFO] File size: {os.path.getsize(filename)} bytes")
            self.log_test_message(f"[INFO] Message capacity: {capacity} characters")
            
            messagebox.showinfo("Success", f"Test image created successfully!\n\nFile: {filename}\nSize: {width}x{height}\nCapacity: {capacity} characters")
            
        except Exception as e:
            self.log_test_message(f"[ERROR] Failed to create test image: {e}")
            messagebox.showerror("Error", f"Failed to create test image: {e}")
            
    def open_test_output_folder(self):
        """Open folder containing test image"""
        filename = self.test_filename_var.get().strip()
        if filename and os.path.exists(filename):
            folder = os.path.dirname(os.path.abspath(filename))
            if sys.platform == "win32":
                os.startfile(folder)
            elif sys.platform == "darwin":
                os.system(f"open '{folder}'")
            else:
                os.system(f"xdg-open '{folder}'")
        else:
            messagebox.showwarning("Warning", "Test image file doesn't exist yet.")


def main():
    """Main function to run the GUI application"""
    try:
        root = tk.Tk()
        app = ForensicToolkitGUI(root)
        
        # Center the window on screen
        root.update_idletasks()
        width = root.winfo_width()
        height = root.winfo_height()
        x = (root.winfo_screenwidth() // 2) - (width // 2)
        y = (root.winfo_screenheight() // 2) - (height // 2)
        root.geometry(f"{width}x{height}+{x}+{y}")
        
        # Start the GUI event loop
        root.mainloop()
        
    except Exception as e:
        messagebox.showerror("Fatal Error", f"Application failed to start: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
