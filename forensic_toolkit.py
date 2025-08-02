#!/usr/bin/env python3
"""
Digital Forensic Toolkit - CLI Version
======================================
A comprehensive toolkit for digital forensics education and practice.

Modules:
1. File Recovery Tool - Recover deleted files using file signatures
2. Steganography Tool - Hide/extract messages in images using LSB technique

Author: Lokesh Acharya

"""

import os
import sys
import struct
import binascii
import argparse
from typing import List, Dict, Tuple, Optional
from PIL import Image
import io

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

    def __init__(self, output_dir: str = "recovered_files"):
        self.output_dir = output_dir
        self.recovered_files = []
        self.stats = {
            'total_files': 0,
            'file_types': {},
            'total_size': 0
        }

    def create_output_directory(self):
        """Create output directory for recovered files"""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            print(f"[INFO] Created output directory: {self.output_dir}")

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

        print(f"[INFO] Scanning disk image: {image_path}")
        print(f"[INFO] Image size: {file_size / (1024*1024):.2f} MB")
        print(f"[INFO] Chunk size: {chunk_size / 1024:.0f} KB")
        print("[INFO] Starting scan...")

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
                    if current_mb - processed_mb >= 10:  # Show progress every 10MB
                        progress = (offset / file_size) * 100
                        print(f"[PROGRESS] {progress:.1f}% - Processed {current_mb:.0f} MB")
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
            print(f"[ERROR] Error scanning disk image: {e}")
            return []

        print(f"[INFO] Scan complete. Found {len(recovered_files)} potential files")
        return recovered_files

    def save_recovered_files(self, recovered_files: List[Dict]):
        """Save recovered files to output directory"""
        self.create_output_directory()

        print(f"[INFO] Saving {len(recovered_files)} recovered files...")

        for i, file_info in enumerate(recovered_files):
            file_type = file_info['type']
            extension = self.get_file_extension(file_type)
            filename = f"recovered_{i:04d}_{file_type.lower()}_offset_{file_info['offset']:08x}{extension}"
            filepath = os.path.join(self.output_dir, filename)

            try:
                with open(filepath, 'wb') as f:
                    f.write(file_info['content'])
                print(f"[SAVED] {filename} ({file_info['size']} bytes)")
                self.stats['total_files'] += 1
            except Exception as e:
                print(f"[ERROR] Failed to save {filename}: {e}")

    def print_statistics(self):
        """Print recovery statistics"""
        print("\n" + "="*50)
        print("RECOVERY STATISTICS")
        print("="*50)
        print(f"Total files recovered: {self.stats['total_files']}")
        print(f"Total size recovered: {self.stats['total_size'] / (1024*1024):.2f} MB")
        print("\nFile types found:")

        for file_type, count in sorted(self.stats['file_types'].items()):
            print(f"  {file_type}: {count} files")

        print("="*50)

    def recover_files(self, image_path: str):
        """Main recovery function"""
        print(f"[INFO] Starting file recovery from: {image_path}")

        if not os.path.exists(image_path):
            print(f"[ERROR] File not found: {image_path}")
            return False

        print("[INFO] Scanning for file signatures...")
        recovered_files = self.scan_disk_image(image_path)

        if recovered_files:
            self.save_recovered_files(recovered_files)
            self.print_statistics()
            print(f"[SUCCESS] Recovery complete! Files saved to: {self.output_dir}")
            return True
        else:
            print("[WARNING] No recoverable files found")
            return False


class SteganographyTool:
    """
    Steganography Tool - Module 2
    Hide and extract text messages in images using LSB (Least Significant Bit) technique
    """

    def __init__(self):
        self.delimiter = "####END####"  # Delimiter to mark end of message

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
            print(f"[ERROR] Error calculating capacity: {e}")
            return 0

    def encode_message(self, image_path: str, message: str, output_path: str) -> bool:
        """Encode message into image using LSB technique"""
        try:
            print(f"[INFO] Encoding message into: {image_path}")
            print(f"[INFO] Message length: {len(message)} characters")

            # Open and prepare image
            image = Image.open(image_path)
            original_mode = image.mode
            image = image.convert('RGB')  # Ensure RGB mode

            # Check capacity
            capacity = self.calculate_capacity(image_path)
            if len(message) > capacity:
                print(f"[ERROR] Message too long for image. Max capacity: {capacity} characters, Message: {len(message)} characters")
                return False

            print(f"[INFO] Image capacity: {capacity} characters")

            # Add delimiter to message
            message_with_delimiter = message + self.delimiter
            binary_message = self.text_to_binary(message_with_delimiter)

            print(f"[INFO] Binary message length: {len(binary_message)} bits")

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

            print(f"[SUCCESS] Message encoded successfully in: {output_path}")
            print(f"[INFO] Used {bit_index} bits out of {len(binary_message)} total message bits")

            return True

        except Exception as e:
            print(f"[ERROR] Error encoding message: {e}")
            return False

    def decode_message(self, image_path: str, verbose: bool = True) -> Optional[str]:
        """Decode message from image using LSB technique"""
        try:
            if verbose:
                print(f"[INFO] Decoding message from: {image_path}")

            # Open image
            image = Image.open(image_path)
            image = image.convert('RGB')

            # Get image data
            pixels = list(image.getdata())

            if verbose:
                print(f"[INFO] Image size: {image.size}")
                print(f"[INFO] Total pixels: {len(pixels)}")

            # Extract LSBs
            binary_message = ''
            for pixel in pixels:
                r, g, b = pixel
                binary_message += str(r & 1)
                binary_message += str(g & 1)
                binary_message += str(b & 1)

            if verbose:
                print(f"[INFO] Extracted {len(binary_message)} bits")

            # Convert binary to text
            full_message = self.binary_to_text(binary_message)

            # Find delimiter
            if self.delimiter in full_message:
                message = full_message.split(self.delimiter)[0]
                if verbose:
                    print(f"[SUCCESS] Hidden message found ({len(message)} characters)")
                return message
            else:
                if verbose:
                    print("[WARNING] No hidden message found or delimiter not detected")
                return None

        except Exception as e:
            if verbose:
                print(f"[ERROR] Error decoding message: {e}")
            return None

    def analyze_image(self, image_path: str):
        """Analyze image for steganographic properties"""
        try:
            image = Image.open(image_path)

            print(f"[INFO] Image Analysis: {image_path}")
            print(f"[INFO] Format: {image.format}")
            print(f"[INFO] Mode: {image.mode}")
            print(f"[INFO] Size: {image.size}")
            print(f"[INFO] Capacity: {self.calculate_capacity(image_path)} characters")

            # Try to decode message
            message = self.decode_message(image_path, verbose=False)
            if message:
                print(f"[INFO] Hidden message detected: {len(message)} characters")
                print(f"[INFO] Message preview: {message[:50]}{'...' if len(message) > 50 else ''}")
            else:
                print("[INFO] No hidden message detected")

        except Exception as e:
            print(f"[ERROR] Error analyzing image: {e}")


def create_test_image(filename: str, width: int = 800, height: int = 600):
    """Create a test image for steganography testing"""
    try:
        from PIL import Image, ImageDraw, ImageFont

        # Create a simple test image
        image = Image.new('RGB', (width, height), color='lightblue')
        draw = ImageDraw.Draw(image)

        # Add some patterns
        for i in range(0, width, 50):
            draw.line([(i, 0), (i, height)], fill='white', width=1)
        for i in range(0, height, 50):
            draw.line([(0, i), (width, i)], fill='white', width=1)

        # Add text
        try:
            font = ImageFont.load_default()
            text = "Test Image for Steganography"
            draw.text((width//2 - 100, height//2), text, fill='black', font=font)
        except:
            draw.text((width//2 - 100, height//2), "Test Image", fill='black')

        image.save(filename)
        print(f"[INFO] Test image created: {filename}")

    except Exception as e:
        print(f"[ERROR] Error creating test image: {e}")


def main():
    """Main function - CLI interface"""
    parser = argparse.ArgumentParser(
        description="Digital Forensic Toolkit - CLI Version",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # File Recovery
  python forensic_toolkit.py recovery --image disk.img --output recovered/

  # Steganography - Encode
  python forensic_toolkit.py steganography encode --cover image.png --message "Secret message" --output stego.png

  # Steganography - Decode
  python forensic_toolkit.py steganography decode --image stego.png

  # Steganography - Analyze
  python forensic_toolkit.py steganography analyze --image suspicious.png

  # Create test image
  python forensic_toolkit.py create-test-image --filename test.png --width 1024 --height 768
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # File Recovery subcommand
    recovery_parser = subparsers.add_parser('recovery', help='File recovery operations')
    recovery_parser.add_argument('--image', required=True, help='Disk image file to scan')
    recovery_parser.add_argument('--output', default='recovered_files', help='Output directory for recovered files')
    recovery_parser.add_argument('--chunk-size', type=int, default=1024*1024, help='Chunk size for scanning (bytes)')

    # Steganography subcommand
    stego_parser = subparsers.add_parser('steganography', help='Steganography operations')
    stego_subparsers = stego_parser.add_subparsers(dest='stego_action', help='Steganography actions')

    # Encode subcommand
    encode_parser = stego_subparsers.add_parser('encode', help='Encode message in image')
    encode_parser.add_argument('--cover', required=True, help='Cover image file')
    encode_parser.add_argument('--message', required=True, help='Message to encode')
    encode_parser.add_argument('--output', required=True, help='Output stego image file')

    # Decode subcommand
    decode_parser = stego_subparsers.add_parser('decode', help='Decode message from image')
    decode_parser.add_argument('--image', required=True, help='Stego image file')

    # Analyze subcommand
    analyze_parser = stego_subparsers.add_parser('analyze', help='Analyze image for hidden messages')
    analyze_parser.add_argument('--image', required=True, help='Image file to analyze')

    # Test image creation
    test_parser = subparsers.add_parser('create-test-image', help='Create test image for steganography')
    test_parser.add_argument('--filename', default='test_image.png', help='Output filename')
    test_parser.add_argument('--width', type=int, default=800, help='Image width')
    test_parser.add_argument('--height', type=int, default=600, help='Image height')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # File Recovery
    if args.command == 'recovery':
        print("="*60)
        print("DIGITAL FORENSIC TOOLKIT - FILE RECOVERY")
        print("="*60)

        recovery_tool = FileRecoveryTool(args.output)
        success = recovery_tool.recover_files(args.image)

        if success:
            print("\n[SUCCESS] File recovery completed successfully!")
        else:
            print("\n[FAILED] File recovery failed or no files found.")
            sys.exit(1)

    # Steganography
    elif args.command == 'steganography':
        print("="*60)
        print("DIGITAL FORENSIC TOOLKIT - STEGANOGRAPHY")
        print("="*60)

        stego_tool = SteganographyTool()

        if args.stego_action == 'encode':
            success = stego_tool.encode_message(args.cover, args.message, args.output)
            if success:
                print("\n[SUCCESS] Message encoding completed successfully!")
            else:
                print("\n[FAILED] Message encoding failed.")
                sys.exit(1)

        elif args.stego_action == 'decode':
            message = stego_tool.decode_message(args.image)
            if message:
                print(f"\n[SUCCESS] Decoded message:")
                print("-" * 40)
                print(message)
                print("-" * 40)
            else:
                print("\n[FAILED] No hidden message found.")
                sys.exit(1)

        elif args.stego_action == 'analyze':
            stego_tool.analyze_image(args.image)

        else:
            stego_parser.print_help()

    # Create test image
    elif args.command == 'create-test-image':
        print("="*60)
        print("CREATING TEST IMAGE")
        print("="*60)

        create_test_image(args.filename, args.width, args.height)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
