# Digital Forensic Toolkit - CLI Version

A comprehensive command-line toolkit for digital forensics education and practice, featuring file recovery and steganography capabilities.

---

## 📦 Overview

This toolkit provides two essential digital forensic modules:

1. **File Recovery Tool** – Recovers deleted files from disk images using file signature (magic byte) analysis.
2. **Steganography Tool** – Hides and extracts secret messages in images using the Least Significant Bit (LSB) technique.

Designed for educational use and practical forensic investigations, this tool supports various file types and integrates seamlessly into forensic workflows.

---

## 🛠️ Features

### 🔍 File Recovery Module
- Scans disk images for known file signatures (magic bytes)
- Supports recovery of over 20 common file types:
  - Images: JPEG, PNG, GIF, BMP, TIFF
  - Documents: PDF, DOC, DOCX, RTF
  - Archives: ZIP, RAR, TAR
  - Audio/Video: MP3, MP4, AVI, WAV, FLAC, OGG
  - Executables: EXE
  - Databases: SQLite
- Automatic file type detection and extension assignment
- Detailed recovery statistics
- Configurable output directory and chunk size

### 🖼️ Steganography Module
- Hide text messages inside images (LSB encoding)
- Extract hidden messages from stego-images
- Analyze images for potential steganographic content
- Automatic capacity calculation
- Delimiter-based message termination
- Support for PNG, JPG, BMP, and other common formats

---

## 🚀 Installation

### Prerequisites
- Python 3.6 or higher
- `Pillow` (PIL) for image processing

### Install Dependencies
```bash
pip install pillow
```

> 💡 No other external packages are required.

---

## 🧪 Quick Start

### Clone or download the script:
```bash
wget https://raw.githubusercontent.com/your-repo/digital-forensic-toolkit/main/forensic_toolkit.py
```

Make it executable:
```bash
chmod +x forensic_toolkit.py
```

---

## 🛠️ Usage Examples

### 1. File Recovery
Recover files from a disk image:
```bash
python forensic_toolkit.py recovery --image disk.img --output recovered_files/
```

Use custom chunk size (e.g., 512 KB):
```bash
python forensic_toolkit.py recovery --image disk.img --output recovered/ --chunk-size 524288
```

---

### 2. Steganography – Encode Message
Hide a secret message in an image:
```bash
python forensic_toolkit.py steganography encode \
  --cover photo.png \
  --message "Top secret message!" \
  --output stego_photo.png
```

---

### 3. Steganography – Decode Message
Extract a hidden message:
```bash
python forensic_toolkit.py steganography decode --image stego_photo.png
```
Output:
```
[SUCCESS] Decoded message:
----------------------------------------
Top secret message!
----------------------------------------
```

---

### 4. Steganography – Analyze Image
Check if an image contains hidden 
```bash
python forensic_toolkit.py steganography analyze --image suspicious.png
```

---

### 5. Create Test Image
Generate a test image for steganography experiments:
```bash
python forensic_toolkit.py create-test-image --filename test.png --width 1024 --height 768
```

---

## 📂 Output Structure

After file recovery, the output directory will contain:
```
recovered_files/
├── recovered_0000_jpeg_offset_000a2f3c.jpg
├── recovered_0001_png_offset_001b4c20.png
├── recovered_0002_pdf_offset_002d8e1a.pdf
└── ...
```

Each file is named with:
- Index
- File type
- Offset in the disk image (hex)
- Correct file extension

---

## 📊 Statistics

The recovery tool provides detailed statistics:
```
==================================================
RECOVERY STATISTICS
==================================================
Total files recovered: 15
Total size recovered: 24.78 MB

File types found:
  JPEG: 7 files
  PNG: 4 files
  PDF: 3 files
  ZIP: 1 files
==================================================
```

---

## ⚠️ Limitations & Notes

- **File Recovery**:
  - Works best on raw disk images (e.g., `.img`, `.dd`)
  - Fragmented files may not be fully recovered
  - Some file types use heuristic-based extraction (e.g., MP3)
  - Does not recover file names or directory structure

- **Steganography**:
  - LSB method is basic and detectable
  - JPEG compression may destroy hidden data
  - Use lossless formats (PNG) for reliable results
  - Message length limited by image size

---

## 📚 Educational Use

This toolkit is ideal for:
- Teaching digital forensics concepts
- Demonstrating file carving techniques
- Exploring steganography and data hiding
- Hands-on lab exercises in cybersecurity courses

---

## 🧑‍💻 Author

**Lokesh Acharya**  
Digital Forensics Enthusiast & Educator

---

## 📄 License

This project is open-source and available for educational and non-commercial use. Modify and share as needed.

> Note: Use responsibly and only on systems/data you have legal authorization to analyze.

---

## 🤝 Feedback & Contributions

Feel free to open issues or submit pull requests for improvements, bug fixes, or new features!

---

## 🎯 Future Enhancements (Planned)

- Add entropy analysis for steganography detection
- Support for more file signatures
- JSON output for automation
- GUI version using Tkinter or web interface
- Hash verification of recovered files

---

> ✅ **Always use forensic tools ethically and legally.**  
> This toolkit is for learning and authorized investigations only.
