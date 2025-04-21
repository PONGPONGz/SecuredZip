# Secure Zip - Text Compression with Encryption

A Python application that compresses text files and encrypts them with AES-256 encryption for secure storage and transmission.

## Features

- Text file compression using zlib algorithm
- Strong encryption using AES-256 in GCM mode
- Password-based encryption with PBKDF2 key derivation
- Command-line interface for automation
- Graphical user interface for ease of use
- Cross-platform compatibility (Windows, macOS, Linux)

## Requirements

- Python 3.7 or higher
- Required Python packages:
  - cryptography
  - zlib-wrapper (for compression)
  - tkinter (for GUI, usually included with Python)

## Installation

1. Clone or download this repository
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### GUI Interface

To use the graphical interface:

```bash
python secure_zip_gui.py
```

The GUI provides options to:
- Choose between compression/encryption and decompression/decryption
- Select input and output files
- Enter and confirm passwords
- Process files with a single click

### Command Line Interface

For command-line usage:

```bash
python secure_zip.py compress <input_file> [-o <output_file>] [-p <password>]
python secure_zip.py decompress <input_file> [-o <output_file>] [-p <password>]
```

If the password is not provided via the command line, you will be prompted to enter it securely.

Examples:
```bash
# Compress and encrypt a file
python secure_zip.py compress document.txt

# Compress with specified output
python secure_zip.py compress document.txt -o secret.seczip

# Decrypt and decompress a file
python secure_zip.py decompress document.txt.seczip

# With password provided (not recommended for security reasons)
python secure_zip.py compress document.txt -p mypassword
```

## File Format

The secure zip format (.seczip) contains:
- 16-byte salt for key derivation
- 12-byte initialization vector (IV) for AES-GCM
- 16-byte authentication tag for data integrity verification
- Encrypted compressed data

## Security Notes

- The application uses PBKDF2 with 100,000 iterations to derive the encryption key
- AES-256 in GCM mode provides both confidentiality and authenticity
- Passwords are never stored in the application or in the encrypted files

## License

This project is released under the MIT License.

## Contributing

Contributions, bug reports, and feature requests are welcome!. 