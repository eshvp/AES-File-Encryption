# AES File Encryption System

A secure file encryption system using AES encryption with multiple key sizes (128, 192, 256-bit) and hidden metadata tags for enhanced security.

## Features

- **File Upload & Management**: Upload files with path cleaning (handles quotes and parentheses)
- **Multiple AES Encryption Levels**: Choose between AES-128, AES-192, or AES-256
- **Hidden Metadata Tags**: Encryption type hidden in file metadata for obfuscation
- **Secure Key Derivation**: PBKDF2 with SHA-256 (100,000 iterations)
- **File Listing**: Separate views for uploaded and encrypted files
- **File Deletion**: Safe file removal with confirmation
- **Clean Filenames**: No encryption type visible in filenames

## Directory Structure

```
AES-File-Encryption/
├── Upload/
│   └── upload.py          # Main application with menu interface
├── Encryption/
│   ├── AES.py            # AES encryption implementation
│   └── AESDecrypt.py     # AES decryption implementation
├── uploaded_files/        # Uploaded files (excluded from git)
├── encrypted_files/       # Encrypted files (excluded from git)
├── decrypted_files/       # Decrypted files (excluded from git)
└── .gitignore
```

## Usage

### Running the Application

```bash
cd Upload
python upload.py
```

### Menu Options

1. **Upload File** - Upload files with automatic path cleaning
2. **List Uploaded Files** - View unencrypted files with status
3. **List Encrypted Files** - View encrypted files
4. **Encrypt Files** - Encrypt uploaded files with AES
5. **Decrypt File** - Decrypt encrypted files
6. **Delete File** - Remove files from upload directory
7. **Exit** - Close the application

### Encryption Process

1. Select files to encrypt (individual or all)
2. Choose AES encryption strength:
   - AES-128: Fast, good security
   - AES-192: Balanced security and performance
   - AES-256: Maximum security, slower
3. Enter and confirm password (minimum 8 characters)
4. Files are encrypted and originals are securely deleted

### Hidden Tags

The system uses hidden metadata tags to identify encryption types:
- AES-128: `(h1k789)`
- AES-192: `(GP94GF)`
- AES-256: `(k913h923)`

These tags are embedded in the encrypted file header for automatic detection during decryption.

## Security Features

- **PBKDF2 Key Derivation**: 100,000 iterations with SHA-256
- **Random Salt & IV**: Unique 16-byte salt and IV for each encryption
- **PKCS7 Padding**: Proper block alignment for AES
- **CBC Mode**: Secure block chaining
- **Password Confirmation**: Prevents typos during encryption
- **Original File Deletion**: Automatic cleanup after encryption

## Requirements

```bash
pip install cryptography
```

## File Format

Encrypted files use the following structure:
```
[Hidden Tag][16-byte Salt][16-byte IV][Encrypted Data]
```

## Example

```bash
# Upload a file
Enter the file path to upload: "C:\Documents\secret.txt"

# Encrypt with AES-256
Select AES encryption strength: 3
Enter encryption password: ********
✓ secret.txt → secret.txt.encrypted (original deleted)

# Decrypt the file
Enter decryption password: ********
✓ secret.txt.encrypted → secret.txt (AES-256)
```

## License

This project is for educational and personal use.
