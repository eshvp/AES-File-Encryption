# 🔒 AES File Encryption System

A comprehensive, secure file encryption and decryption system using Advanced Encryption Standard (AES) with multiple key sizes and user-friendly interfaces.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.7+-green.svg)
![Security](https://img.shields.io/badge/security-AES%20256-red.svg)

## 🌟 Features

- **Multi-Level AES Encryption**: Support for AES-128, AES-192, and AES-256
- **Secure Key Derivation**: PBKDF2 with SHA-256 for password-based encryption
- **Hidden Metadata System**: Secure tag-based encryption type identification
- **User-Friendly Interface**: Interactive CLI and batch file execution
- **Auto-Detection**: Automatically finds and pairs encrypted files with metadata
- **Cross-Platform**: Works on Windows, macOS, and Linux
- **API-Ready**: Modular design for easy integration into other projects

## 📁 Project Structure

```
AES-File-Encryption/
├── 📂 Encryption/           # Core encryption modules
│   ├── aesEncryption.py    # Main AES encryption class
│   └── RSA.py             # RSA encryption (placeholder)
├── 📂 api/                 # API modules
│   └── decryptAPI.py      # Decryption API and utilities
├── 📂 recipient/           # End-user decryption tools
│   ├── decrypt_tool.py    # Interactive decryption tool
│   ├── decrypt.bat        # Windows batch launcher
│   └── DECRYPT_README.md  # User guide for decryption
├── 📂 server/             # Server components (future)
├── 📂 test/               # Test files and examples
└── README.md              # This file
```

## 🚀 Quick Start

### Prerequisites

- Python 3.7 or higher
- `cryptography` library

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/eshvp/AES-File-Encryption.git
   cd AES-File-Encryption
   ```

2. **Install dependencies:**
   ```bash
   pip install cryptography
   ```

3. **For virtual environment (recommended):**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   pip install cryptography
   ```

## 🔐 Encryption Usage

### Using the AES Encryption Class

```python
from Encryption.aesEncryption import AESEncryption

# Create encryptor instance
encryptor = AESEncryption()

# Encrypt a file with AES-256
encrypted_file, metadata_file = encryptor.encrypt_file(
    input_file="document.txt",
    password="your_secure_password",
    encryption_type="AES-256"
)

print(f"Encrypted: {encrypted_file}")
print(f"Metadata: {metadata_file}")
```

### Supported Encryption Types

| Type    | Key Size | Security Level | Use Case |
|---------|----------|----------------|----------|
| AES-128 | 128-bit  | High          | Fast encryption, standard security |
| AES-192 | 192-bit  | Very High     | Enhanced security |
| AES-256 | 256-bit  | Maximum       | Maximum security, government grade |

## 🔓 Decryption Usage

### Interactive Mode (Recommended)

**Windows:**
```cmd
# Double-click decrypt.bat or run:
cd recipient
decrypt.bat
```

**Cross-Platform:**
```bash
cd recipient
python decrypt_tool.py
```

### Command Line Mode

```bash
# Auto-detect files by base name
python decrypt_tool.py --auto --base-name "document" --password "your_password"

# Manual file specification
python decrypt_tool.py --encrypted file.enc --metadata file.json --password "your_password"

# With custom directory
python decrypt_tool.py --auto --base-name "document" --directory "/path/to/files" --password "your_password"
```

### API Usage

```python
from api.decryptAPI import AESDecryptionAPI

# Create decryptor instance
decryptor = AESDecryptionAPI()

# Decrypt a file
decrypted_file = decryptor.decrypt_file(
    encrypted_file="document_encrypted.enc",
    metadata_file="document_metadata.json",
    password="your_secure_password"
)

print(f"Decrypted: {decrypted_file}")
```

## 🛡️ Security Features

### Encryption Details
- **Algorithm**: AES (Advanced Encryption Standard)
- **Mode**: CBC (Cipher Block Chaining)
- **Padding**: PKCS7
- **Key Derivation**: PBKDF2 with SHA-256
- **Salt**: Cryptographically secure random 32-byte salt
- **IV**: Cryptographically secure random 16-byte initialization vector

### Metadata Protection
- Hidden encryption tags prevent algorithm fingerprinting
- Metadata stored separately from encrypted data
- Base64 encoding for safe storage and transmission

### Security Best Practices
- ✅ Strong password-based key derivation (PBKDF2)
- ✅ Random salt generation for each encryption
- ✅ Random IV generation for each encryption
- ✅ Secure random number generation
- ✅ Memory-safe cryptographic operations

## 📋 File Format

### Encrypted File (.enc)
- Contains the encrypted binary data
- Uses AES encryption with CBC mode
- Includes random IV prepended to data

### Metadata File (.json)
```json
{
    "original_filename": "document.txt",
    "original_size": 1024,
    "encryption_type": "AES-256",
    "tag": "k913h923",
    "salt": "base64_encoded_salt",
    "created_at": "2025-07-13T10:30:00"
}
```

## 🔧 Advanced Usage

### Batch Processing
```python
from Encryption.aesEncryption import AESEncryption

encryptor = AESEncryption()
files_to_encrypt = ["doc1.txt", "doc2.pdf", "doc3.docx"]

for file_path in files_to_encrypt:
    encrypted, metadata = encryptor.encrypt_file(
        file_path, 
        "batch_password", 
        "AES-256"
    )
    print(f"✅ Encrypted: {file_path} → {encrypted}")
```

### File Validation
```python
from api.decryptAPI import validate_encrypted_files

# Validate file integrity
validation = validate_encrypted_files("file.enc", "file.json")
if validation['valid']:
    print("✅ Files are valid")
else:
    print("❌ Validation errors:", validation['errors'])
```

## 🎯 Use Cases

- **Personal File Security**: Encrypt sensitive documents, photos, and files
- **Business Data Protection**: Secure confidential business documents
- **Cloud Storage Security**: Encrypt files before uploading to cloud services
- **Data Archival**: Long-term secure storage of important data
- **Secure File Sharing**: Safe transmission of sensitive files
- **Compliance**: Meet data protection requirements (GDPR, HIPAA, etc.)

## 🚨 Error Handling

The system provides comprehensive error handling:

- **File Not Found**: Clear messages for missing files
- **Invalid Password**: Secure password verification
- **Corrupted Data**: Integrity checking and validation
- **Permission Errors**: File access permission guidance
- **Format Errors**: Metadata and file format validation

## 🛠️ Development

### Contributing
1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit changes: `git commit -am 'Add feature'`
4. Push to branch: `git push origin feature-name`
5. Submit a Pull Request

### Testing
```bash
# Run basic encryption/decryption test
python -c "
from Encryption.aesEncryption import AESEncryption
from api.decryptAPI import AESDecryptionAPI

# Test encryption
enc = AESEncryption()
enc_file, meta_file = enc.encrypt_file('test.txt', 'test123', 'AES-256')

# Test decryption
dec = AESDecryptionAPI()
dec_file = dec.decrypt_file(enc_file, meta_file, 'test123')
print('✅ Test passed!')
"
```

## 📚 API Reference

### AESEncryption Class

#### Methods
- `encrypt_file(input_file, password, encryption_type)`: Encrypt a file
- `encrypt_data(data, password, encryption_type)`: Encrypt raw data
- `derive_key(password, salt, key_size)`: Derive encryption key from password

### AESDecryptionAPI Class

#### Methods
- `decrypt_file(encrypted_file, metadata_file, password)`: Decrypt a file
- `decrypt_data(encrypted_data, password, salt, encryption_type)`: Decrypt raw data
- `auto_decrypt(base_name, password, directory)`: Auto-detect and decrypt

#### Utility Functions
- `validate_encrypted_files(enc_file, meta_file)`: Validate file pair
- `get_encryption_info(metadata_file)`: Extract encryption information

## ⚠️ Important Notes

1. **Password Security**: Use strong, unique passwords for encryption
2. **Backup Metadata**: Always keep metadata files safe - they're required for decryption
3. **File Overwrites**: The system will not overwrite existing files without confirmation
4. **Memory Security**: Passwords are handled securely in memory
5. **Platform Compatibility**: Encrypted files work across different operating systems

## 🐛 Troubleshooting

### Common Issues

**"ModuleNotFoundError: No module named 'cryptography'"**
```bash
pip install cryptography
```

**"No module named 'decryptAPI'"**
- Ensure you're running from the correct directory
- Check that the `api` folder exists and contains `decryptAPI.py`

**"Invalid password or corrupted file"**
- Verify the password is correct
- Ensure both .enc and .json files are present and not corrupted
- Check file permissions

**"Permission denied" errors**
- Run with appropriate permissions
- Check file/folder access rights
- Ensure files are not in use by other applications

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **cryptography library**: For providing robust cryptographic primitives
- **Python community**: For excellent documentation and support
- **Security researchers**: For AES implementation best practices

## 📞 Support

For questions, issues, or contributions:
- 📧 Create an issue on GitHub
- 💬 Join discussions in the repository
- 📖 Check the documentation in `/recipient/DECRYPT_README.md`

---

**⚡ Made with ❤️ for secure file encryption**

*Remember: Your security is only as strong as your weakest password. Choose wisely! 🔐*
