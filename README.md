# 🔐 Hybrid Encryption System

A comprehensive file encryption system combining **AES symmetric encryption** and **RSA asymmetric encryption** for secure file sharing. Features a modular architecture with a central control panel for coordinating all encryption operations.

## 🚀 Features

### 🔒 **Hybrid Encryption**
- **AES-256-CBC** for fast file encryption
- **RSA-OAEP-SHA256** for secure key exchange
- **Complete sender/receiver workflow** for secure file sharing

### 📁 **File Management**
- Upload and organize files with automatic path cleaning
- Support for any file type and size
- Clean directory structure with automatic organization

### 🔑 **RSA Key Management**
- Generate RSA key pairs (2048/3072/4096-bit)
- Recipient management with public key validation
- Secure private key storage

### 🛡️ **Security Features**
- **Random AES key generation** (32 bytes for AES-256)
- **PBKDF2 key derivation** with 100,000 iterations
- **Random IV per file** for maximum security
- **Hidden metadata tags** for encryption type detection
- **Comprehensive package validation**

## 🏗️ Architecture

### **Modular Design**
```
🔐 Control Panel (Central Hub)
├── 📁 File Manager (upload.py)
├── 🔒 AES Encryption (AES.py)
├── 🔓 AES Decryption (AESDecrypt.py)
└── 🔑 RSA & Hybrid (RSA.py)
```

### **Directory Structure**
```
Encrypted-Files/
├── Control-Center/
│   └── controlPanel.py    # 🎯 Main control hub
├── Upload/
│   └── upload.py         # 📁 File management
├── Encryption/
│   ├── AES.py           # 🔒 AES encryption
│   ├── AESDecrypt.py    # 🔓 AES decryption
│   └── RSA.py           # 🔑 RSA & hybrid operations
├── uploaded_files/       # 📂 Source files
├── encrypted_files/      # 🔒 AES encrypted files
├── encrypted_packages/   # 📦 Hybrid encryption packages
├── decrypted_files/      # 🔓 Decrypted files
├── rsa_keys/            # 🔑 RSA key pairs
└── recipients/          # 👥 Recipient public keys
```

## 🎯 Quick Start

### **1. Launch Control Panel**
```bash
cd Control-Center
python controlPanel.py
```

### **2. Basic Workflow**
1. **Upload files** (Option 1: File Manager)
2. **Generate RSA keys** (Option 4: RSA Menu)
3. **Add recipients** (Option 4: RSA Menu)
4. **Encrypt for recipient** (Option 5: Quick Hybrid)
5. **Send package** to recipient
6. **Recipient decrypts** (Option 6: Decrypt Package)

## 🔄 Usage Modes

### **🎛️ Control Panel Mode (Recommended)**
```bash
python Control-Center/controlPanel.py
```
- **Unified interface** for all operations
- **Quick access** to common tasks
- **System status** and diagnostics

### **📦 Individual Module Mode**
```bash
# File management
python Upload/upload.py

# AES encryption
python Encryption/AES.py

# AES decryption
python Encryption/AESDecrypt.py

# RSA & hybrid operations
python Encryption/RSA.py
```

## 🔒 Hybrid Encryption Workflow

### **📤 Sender Side**
1. **Generate random AES-256 key** (32 bytes)
2. **Encrypt file** with AES-256-CBC
3. **Encrypt AES key** with recipient's RSA public key
4. **Package everything** together:
   ```
   📦 Package/
   ├── original_file.txt.encrypted  # AES-encrypted file
   ├── encrypted_aes_key.bin        # RSA-encrypted AES key
   └── metadata.json                # Encryption details
   ```

### **📥 Receiver Side**
1. **Decrypt AES key** using RSA private key
2. **Decrypt file** using recovered AES key
3. **Restore original file**

## 🛡️ Security Specifications

### **AES Encryption**
- **Algorithm**: AES-256-CBC
- **Key Size**: 256 bits (32 bytes)
- **IV**: Random 16 bytes per file
- **Padding**: PKCS7
- **Key Derivation**: PBKDF2-SHA256 (100,000 iterations)

### **RSA Encryption**
- **Key Sizes**: 2048, 3072, or 4096 bits
- **Padding**: OAEP with SHA-256
- **Purpose**: AES key encryption only

### **Hidden Tags**
- **AES-128**: `(h1k789)`
- **AES-192**: `(GP94GF)`
- **AES-256**: `(k913h923)`

## 📋 Menu Options

### **🎯 Control Panel**
```
📁 FILE MANAGEMENT:
  1. File Manager (Upload/List/Delete)

🔒 ENCRYPTION:
  2. AES Encryption Menu
  3. AES Decryption Menu
  4. RSA & Hybrid Encryption Menu

🔒🔑 QUICK HYBRID OPERATIONS:
  5. Encrypt File for Recipient
  6. Decrypt Package
  7. List Encrypted Packages

ℹ️ SYSTEM:
  8. System Status
  9. Help
  10. Exit
```

## 💻 Requirements

```bash
pip install cryptography
```

## 🔐 Example: Complete Workflow

### **Setup Phase**
```bash
# 1. Generate your RSA key pair
RSA Menu → Generate Key Pair → "alice_keys" (2048-bit)

# 2. Share public key with recipient
# Send: rsa_keys/alice_keys_public.pem

# 3. Add recipient's public key
RSA Menu → Add Recipient → "Bob" → bob_public.pem
```

### **Encryption Phase**
```bash
# 1. Upload file
File Manager → Upload → "secret-document.pdf"

# 2. Encrypt for recipient
Quick Hybrid → Select file → Select "Bob" → ✓ Package created
```

### **Package Contents**
```
encrypted_packages/secret-document_Bob_20250712_143022/
├── secret-document.pdf.encrypted  # AES-256 encrypted file
├── encrypted_aes_key.bin          # RSA encrypted AES key
└── metadata.json                  # Encryption metadata
```

### **Decryption Phase** (Recipient)
```bash
# Recipient receives package and decrypts
Decrypt Package → Select package → Select private key → Enter password
✓ File decrypted: decrypted_files/secret-document.pdf
```

## 🎯 Benefits

- **🔒 Security**: Military-grade hybrid encryption
- **🏗️ Modularity**: Each component is independent
- **🎛️ Flexibility**: Use control panel or individual modules
- **📦 Portability**: Self-contained encryption packages
- **🔄 Workflow**: Complete sender-to-receiver process
- **🛡️ Future-proof**: Easy to extend and maintain

## 📄 License

This project is for educational and personal use.
