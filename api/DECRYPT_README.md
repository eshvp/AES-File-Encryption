# 🔓 AES File Decryption Tool

Easy-to-use tool for decrypting files that were encrypted with the AES encryption system.

## 🚀 Quick Start

### Option 1: Double-click the batch file (Windows)
1. Double-click `decrypt.bat`
2. Follow the interactive prompts

### Option 2: Run Python script directly
```powershell
python decrypt_tool.py
```

### Option 3: Command line usage
```powershell
# Auto-decrypt (finds files automatically)
python decrypt_tool.py --auto --base-name "document" --password "yourpassword"

# Manual file specification
python decrypt_tool.py --encrypted "file.enc" --metadata "file.json" --password "yourpassword"
```

## 🔍 How It Works

The tool automatically:
1. **Detects encrypted files** in your directory (looks for `.enc` files)
2. **Finds matching metadata** (looks for corresponding `.json` files)
3. **Identifies encryption type** using hidden tags (AES-128/192/256)
4. **Prompts for password** securely
5. **Decrypts the file** and saves it with `_decrypted` suffix

## 📁 Interactive Mode Features

### 1. Auto-Detection
- Scans current directory for encrypted files
- Shows list of available files to decrypt
- Matches `.enc` files with their `.json` metadata

### 2. Directory Selection
- Choose specific directory to scan
- Useful when files are in different locations

### 3. Manual File Selection
- Specify exact paths to encrypted and metadata files
- Full control over file selection

## 🔐 Security Features

- **Password masking**: Password input is hidden for security
- **File validation**: Verifies files are compatible before decryption
- **Error handling**: Clear error messages for common issues

## 📊 What You'll See

```
🔓 AES File Decryption Tool - Interactive Mode
============================================================

Choose an option:
1. Auto-detect encrypted files in current directory
2. Auto-detect encrypted files in specific directory  
3. Manually specify file paths
4. Exit

Enter your choice (1-4): 1

📁 Found 2 encrypted file(s):
   1. document
   2. image

Select file to decrypt (1-2): 1

🔍 Processing: document
📁 Encrypted file: document_encrypted.enc
📋 Metadata file: document_metadata.json
🔍 Validating files...
✅ Files validated successfully
📊 Encryption type: AES-256
🏷️  Hidden tag: k913h923

🔑 Enter decryption password: [hidden]

🔄 Decrypting file...
✅ Decryption successful!
📁 Decrypted file saved: document_decrypted
📊 File size: 1,234 bytes

👀 Would you like to preview the content? (y/n): y

📖 Content preview (first 500 characters):
--------------------------------------------------
This is the original content of your document...
--------------------------------------------------
```

## ❌ Troubleshooting

### "File not found" errors
- Check file paths are correct
- Ensure both `.enc` and `.json` files exist
- Use quotes around paths with spaces

### "Decryption failed" errors
- **Wrong password**: Most common cause
- **Corrupted files**: Files may be damaged
- **Missing metadata**: `.json` file is required

### "Unknown encryption tag" errors
- File was encrypted with different system
- Metadata file is corrupted or incompatible

## 🛠️ Advanced Usage

### Command Line Arguments
- `--encrypted, -e`: Path to encrypted file
- `--metadata, -m`: Path to metadata file  
- `--password, -p`: Decryption password
- `--auto, -a`: Enable auto-detection mode
- `--base-name, -b`: Base filename for auto-detection
- `--directory, -d`: Directory to search in

### Examples
```powershell
# Decrypt specific files
python decrypt_tool.py -e "C:\files\doc.enc" -m "C:\files\doc.json" -p "mypass"

# Auto-decrypt in specific directory
python decrypt_tool.py --auto --base-name "report" --directory "C:\documents" --password "mypass"
```

## 📝 File Naming Convention

The tool expects files to follow this naming pattern:
- Encrypted file: `filename_encrypted.enc`
- Metadata file: `filename_metadata.json`
- Output file: `filename_decrypted`

## 🔒 Security Notes

- Never share your password or metadata files
- Keep encrypted files and metadata together
- Original files are not modified during decryption
- Decrypted files are saved with `_decrypted` suffix

---

**Need help?** The tool provides detailed error messages and suggestions for common issues.
