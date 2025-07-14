# 🧪 Test Directory

This directory contains the test suite and sample data for the AES File Encryption System.

## Files

- **`test_suite.py`** - Comprehensive test suite with metrics and validation
- **`sample_data.txt`** - Sample file for testing encryption/decryption

## Running Tests

```powershell
# Run the complete test suite
python test\test_suite.py
```

## Test Coverage

The test suite validates:

✅ **RSA Key Management**
- Key pair generation (2048, 3072, 4096 bits)
- Key saving and loading
- RSA encryption/decryption functionality

✅ **Hybrid RSA+AES Encryption**
- File encryption with RSA key protection
- Decryption with private key
- Content integrity verification
- Performance metrics

✅ **Password-Based Encryption**
- Traditional AES encryption with PBKDF2
- Password-based decryption
- Content integrity verification

✅ **Smart Auto-Detection**
- Automatic encryption method detection
- Hybrid file auto-decryption
- Password file auto-decryption

✅ **AES Encryption Types**
- AES-128 encryption/decryption
- AES-192 encryption/decryption  
- AES-256 encryption/decryption

## Test Metrics

The test suite provides:
- Pass/fail counts
- Performance timing
- File size analysis
- Success rate percentage
- Detailed error reporting

All tests use temporary directories and clean up automatically.
