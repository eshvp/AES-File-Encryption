"""
🧪 AES File Encryption System - Comprehensive Test Suite
=========================================================

This test suite validates all core functionality of the encryption system:
- RSA key generation and management
- Hybrid RSA+AES encryption/decryption  
- Password-based AES encryption/decryption
- Auto-detection capabilities
- File integrity verification
- Performance metrics

Run with: python test_suite.py
"""

import sys
import os
import time
import tempfile
import shutil
from pathlib import Path

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Encryption.RSA import RSAKeyManager, HybridEncryption
from Encryption.aesEncryption import AESEncryption
from api.decryptAPI import AESDecryptionAPI


class TestMetrics:
    """Collect and display test metrics"""
    
    def __init__(self):
        self.tests_run = 0
        self.tests_passed = 0
        self.tests_failed = 0
        self.start_time = time.time()
        self.errors = []
    
    def record_pass(self, test_name):
        self.tests_run += 1
        self.tests_passed += 1
        print(f"✅ {test_name}")
    
    def record_fail(self, test_name, error):
        self.tests_run += 1
        self.tests_failed += 1
        self.errors.append(f"{test_name}: {error}")
        print(f"❌ {test_name}: {error}")
    
    def report(self):
        duration = time.time() - self.start_time
        print(f"\n🧪 TEST RESULTS")
        print("=" * 40)
        print(f"Tests run: {self.tests_run}")
        print(f"Passed: {self.tests_passed}")
        print(f"Failed: {self.tests_failed}")
        print(f"Success rate: {(self.tests_passed/self.tests_run)*100:.1f}%")
        print(f"Duration: {duration:.2f} seconds")
        
        if self.errors:
            print(f"\n❌ FAILURES:")
            for error in self.errors:
                print(f"   {error}")
        
        return self.tests_failed == 0


def test_rsa_key_management(metrics, temp_dir):
    """Test RSA key generation, saving, and loading"""
    
    try:
        # Test key generation
        rsa_manager = RSAKeyManager()
        private_key, public_key = rsa_manager.generate_key_pair(2048)
        
        if private_key is None or public_key is None:
            raise Exception("Key generation returned None")
        
        metrics.record_pass("RSA key generation (2048-bit)")
        
        # Test key saving
        private_path, public_path = rsa_manager.save_key_pair(
            private_key, public_key, temp_dir, "test_key"
        )
        
        if not os.path.exists(private_path) or not os.path.exists(public_path):
            raise Exception("Key files not created")
        
        metrics.record_pass("RSA key file saving")
        
        # Test key loading
        loaded_private = rsa_manager.load_private_key(private_path)
        loaded_public = rsa_manager.load_public_key(public_path)
        
        # Test key functionality
        test_data = b"test encryption data"
        encrypted = rsa_manager.encrypt_aes_key(test_data, loaded_public)
        decrypted = rsa_manager.decrypt_aes_key(encrypted, loaded_private)
        
        if decrypted != test_data:
            raise Exception("RSA encrypt/decrypt cycle failed")
        
        metrics.record_pass("RSA key loading and functionality")
        
    except Exception as e:
        metrics.record_fail("RSA key management", str(e))


def test_hybrid_encryption(metrics, temp_dir):
    """Test hybrid RSA+AES encryption/decryption"""
    
    try:
        # Create test file
        test_content = "This is test content for hybrid encryption validation."
        test_file = os.path.join(temp_dir, "hybrid_test.txt")
        with open(test_file, 'w') as f:
            f.write(test_content)
        
        # Generate RSA keys
        rsa_manager = RSAKeyManager()
        private_key, public_key = rsa_manager.generate_key_pair(2048)
        private_path, public_path = rsa_manager.save_key_pair(
            private_key, public_key, temp_dir, "hybrid_test"
        )
        
        # Test encryption
        start_time = time.time()
        encryptor = AESEncryption()
        encrypted_data, metadata = encryptor.encrypt_file_hybrid(
            test_file, public_path, 'AES-256'
        )
        encryption_time = time.time() - start_time
        
        enc_file, meta_file = encryptor.save_encrypted_file(
            test_file, encrypted_data, metadata
        )
        
        metrics.record_pass(f"Hybrid encryption ({encryption_time:.3f}s)")
        
        # Test decryption
        start_time = time.time()
        decryptor = AESDecryptionAPI()
        decrypted_file = decryptor.decrypt_file_hybrid(
            str(enc_file), str(meta_file), private_path
        )
        decryption_time = time.time() - start_time
        
        # Verify content
        with open(decrypted_file, 'r') as f:
            decrypted_content = f.read()
        
        if decrypted_content != test_content:
            raise Exception("Content integrity check failed")
        
        metrics.record_pass(f"Hybrid decryption ({decryption_time:.3f}s)")
        metrics.record_pass("Hybrid content integrity")
        
        # Test file sizes
        original_size = os.path.getsize(test_file)
        encrypted_size = os.path.getsize(str(enc_file))
        metadata_size = os.path.getsize(str(meta_file))
        
        print(f"   📊 File sizes: {original_size}→{encrypted_size} bytes (+{metadata_size} metadata)")
        
    except Exception as e:
        metrics.record_fail("Hybrid encryption", str(e))


def test_password_encryption(metrics, temp_dir):
    """Test traditional password-based encryption/decryption"""
    
    try:
        # Create test file
        test_content = "This is test content for password-based encryption validation."
        test_file = os.path.join(temp_dir, "password_test.txt")
        with open(test_file, 'w') as f:
            f.write(test_content)
        
        password = "TestPassword123!"
        
        # Test encryption
        start_time = time.time()
        encryptor = AESEncryption()
        encrypted_data, metadata = encryptor.encrypt_file(
            test_file, password, 'AES-256'
        )
        encryption_time = time.time() - start_time
        
        enc_file, meta_file = encryptor.save_encrypted_file(
            test_file, encrypted_data, metadata
        )
        
        metrics.record_pass(f"Password encryption ({encryption_time:.3f}s)")
        
        # Test decryption
        start_time = time.time()
        decryptor = AESDecryptionAPI()
        decrypted_file = decryptor.decrypt_file(
            str(enc_file), str(meta_file), password
        )
        decryption_time = time.time() - start_time
        
        # Verify content
        with open(decrypted_file, 'r') as f:
            decrypted_content = f.read()
        
        if decrypted_content != test_content:
            raise Exception("Content integrity check failed")
        
        metrics.record_pass(f"Password decryption ({decryption_time:.3f}s)")
        metrics.record_pass("Password content integrity")
        
    except Exception as e:
        metrics.record_fail("Password encryption", str(e))


def test_auto_detection(metrics, temp_dir):
    """Test smart auto-detection of encryption methods"""
    
    try:
        # Create test files for both methods
        test_content = "Auto-detection test content."
        test_file = os.path.join(temp_dir, "auto_test.txt")
        with open(test_file, 'w') as f:
            f.write(test_content)
        
        encryptor = AESEncryption()
        decryptor = AESDecryptionAPI()
        
        # Test 1: Hybrid file detection
        rsa_manager = RSAKeyManager()
        private_key, public_key = rsa_manager.generate_key_pair(2048)
        private_path, public_path = rsa_manager.save_key_pair(
            private_key, public_key, temp_dir, "auto_test"
        )
        
        encrypted_data, metadata = encryptor.encrypt_file_hybrid(
            test_file, public_path, 'AES-256'
        )
        enc_file, meta_file = encryptor.save_encrypted_file(
            test_file, encrypted_data, metadata
        )
        
        # Rename to distinguish
        hybrid_enc = os.path.join(temp_dir, "auto_hybrid.enc")
        hybrid_meta = os.path.join(temp_dir, "auto_hybrid.json")
        shutil.move(str(enc_file), hybrid_enc)
        shutil.move(str(meta_file), hybrid_meta)
        
        # Test auto-detection with hybrid file
        decrypted_file = decryptor.decrypt_file_auto(
            hybrid_enc, hybrid_meta, private_key_path=private_path
        )
        
        with open(decrypted_file, 'r') as f:
            if f.read() != test_content:
                raise Exception("Hybrid auto-detection failed")
        
        metrics.record_pass("Auto-detection (hybrid files)")
        
        # Test 2: Password file detection  
        password = "TestPassword123!"
        encrypted_data, metadata = encryptor.encrypt_file(
            test_file, password, 'AES-256'
        )
        enc_file, meta_file = encryptor.save_encrypted_file(
            test_file, encrypted_data, metadata
        )
        
        # Rename to distinguish
        pwd_enc = os.path.join(temp_dir, "auto_password.enc")
        pwd_meta = os.path.join(temp_dir, "auto_password.json")
        shutil.move(str(enc_file), pwd_enc)
        shutil.move(str(meta_file), pwd_meta)
        
        # Test auto-detection with password file
        decrypted_file = decryptor.decrypt_file_auto(
            pwd_enc, pwd_meta, password=password
        )
        
        with open(decrypted_file, 'r') as f:
            if f.read() != test_content:
                raise Exception("Password auto-detection failed")
        
        metrics.record_pass("Auto-detection (password files)")
        
    except Exception as e:
        metrics.record_fail("Auto-detection", str(e))


def test_encryption_types(metrics, temp_dir):
    """Test all AES encryption types"""
    
    for aes_type in ['AES-128', 'AES-192', 'AES-256']:
        try:
            test_content = f"Testing {aes_type} encryption."
            test_file = os.path.join(temp_dir, f"{aes_type.lower()}_test.txt")
            with open(test_file, 'w') as f:
                f.write(test_content)
            
            password = "TestPassword123!"
            
            # Test encryption/decryption cycle
            encryptor = AESEncryption()
            encrypted_data, metadata = encryptor.encrypt_file(
                test_file, password, aes_type
            )
            
            enc_file, meta_file = encryptor.save_encrypted_file(
                test_file, encrypted_data, metadata
            )
            
            decryptor = AESDecryptionAPI()
            decrypted_file = decryptor.decrypt_file(
                str(enc_file), str(meta_file), password
            )
            
            # Verify
            with open(decrypted_file, 'r') as f:
                if f.read() != test_content:
                    raise Exception(f"{aes_type} content verification failed")
            
            metrics.record_pass(f"{aes_type} encryption/decryption")
            
        except Exception as e:
            metrics.record_fail(f"{aes_type} encryption", str(e))


def run_test_suite():
    """Run the complete test suite"""
    
    print("🧪 AES File Encryption System - Test Suite")
    print("=" * 50)
    
    metrics = TestMetrics()
    
    # Create temporary directory for tests
    with tempfile.TemporaryDirectory() as temp_dir:
        print(f"📁 Test directory: {temp_dir}")
        
        # Run all test categories
        test_rsa_key_management(metrics, temp_dir)
        test_hybrid_encryption(metrics, temp_dir)
        test_password_encryption(metrics, temp_dir)
        test_auto_detection(metrics, temp_dir)
        test_encryption_types(metrics, temp_dir)
    
    # Generate final report
    success = metrics.report()
    
    if success:
        print("\n🎉 ALL TESTS PASSED! System is functioning correctly.")
    else:
        print("\n⚠️  SOME TESTS FAILED! Please review the failures above.")
    
    return success


if __name__ == "__main__":
    success = run_test_suite()
    sys.exit(0 if success else 1)
