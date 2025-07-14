import os
import base64
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import secrets


class AESEncryption:
    """Modular AES encryption class supporting AES-128, AES-192, and AES-256"""
    
    # Hidden tags for decryption system identification
    ENCRYPTION_TAGS = {
        'AES-128': 'h1k789',
        'AES-192': 'GP94GF',
        'AES-256': 'k913h923'
    }
    
    KEY_SIZES = {
        'AES-128': 16,  # 128 bits = 16 bytes
        'AES-192': 24,  # 192 bits = 24 bytes
        'AES-256': 32   # 256 bits = 32 bytes
    }
    
    def __init__(self):
        self.backend = default_backend()
    
    def generate_key(self, password: str, salt: bytes, key_size: int) -> bytes:
        """Generate encryption key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_size,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(password.encode())
    
    def encrypt_file(self, file_path: str, password: str, encryption_type: str) -> tuple:
        """
        Encrypt a file using specified AES encryption type
        
        Args:
            file_path: Path to the file to encrypt
            password: Password for encryption
            encryption_type: 'AES-128', 'AES-192', or 'AES-256'
        
        Returns:
            tuple: (encrypted_data, metadata) where metadata contains salt, iv, and tag
        """
        if encryption_type not in self.KEY_SIZES:
            raise ValueError(f"Unsupported encryption type: {encryption_type}")
        
        # Read file content
        with open(file_path, 'rb') as file:
            file_data = file.read()
        
        # Generate salt and IV
        salt = secrets.token_bytes(16)
        iv = secrets.token_bytes(16)
        
        # Generate key
        key_size = self.KEY_SIZES[encryption_type]
        key = self.generate_key(password, salt, key_size)
        
        # Pad the data
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(file_data)
        padded_data += padder.finalize()
        
        # Encrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Create metadata with hidden tag
        metadata = {
            'salt': base64.b64encode(salt).decode(),
            'iv': base64.b64encode(iv).decode(),
            'tag': self.ENCRYPTION_TAGS[encryption_type],
            'encryption_type': encryption_type,
            'original_filename': Path(file_path).name,
            'original_size': len(file_data)
        }
        
        return encrypted_data, metadata
    
    def save_encrypted_file(self, original_file_path: str, encrypted_data: bytes, metadata: dict):
        """Save encrypted file with metadata"""
        original_path = Path(original_file_path)
        encrypted_file_path = original_path.parent / f"{original_path.stem}_encrypted.enc"
        metadata_file_path = original_path.parent / f"{original_path.stem}_metadata.json"
        
        # Save encrypted data as binary
        with open(encrypted_file_path, 'wb') as file:
            file.write(encrypted_data)
        
        # Save metadata
        import json
        with open(metadata_file_path, 'w') as file:
            json.dump(metadata, file, indent=2)
        
        return encrypted_file_path, metadata_file_path


def get_file_path():
    """Get file path from user input with validation"""
    while True:
        file_path = input("\nEnter the file path you want to encrypt: ").strip()
        
        # Remove surrounding quotes if present, but preserve other characters including parentheses
        if file_path.startswith('"') and file_path.endswith('"'):
            file_path = file_path[1:-1]
        elif file_path.startswith("'") and file_path.endswith("'"):
            file_path = file_path[1:-1]
        
        if os.path.exists(file_path):
            if os.path.isfile(file_path):
                return file_path
            else:
                print("❌ Error: Path exists but is not a file. Please enter a valid file path.")
        else:
            print("❌ Error: File not found. Please check the path and try again.")


def get_encryption_type():
    """Get encryption type choice from user"""
    print("\n🔐 Choose encryption type:")
    print("1. AES-128 (Fast, good security)")
    print("2. AES-192 (Balanced security and performance)")
    print("3. AES-256 (Maximum security, slower)")
    
    while True:
        choice = input("\nEnter your choice (1-3): ").strip()
        
        encryption_map = {
            '1': 'AES-128',
            '2': 'AES-192',
            '3': 'AES-256'
        }
        
        if choice in encryption_map:
            return encryption_map[choice]
        else:
            print("❌ Invalid choice. Please enter 1, 2, or 3.")


def get_password():
    """Get password from user with confirmation"""
    import getpass
    
    while True:
        password = getpass.getpass("\nEnter encryption password: ")
        if len(password) < 8:
            print("❌ Password must be at least 8 characters long.")
            continue
        
        confirm_password = getpass.getpass("Confirm password: ")
        if password == confirm_password:
            return password
        else:
            print("❌ Passwords don't match. Please try again.")


def main():
    """Main function to run the encryption process"""
    print("🔒 AES File Encryption Tool")
    print("=" * 40)
    
    try:
        # Get user inputs
        file_path = get_file_path()
        encryption_type = get_encryption_type()
        password = get_password()
        
        # Initialize encryption
        aes_encryptor = AESEncryption()
        
        print(f"\n🔄 Encrypting file with {encryption_type}...")
        
        # Encrypt the file
        encrypted_data, metadata = aes_encryptor.encrypt_file(file_path, password, encryption_type)
        
        # Save encrypted file
        encrypted_file_path, metadata_file_path = aes_encryptor.save_encrypted_file(
            file_path, encrypted_data, metadata
        )
        
        print("✅ Encryption completed successfully!")
        print(f"📁 Encrypted file saved: {encrypted_file_path}")
        print(f"📋 Metadata saved: {metadata_file_path}")
        print(f"🏷️  Hidden tag for decryption: {metadata['tag']}")
        
    except KeyboardInterrupt:
        print("\n\n❌ Operation cancelled by user.")
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")


if __name__ == "__main__":
    main()