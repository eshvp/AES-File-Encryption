import os
import sys
import base64
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import secrets

# Add current directory to path for RSA import
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from RSA import HybridEncryption


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
        self.hybrid_encryption = HybridEncryption()
    
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
    
    def encrypt_file_hybrid(self, file_path: str, public_key_path: str, encryption_type: str) -> tuple:
        """
        Encrypt a file using hybrid RSA+AES encryption
        
        Args:
            file_path: Path to the file to encrypt
            public_key_path: Path to RSA public key for encrypting AES key
            encryption_type: 'AES-128', 'AES-192', or 'AES-256'
        
        Returns:
            tuple: (encrypted_data, metadata) where metadata contains encrypted AES key and other info
        """
        if encryption_type not in self.KEY_SIZES:
            raise ValueError(f"Unsupported encryption type: {encryption_type}")
        
        # Read file content
        with open(file_path, 'rb') as file:
            file_data = file.read()
        
        # Generate random AES key and IV
        key_size = self.KEY_SIZES[encryption_type]
        aes_key = self.hybrid_encryption.generate_aes_key(key_size)
        iv = secrets.token_bytes(16)
        
        # Pad the data
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(file_data)
        padded_data += padder.finalize()
        
        # Encrypt with AES
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Encrypt AES key with RSA
        rsa_encryption_data = self.hybrid_encryption.encrypt_with_hybrid(aes_key, public_key_path)
        
        # Create metadata with encrypted AES key
        metadata = {
            'iv': base64.b64encode(iv).decode(),
            'tag': self.ENCRYPTION_TAGS[encryption_type],
            'encryption_type': encryption_type,
            'original_filename': Path(file_path).name,
            'original_size': len(file_data),
            'encryption_method': 'hybrid_rsa_aes',
            'encrypted_aes_key': rsa_encryption_data['encrypted_aes_key'],
            'rsa_key_size': rsa_encryption_data['rsa_key_size']
        }
        
        return encrypted_data, metadata


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


def get_public_key_path():
    """Get RSA public key path from user input with validation"""
    while True:
        key_path = input("\nEnter path to RSA public key (.pem): ").strip()
        
        # Remove surrounding quotes if present
        if key_path.startswith('"') and key_path.endswith('"'):
            key_path = key_path[1:-1]
        elif key_path.startswith("'") and key_path.endswith("'"):
            key_path = key_path[1:-1]
        
        if os.path.exists(key_path):
            if os.path.isfile(key_path):
                return key_path
            else:
                print("❌ Error: Path exists but is not a file. Please enter a valid key file path.")
        else:
            print("❌ Error: Key file not found. Please check the path and try again.")


def get_encryption_method():
    """Get encryption method choice from user"""
    print("\n🔐 Choose encryption method:")
    print("1. Hybrid RSA+AES (Recommended - Most secure)")
    print("2. Password-based AES (Traditional method)")
    
    while True:
        choice = input("\nEnter your choice (1-2): ").strip()
        
        if choice == '1':
            return 'hybrid'
        elif choice == '2':
            return 'password'
        else:
            print("❌ Invalid choice. Please enter 1 or 2.")


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


def setup_rsa_keys_prompt():
    """Prompt user to setup RSA keys if they choose hybrid encryption"""
    print("\n🔑 RSA Key Setup Required")
    print("Hybrid encryption requires RSA key pairs.")
    
    choice = input("\nDo you have RSA keys already? (y/n): ").lower().strip()
    
    if choice in ['n', 'no']:
        print("\n🚀 Let's generate RSA keys for you!")
        from RSA import setup_rsa_keys
        private_path, public_path = setup_rsa_keys()
        return public_path
    else:
        return get_public_key_path()


def main():
    """Main function to run the encryption process"""
    print("🔒 Hybrid AES File Encryption Tool")
    print("=" * 50)
    print("Now supports RSA+AES hybrid encryption!")
    
    try:
        # Get user inputs
        file_path = get_file_path()
        encryption_type = get_encryption_type()
        encryption_method = get_encryption_method()
        
        # Initialize encryption
        aes_encryptor = AESEncryption()
        
        if encryption_method == 'hybrid':
            # Hybrid RSA+AES encryption
            public_key_path = setup_rsa_keys_prompt()
            
            print(f"\n🔄 Encrypting file with {encryption_type} + RSA...")
            
            # Encrypt the file with hybrid method
            encrypted_data, metadata = aes_encryptor.encrypt_file_hybrid(
                file_path, public_key_path, encryption_type
            )
            
            # Save encrypted file
            encrypted_file_path, metadata_file_path = aes_encryptor.save_encrypted_file(
                file_path, encrypted_data, metadata
            )
            
            print("✅ Hybrid encryption completed successfully!")
            print(f"📁 Encrypted file saved: {encrypted_file_path}")
            print(f"📋 Metadata saved: {metadata_file_path}")
            print(f"🔑 RSA key size: {metadata['rsa_key_size']} bits")
            print(f"🏷️  Hidden tag for decryption: {metadata['tag']}")
            print(f"🔐 Method: {metadata['encryption_method']}")
            
        else:
            # Traditional password-based encryption
            password = get_password()
            
            print(f"\n🔄 Encrypting file with {encryption_type}...")
            
            # Encrypt the file with password
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