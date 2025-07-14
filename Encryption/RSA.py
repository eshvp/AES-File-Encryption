import os
import base64
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import secrets


class RSAKeyManager:
    """RSA key generation and management for hybrid encryption"""
    
    def __init__(self):
        self.backend = default_backend()
    
    def generate_key_pair(self, key_size: int = 2048) -> tuple:
        """
        Generate RSA key pair
        
        Args:
            key_size: RSA key size (2048, 3072, or 4096 bits)
        
        Returns:
            tuple: (private_key, public_key) objects
        """
        if key_size not in [2048, 3072, 4096]:
            raise ValueError("Key size must be 2048, 3072, or 4096 bits")
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=self.backend
        )
        public_key = private_key.public_key()
        
        return private_key, public_key
    
    def save_key_pair(self, private_key, public_key, directory: str = None, key_name: str = "encryption_key"):
        """
        Save RSA key pair to files
        
        Args:
            private_key: Private key object
            public_key: Public key object
            directory: Directory to save keys (default: current directory)
            key_name: Base name for key files
        
        Returns:
            tuple: (private_key_path, public_key_path)
        """
        if directory is None:
            directory = os.getcwd()
        
        directory = Path(directory)
        private_key_path = directory / f"{key_name}_private.pem"
        public_key_path = directory / f"{key_name}_public.pem"
        
        # Save private key (password protected)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()  # No password for now
        )
        
        # Save public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(private_key_path, 'wb') as f:
            f.write(private_pem)
        
        with open(public_key_path, 'wb') as f:
            f.write(public_pem)
        
        return str(private_key_path), str(public_key_path)
    
    def load_private_key(self, private_key_path: str, password: bytes = None):
        """Load private key from file"""
        with open(private_key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=password,
                backend=self.backend
            )
        return private_key
    
    def load_public_key(self, public_key_path: str):
        """Load public key from file"""
        with open(public_key_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=self.backend
            )
        return public_key
    
    def encrypt_aes_key(self, aes_key: bytes, public_key) -> bytes:
        """
        Encrypt AES key with RSA public key
        
        Args:
            aes_key: AES key to encrypt
            public_key: RSA public key object
        
        Returns:
            bytes: Encrypted AES key
        """
        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_key
    
    def decrypt_aes_key(self, encrypted_aes_key: bytes, private_key) -> bytes:
        """
        Decrypt AES key with RSA private key
        
        Args:
            encrypted_aes_key: Encrypted AES key
            private_key: RSA private key object
        
        Returns:
            bytes: Decrypted AES key
        """
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return aes_key


class HybridEncryption:
    """Hybrid RSA+AES encryption system"""
    
    def __init__(self):
        self.rsa_manager = RSAKeyManager()
    
    def generate_aes_key(self, key_size: int) -> bytes:
        """Generate random AES key"""
        return secrets.token_bytes(key_size)
    
    def encrypt_with_hybrid(self, aes_key: bytes, public_key_path: str) -> dict:
        """
        Encrypt AES key with RSA for hybrid encryption
        
        Args:
            aes_key: AES key to encrypt
            public_key_path: Path to RSA public key
        
        Returns:
            dict: Encryption metadata including encrypted AES key
        """
        # Load public key
        public_key = self.rsa_manager.load_public_key(public_key_path)
        
        # Encrypt AES key with RSA
        encrypted_aes_key = self.rsa_manager.encrypt_aes_key(aes_key, public_key)
        
        return {
            'encrypted_aes_key': base64.b64encode(encrypted_aes_key).decode(),
            'rsa_key_size': public_key.key_size,
            'encryption_method': 'RSA-OAEP + AES'
        }
    
    def decrypt_with_hybrid(self, encrypted_key_data: dict, private_key_path: str) -> bytes:
        """
        Decrypt AES key with RSA for hybrid decryption
        
        Args:
            encrypted_key_data: Dictionary containing encrypted AES key
            private_key_path: Path to RSA private key
        
        Returns:
            bytes: Decrypted AES key
        """
        # Load private key
        private_key = self.rsa_manager.load_private_key(private_key_path)
        
        # Decode encrypted AES key
        encrypted_aes_key = base64.b64decode(encrypted_key_data['encrypted_aes_key'])
        
        # Decrypt AES key
        aes_key = self.rsa_manager.decrypt_aes_key(encrypted_aes_key, private_key)
        
        return aes_key


def setup_rsa_keys(directory: str = None, key_name: str = "encryption_key") -> tuple:
    """
    Setup RSA key pair for hybrid encryption
    
    Args:
        directory: Directory to save keys
        key_name: Base name for key files
    
    Returns:
        tuple: (private_key_path, public_key_path)
    """
    print("🔑 Setting up RSA key pair for hybrid encryption...")
    
    # Choose key size
    print("\nChoose RSA key size:")
    print("1. 2048 bits (Standard, fast)")
    print("2. 3072 bits (Enhanced security)")  
    print("3. 4096 bits (Maximum security, slower)")
    
    while True:
        choice = input("\nEnter your choice (1-3): ").strip()
        key_sizes = {'1': 2048, '2': 3072, '3': 4096}
        if choice in key_sizes:
            key_size = key_sizes[choice]
            break
        print("❌ Invalid choice. Please enter 1, 2, or 3.")
    
    # Generate keys
    rsa_manager = RSAKeyManager()
    private_key, public_key = rsa_manager.generate_key_pair(key_size)
    
    # Save keys
    private_path, public_path = rsa_manager.save_key_pair(
        private_key, public_key, directory, key_name
    )
    
    print(f"✅ RSA key pair generated ({key_size} bits)")
    print(f"🔒 Private key: {private_path}")
    print(f"🔓 Public key: {public_path}")
    print("\n⚠️  IMPORTANT: Keep your private key secure and backup both keys!")
    
    return private_path, public_path


if __name__ == "__main__":
    # Demo/test the RSA functionality
    setup_rsa_keys()
