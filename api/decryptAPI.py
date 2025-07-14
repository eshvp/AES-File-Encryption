import os
import json
import base64
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from typing import Dict, Tuple, Optional


class AESDecryptionAPI:
    """API module for decrypting AES encrypted files using hidden meta tags"""
    
    # Hidden tags mapping (must match encryption module)
    TAG_TO_ENCRYPTION = {
        'h1k789': 'AES-128',
        'GP94GF': 'AES-192', 
        'k913h923': 'AES-256'
    }
    
    KEY_SIZES = {
        'AES-128': 16,  # 128 bits = 16 bytes
        'AES-192': 24,  # 192 bits = 24 bytes
        'AES-256': 32   # 256 bits = 32 bytes
    }
    
    def __init__(self):
        self.backend = default_backend()
    
    def generate_key(self, password: str, salt: bytes, key_size: int) -> bytes:
        """Generate decryption key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_size,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(password.encode())
    
    def load_metadata(self, metadata_path: str) -> Dict:
        """Load metadata from JSON file"""
        try:
            with open(metadata_path, 'r') as file:
                metadata = json.load(file)
            return metadata
        except FileNotFoundError:
            raise FileNotFoundError(f"Metadata file not found: {metadata_path}")
        except json.JSONDecodeError:
            raise ValueError(f"Invalid JSON in metadata file: {metadata_path}")
    
    def identify_encryption_type(self, metadata: Dict) -> str:
        """Identify encryption type from hidden tag in metadata"""
        tag = metadata.get('tag')
        if not tag:
            raise ValueError("No hidden tag found in metadata")
        
        encryption_type = self.TAG_TO_ENCRYPTION.get(tag)
        if not encryption_type:
            raise ValueError(f"Unknown encryption tag: {tag}")
        
        return encryption_type
    
    def decrypt_data(self, encrypted_data: bytes, metadata: Dict, password: str) -> bytes:
        """
        Decrypt data using metadata and password
        
        Args:
            encrypted_data: Binary encrypted data
            metadata: Metadata dictionary containing salt, IV, and tag
            password: Decryption password
        
        Returns:
            bytes: Decrypted file data
        """
        # Identify encryption type from hidden tag
        encryption_type = self.identify_encryption_type(metadata)
        
        # Extract metadata
        salt = base64.b64decode(metadata['salt'])
        iv = base64.b64decode(metadata['iv'])
        
        # Generate key
        key_size = self.KEY_SIZES[encryption_type]
        key = self.generate_key(password, salt, key_size)
        
        # Use encrypted data directly (no base64 decoding needed)
        encrypted_bytes = encrypted_data
        
        # Decrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_bytes) + decryptor.finalize()
        
        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        file_data = unpadder.update(padded_data)
        file_data += unpadder.finalize()
        
        return file_data
    
    def decrypt_file(self, encrypted_file_path: str, metadata_file_path: str, 
                    password: str, output_path: Optional[str] = None) -> str:
        """
        Decrypt a file using its metadata
        
        Args:
            encrypted_file_path: Path to encrypted .enc file
            metadata_file_path: Path to metadata .json file
            password: Decryption password
            output_path: Optional custom output path
        
        Returns:
            str: Path to decrypted file
        """
        # Load encrypted data as binary
        with open(encrypted_file_path, 'rb') as file:
            encrypted_data = file.read()
        
        # Load metadata
        metadata = self.load_metadata(metadata_file_path)
        
        # Decrypt data
        try:
            decrypted_data = self.decrypt_data(encrypted_data, metadata, password)
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
        
        # Determine output path
        if output_path is None:
            encrypted_path = Path(encrypted_file_path)
            # Remove _encrypted suffix and .enc extension
            original_name = encrypted_path.stem.replace('_encrypted', '')
            output_path = encrypted_path.parent / f"{original_name}_decrypted"
        
        # Save decrypted file
        with open(output_path, 'wb') as file:
            file.write(decrypted_data)
        
        return str(output_path)
    
    def auto_decrypt(self, base_filename: str, password: str, 
                    directory: Optional[str] = None) -> str:
        """
        Auto-decrypt files by finding matching .enc and metadata files
        
        Args:
            base_filename: Base filename without extension (e.g., 'document')
            password: Decryption password
            directory: Directory to search in (defaults to current directory)
        
        Returns:
            str: Path to decrypted file
        """
        if directory is None:
            directory = os.getcwd()
        
        dir_path = Path(directory)
        
        # Look for encrypted file and metadata
        encrypted_file = dir_path / f"{base_filename}_encrypted.enc"
        metadata_file = dir_path / f"{base_filename}_metadata.json"
        
        if not encrypted_file.exists():
            raise FileNotFoundError(f"Encrypted file not found: {encrypted_file}")
        
        if not metadata_file.exists():
            raise FileNotFoundError(f"Metadata file not found: {metadata_file}")
        
        return self.decrypt_file(str(encrypted_file), str(metadata_file), password)
    
    def validate_files(self, encrypted_file_path: str, metadata_file_path: str) -> Dict:
        """
        Validate that encrypted file and metadata are compatible
        
        Returns:
            Dict: Validation results and file information
        """
        result = {
            'valid': False,
            'encryption_type': None,
            'tag': None,
            'errors': []
        }
        
        try:
            # Check if files exist
            if not os.path.exists(encrypted_file_path):
                result['errors'].append(f"Encrypted file not found: {encrypted_file_path}")
                return result
            
            if not os.path.exists(metadata_file_path):
                result['errors'].append(f"Metadata file not found: {metadata_file_path}")
                return result
            
            # Load and validate metadata
            metadata = self.load_metadata(metadata_file_path)
            
            # Check required fields
            required_fields = ['salt', 'iv', 'tag', 'encryption_type']
            missing_fields = [field for field in required_fields if field not in metadata]
            
            if missing_fields:
                result['errors'].append(f"Missing metadata fields: {missing_fields}")
                return result
            
            # Validate tag
            tag = metadata['tag']
            if tag not in self.TAG_TO_ENCRYPTION:
                result['errors'].append(f"Unknown encryption tag: {tag}")
                return result
            
            # Check if tag matches declared encryption type
            declared_type = metadata['encryption_type']
            tag_type = self.TAG_TO_ENCRYPTION[tag]
            
            if declared_type != tag_type:
                result['errors'].append(
                    f"Encryption type mismatch: tag indicates {tag_type}, "
                    f"but metadata declares {declared_type}"
                )
                return result
            
            result['valid'] = True
            result['encryption_type'] = tag_type
            result['tag'] = tag
            
        except Exception as e:
            result['errors'].append(f"Validation error: {str(e)}")
        
        return result


# Convenience functions for easy API usage
def decrypt_file(encrypted_file_path: str, metadata_file_path: str, 
                password: str, output_path: Optional[str] = None) -> str:
    """
    Convenience function to decrypt a file
    
    Args:
        encrypted_file_path: Path to encrypted .enc file
        metadata_file_path: Path to metadata .json file
        password: Decryption password
        output_path: Optional custom output path
    
    Returns:
        str: Path to decrypted file
    """
    api = AESDecryptionAPI()
    return api.decrypt_file(encrypted_file_path, metadata_file_path, password, output_path)


def auto_decrypt(base_filename: str, password: str, 
                directory: Optional[str] = None) -> str:
    """
    Convenience function to auto-decrypt files by base filename
    
    Args:
        base_filename: Base filename without extension
        password: Decryption password
        directory: Directory to search in
    
    Returns:
        str: Path to decrypted file
    """
    api = AESDecryptionAPI()
    return api.auto_decrypt(base_filename, password, directory)


def validate_encrypted_files(encrypted_file_path: str, metadata_file_path: str) -> Dict:
    """
    Convenience function to validate encrypted files
    
    Returns:
        Dict: Validation results
    """
    api = AESDecryptionAPI()
    return api.validate_files(encrypted_file_path, metadata_file_path)


def get_encryption_info(metadata_file_path: str) -> Dict:
    """
    Get encryption information from metadata file
    
    Args:
        metadata_file_path: Path to metadata file
    
    Returns:
        Dict: Encryption information
    """
    api = AESDecryptionAPI()
    metadata = api.load_metadata(metadata_file_path)
    encryption_type = api.identify_encryption_type(metadata)
    
    return {
        'encryption_type': encryption_type,
        'tag': metadata['tag'],
        'declared_type': metadata.get('encryption_type', 'Unknown')
    }


# Example usage and testing
if __name__ == "__main__":
    print("🔓 AES Decryption API Module")
    print("=" * 40)
    print("Available functions:")
    print("- decrypt_file(encrypted_path, metadata_path, password)")
    print("- auto_decrypt(base_filename, password, directory)")
    print("- validate_encrypted_files(encrypted_path, metadata_path)")
    print("- get_encryption_info(metadata_path)")
    print("\nExample:")
    print("from decryptAPI import auto_decrypt")
    print("decrypted_file = auto_decrypt('document', 'mypassword', '/path/to/files')")