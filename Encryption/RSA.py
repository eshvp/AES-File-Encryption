import os
import json
import secrets
import datetime
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

class RSAKeyManager:
    def __init__(self):
        self.keys_dir = Path("rsa_keys")
        self.keys_dir.mkdir(exist_ok=True)
        self.recipients_dir = Path("recipients")
        self.recipients_dir.mkdir(exist_ok=True)
        
    def generate_key_pair(self, key_name="default", key_size=2048):
        """Generate RSA key pair and save to files"""
        try:
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
            
            # Get public key
            public_key = private_key.public_key()
            
            # Serialize private key
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Serialize public key
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Save keys
            private_key_path = self.keys_dir / f"{key_name}_private.pem"
            public_key_path = self.keys_dir / f"{key_name}_public.pem"
            
            with open(private_key_path, 'wb') as f:
                f.write(private_pem)
            
            with open(public_key_path, 'wb') as f:
                f.write(public_pem)
            
            print(f"✓ RSA key pair generated successfully:")
            print(f"  Private key: {private_key_path}")
            print(f"  Public key: {public_key_path}")
            print(f"  Key size: {key_size} bits")
            
            return private_key_path, public_key_path
            
        except Exception as e:
            raise Exception(f"Failed to generate RSA key pair: {str(e)}")
    
    def load_private_key(self, key_path, password=None):
        """Load RSA private key from file"""
        try:
            with open(key_path, 'rb') as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=password.encode() if password else None,
                    backend=default_backend()
                )
            return private_key
        except Exception as e:
            raise Exception(f"Failed to load private key: {str(e)}")
    
    def load_public_key(self, key_path):
        """Load RSA public key from file"""
        try:
            with open(key_path, 'rb') as f:
                public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )
            return public_key
        except Exception as e:
            raise Exception(f"Failed to load public key: {str(e)}")
    
    def list_key_pairs(self):
        """List available RSA key pairs"""
        try:
            private_keys = list(self.keys_dir.glob("*_private.pem"))
            key_pairs = []
            
            for private_key_path in private_keys:
                key_name = private_key_path.name.replace("_private.pem", "")
                public_key_path = self.keys_dir / f"{key_name}_public.pem"
                
                if public_key_path.exists():
                    key_pairs.append({
                        'name': key_name,
                        'private_key': private_key_path,
                        'public_key': public_key_path
                    })
            
            return key_pairs
        except Exception as e:
            raise Exception(f"Failed to list key pairs: {str(e)}")

class RSAEncryption:
    def __init__(self):
        self.key_manager = RSAKeyManager()
        
    def encrypt_aes_key(self, aes_key, recipient_public_key_path):
        """Encrypt AES key using recipient's RSA public key"""
        try:
            # Load recipient's public key
            public_key = self.key_manager.load_public_key(recipient_public_key_path)
            
            # Encrypt the AES key
            encrypted_aes_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return encrypted_aes_key
            
        except Exception as e:
            raise Exception(f"Failed to encrypt AES key: {str(e)}")
    
    def decrypt_aes_key(self, encrypted_aes_key, private_key_path, password=None):
        """Decrypt AES key using RSA private key"""
        try:
            # Load private key
            private_key = self.key_manager.load_private_key(private_key_path, password)
            
            # Decrypt the AES key
            aes_key = private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return aes_key
            
        except Exception as e:
            raise Exception(f"Failed to decrypt AES key: {str(e)}")

class RecipientManager:
    """Abstract foundation for managing recipients and their public keys"""
    
    def __init__(self):
        self.recipients_dir = Path("recipients")
        self.recipients_dir.mkdir(exist_ok=True)
        self.recipients_file = self.recipients_dir / "recipients.json"
    
    def add_recipient(self, name, email, public_key_path):
        """Add a recipient with their public key"""
        try:
            # Load existing recipients
            recipients = self.load_recipients()
            
            # Validate inputs
            if not name or not email:
                raise ValueError("Name and email are required")
            
            # Check if recipient already exists
            if name in recipients:
                overwrite = input(f"Recipient '{name}' already exists. Overwrite? (y/n): ").strip().lower()
                if overwrite != 'y' and overwrite != 'yes':
                    print("Operation cancelled.")
                    return False
            
            # Validate public key file exists
            source_key_path = Path(public_key_path)
            if not source_key_path.exists():
                raise FileNotFoundError(f"Public key file not found: {public_key_path}")
            
            # Copy public key to recipients directory
            recipient_key_path = self.recipients_dir / f"{name}_public.pem"
            
            # Validate the public key by trying to load it
            try:
                with open(source_key_path, 'rb') as f:
                    serialization.load_pem_public_key(f.read(), backend=default_backend())
            except Exception as e:
                raise ValueError(f"Invalid public key file: {str(e)}")
            
            # Copy the public key
            import shutil
            shutil.copy2(source_key_path, recipient_key_path)
            
            # Store recipient info
            recipients[name] = {
                'email': email,
                'public_key': str(recipient_key_path),
                'added_date': datetime.datetime.now().isoformat()
            }
            
            # Save recipients
            self.save_recipients(recipients)
            
            print(f"✓ Recipient '{name}' added successfully")
            print(f"  Email: {email}")
            print(f"  Public key copied to: {recipient_key_path}")
            
            return True
            
        except Exception as e:
            raise Exception(f"Failed to add recipient: {str(e)}")
    
    def remove_recipient(self, name):
        """Remove a recipient"""
        try:
            recipients = self.load_recipients()
            
            if name not in recipients:
                print(f"Recipient '{name}' not found.")
                return False
            
            # Remove public key file
            recipient_key_path = Path(recipients[name]['public_key'])
            if recipient_key_path.exists():
                recipient_key_path.unlink()
            
            # Remove from recipients
            del recipients[name]
            self.save_recipients(recipients)
            
            print(f"✓ Recipient '{name}' removed successfully")
            return True
            
        except Exception as e:
            raise Exception(f"Failed to remove recipient: {str(e)}")
    
    def get_recipient_public_key(self, name):
        """Get recipient's public key path"""
        try:
            recipients = self.load_recipients()
            
            if name not in recipients:
                raise ValueError(f"Recipient '{name}' not found")
            
            key_path = Path(recipients[name]['public_key'])
            if not key_path.exists():
                raise FileNotFoundError(f"Public key file not found: {key_path}")
            
            return key_path
            
        except Exception as e:
            raise Exception(f"Failed to get recipient public key: {str(e)}")
    
    def load_recipients(self):
        """Load recipients from JSON file"""
        try:
            if self.recipients_file.exists():
                with open(self.recipients_file, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            return {}
    
    def save_recipients(self, recipients):
        """Save recipients to JSON file"""
        try:
            with open(self.recipients_file, 'w') as f:
                json.dump(recipients, f, indent=2)
        except Exception as e:
            raise Exception(f"Failed to save recipients: {str(e)}")
    
    def list_recipients(self):
        """List all available recipients (abstract foundation)"""
        try:
            recipients = self.load_recipients()
            
            if not recipients:
                print("No recipients found.")
                return []
            
            print(f"\n--- Recipients ({len(recipients)} total) ---")
            for name, info in recipients.items():
                print(f"Name: {name}")
                print(f"Email: {info.get('email', 'N/A')}")
                print(f"Public Key: {info.get('public_key', 'N/A')}")
                print()
            
            return list(recipients.keys())
            
        except Exception as e:
            raise Exception(f"Failed to list recipients: {str(e)}")

class HybridEncryption:
    """Complete hybrid AES+RSA encryption system"""
    
    def __init__(self):
        self.rsa_encryption = RSAEncryption()
        self.recipient_manager = RecipientManager()
        self.encrypted_dir = Path("encrypted_files")
        self.encrypted_dir.mkdir(exist_ok=True)
        self.packages_dir = Path("encrypted_packages")
        self.packages_dir.mkdir(exist_ok=True)
    
    def generate_aes_key(self, key_size=32):
        """Generate a random AES key (32 bytes for AES-256)"""
        return secrets.token_bytes(key_size)
    
    def encrypt_file_with_aes(self, file_path, aes_key):
        """Encrypt file using AES-256-CBC"""
        try:
            # Generate random IV
            iv = secrets.token_bytes(16)
            
            # Read file content
            with open(file_path, 'rb') as f:
                plaintext = f.read()
            
            # Add PKCS7 padding
            padder = sym_padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext)
            padded_data += padder.finalize()
            
            # Encrypt with AES
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            return iv, ciphertext
            
        except Exception as e:
            raise Exception(f"Failed to encrypt file with AES: {str(e)}")
    
    def decrypt_file_with_aes(self, iv, ciphertext, aes_key):
        """Decrypt file using AES-256-CBC"""
        try:
            # Decrypt with AES
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove PKCS7 padding
            unpadder = sym_padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext)
            plaintext += unpadder.finalize()
            
            return plaintext
            
        except Exception as e:
            raise Exception(f"Failed to decrypt file with AES: {str(e)}")
    
    def create_package_metadata(self, original_filename, recipient_name, aes_key_size, rsa_key_size):
        """Create metadata for the encrypted package"""
        return {
            'version': '1.0',
            'timestamp': datetime.datetime.now().isoformat(),
            'original_filename': original_filename,
            'recipient': recipient_name,
            'encryption': {
                'aes_mode': 'CBC',
                'aes_key_size': aes_key_size * 8,  # Convert bytes to bits
                'rsa_key_size': rsa_key_size,
                'padding': 'OAEP_SHA256'
            }
        }
    
    def encrypt_file_for_recipient(self, file_path, recipient_name):
        """🔒 SENDER SIDE: Complete file encryption for recipient"""
        try:
            file_path = Path(file_path)
            
            # Validate file exists
            if not file_path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")
            
            # Get recipient's public key
            recipient_public_key_path = self.recipient_manager.get_recipient_public_key(recipient_name)
            
            # Step 1: Generate random AES key (32 bytes for AES-256)
            aes_key = self.generate_aes_key(32)
            print(f"✓ Generated AES-256 key ({len(aes_key)} bytes)")
            
            # Step 2: Use AES key to encrypt the file
            iv, encrypted_file_data = self.encrypt_file_with_aes(file_path, aes_key)
            print(f"✓ File encrypted with AES-256-CBC")
            
            # Step 3: Use recipient's RSA public key to encrypt the AES key
            encrypted_aes_key = self.rsa_encryption.encrypt_aes_key(aes_key, recipient_public_key_path)
            print(f"✓ AES key encrypted with RSA public key")
            
            # Step 4: Create metadata
            public_key = self.rsa_encryption.key_manager.load_public_key(recipient_public_key_path)
            rsa_key_size = public_key.key_size
            metadata = self.create_package_metadata(file_path.name, recipient_name, len(aes_key), rsa_key_size)
            
            # Step 5: Package everything together
            package_name = f"{file_path.stem}_{recipient_name}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
            package_dir = self.packages_dir / package_name
            package_dir.mkdir(exist_ok=True)
            
            # Save encrypted file
            encrypted_file_path = package_dir / f"{file_path.name}.encrypted"
            with open(encrypted_file_path, 'wb') as f:
                f.write(iv + encrypted_file_data)  # IV + encrypted data
            
            # Save encrypted AES key
            encrypted_key_path = package_dir / "encrypted_aes_key.bin"
            with open(encrypted_key_path, 'wb') as f:
                f.write(encrypted_aes_key)
            
            # Save metadata
            metadata_path = package_dir / "metadata.json"
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            print(f"\n✓ Encryption package created successfully!")
            print(f"  Package: {package_dir}")
            print(f"  Encrypted file: {encrypted_file_path.name}")
            print(f"  Encrypted AES key: {encrypted_key_path.name}")
            print(f"  Metadata: {metadata_path.name}")
            print(f"  Recipient: {recipient_name}")
            
            return {
                'package_dir': package_dir,
                'encrypted_file': encrypted_file_path,
                'encrypted_aes_key': encrypted_key_path,
                'metadata': metadata_path,
                'recipient': recipient_name
            }
            
        except Exception as e:
            raise Exception(f"Failed to encrypt file for recipient: {str(e)}")
    
    def decrypt_package_with_private_key(self, package_dir, private_key_path, password=None):
        """🔓 RECEIVER SIDE: Complete package decryption with private key"""
        try:
            package_dir = Path(package_dir)
            
            # Validate package directory
            if not package_dir.exists():
                raise FileNotFoundError(f"Package directory not found: {package_dir}")
            
            # Load metadata
            metadata_path = package_dir / "metadata.json"
            if not metadata_path.exists():
                raise FileNotFoundError("Package metadata not found")
            
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            # Find encrypted files
            encrypted_key_path = package_dir / "encrypted_aes_key.bin"
            encrypted_files = list(package_dir.glob("*.encrypted"))
            
            if not encrypted_key_path.exists():
                raise FileNotFoundError("Encrypted AES key not found")
            
            if not encrypted_files:
                raise FileNotFoundError("No encrypted files found in package")
            
            encrypted_file_path = encrypted_files[0]  # Take first encrypted file
            
            # Step 1: Use RSA private key to decrypt the AES key
            with open(encrypted_key_path, 'rb') as f:
                encrypted_aes_key = f.read()
            
            aes_key = self.rsa_encryption.decrypt_aes_key(encrypted_aes_key, private_key_path, password)
            print(f"✓ AES key decrypted with RSA private key")
            
            # Step 2: Use AES key to decrypt the file
            with open(encrypted_file_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Extract IV and ciphertext
            iv = encrypted_data[:16]  # First 16 bytes are IV
            ciphertext = encrypted_data[16:]  # Rest is encrypted data
            
            # Decrypt file content
            decrypted_data = self.decrypt_file_with_aes(iv, ciphertext, aes_key)
            print(f"✓ File decrypted with AES-256-CBC")
            
            # Step 3: Save decrypted file
            decrypted_dir = Path("decrypted_files")
            decrypted_dir.mkdir(exist_ok=True)
            
            original_filename = metadata['original_filename']
            decrypted_file_path = decrypted_dir / original_filename
            
            with open(decrypted_file_path, 'wb') as f:
                f.write(decrypted_data)
            
            print(f"\n✓ Package decrypted successfully!")
            print(f"  Original file: {original_filename}")
            print(f"  Decrypted file: {decrypted_file_path}")
            print(f"  Encryption: AES-{metadata['encryption']['aes_key_size']}-{metadata['encryption']['aes_mode']}")
            print(f"  RSA key size: {metadata['encryption']['rsa_key_size']} bits")
            print(f"  Sender timestamp: {metadata['timestamp']}")
            
            return {
                'decrypted_file': decrypted_file_path,
                'original_filename': original_filename,
                'metadata': metadata
            }
            
        except Exception as e:
            raise Exception(f"Failed to decrypt package: {str(e)}")
    
    def list_packages(self):
        """List all available encrypted packages"""
        try:
            if not self.packages_dir.exists():
                print("No encrypted packages found.")
                return []
            
            packages = [d for d in self.packages_dir.iterdir() if d.is_dir()]
            
            if not packages:
                print("No encrypted packages found.")
                return []
            
            print(f"\n--- Available Encrypted Packages ({len(packages)} total) ---")
            for i, package_dir in enumerate(packages, 1):
                try:
                    metadata_path = package_dir / "metadata.json"
                    if metadata_path.exists():
                        with open(metadata_path, 'r') as f:
                            metadata = json.load(f)
                        
                        print(f"{i:2d}. {package_dir.name}")
                        print(f"     Original file: {metadata.get('original_filename', 'Unknown')}")
                        print(f"     Recipient: {metadata.get('recipient', 'Unknown')}")
                        print(f"     Created: {metadata.get('timestamp', 'Unknown')}")
                        print(f"     Encryption: AES-{metadata.get('encryption', {}).get('aes_key_size', 'Unknown')}")
                        print()
                    else:
                        print(f"{i:2d}. {package_dir.name} (No metadata)")
                        print()
                except Exception:
                    print(f"{i:2d}. {package_dir.name} (Error reading metadata)")
                    print()
            
            return packages
            
        except Exception as e:
            raise Exception(f"Failed to list packages: {str(e)}")

def main():
    """Test and demonstration of complete hybrid encryption system"""
    print("=== 🔒 Hybrid AES+RSA Encryption System ===")
    
    # Initialize components
    key_manager = RSAKeyManager()
    rsa_encryption = RSAEncryption()
    recipient_manager = RecipientManager()
    hybrid_encryption = HybridEncryption()
    
    print("\n🔒 SENDER SIDE Capabilities:")
    print("   1. Generate RSA key pairs")
    print("   2. Add recipients with their public keys")
    print("   3. Generate random AES-256 keys")
    print("   4. Encrypt files with AES-256-CBC")
    print("   5. Encrypt AES keys with recipient's RSA public key")
    print("   6. Package everything (encrypted_file + encrypted_AES_key + metadata)")
    
    print("\n🔓 RECEIVER SIDE Capabilities:")
    print("   1. Use RSA private key to decrypt AES key")
    print("   2. Use decrypted AES key to decrypt file")
    print("   3. Restore original file")
    
    print("\n📦 Package Structure:")
    print("   ├── original_file.txt.encrypted  (AES-encrypted file)")
    print("   ├── encrypted_aes_key.bin        (RSA-encrypted AES key)")
    print("   └── metadata.json                (Encryption details)")
    
    print("\n✨ Security Features:")
    print("   • AES-256-CBC for file encryption")
    print("   • RSA-OAEP-SHA256 for key encryption")
    print("   • Random IV per file")
    print("   • PKCS7 padding")
    print("   • Comprehensive metadata")
    
    print("\nSystem ready for hybrid encryption operations!")

if __name__ == "__main__":
    main()
