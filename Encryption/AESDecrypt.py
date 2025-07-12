import os
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

class AESDecryption:
    def __init__(self):
        self.encrypted_dir = Path("encrypted_files")
        self.decrypted_dir = Path("decrypted_files")
        self.decrypted_dir.mkdir(exist_ok=True)
        
        # Hidden tags mapping
        self.hidden_tags = {
            "(h1k789)": (128, 16),   # AES-128
            "(GP94GF)": (192, 24),   # AES-192
            "(k913h923)": (256, 32)  # AES-256
        }
    
    def detect_encryption_type(self, file_path):
        """Detect encryption type from hidden tag in file"""
        try:
            with open(file_path, 'rb') as f:
                # Read first 10 bytes to check for hidden tags
                header = f.read(10).decode('utf-8', errors='ignore')
                
                for tag, (key_size_bits, key_length) in self.hidden_tags.items():
                    if header.startswith(tag):
                        return key_size_bits, key_length, len(tag.encode('utf-8'))
                
                # If no tag found, assume legacy format or unknown
                return None, None, 0
                
        except Exception as e:
            raise Exception(f"Failed to detect encryption type: {str(e)}")
    
    def derive_key(self, password, salt, key_length):
        """Derive decryption key from password using PBKDF2"""
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, key_length)
    
    def decrypt_file(self, file_path, password):
        """Decrypt a single file using AES decryption"""
        try:
            # Detect encryption type from hidden tag
            key_size_bits, key_length, tag_length = self.detect_encryption_type(file_path)
            
            if key_size_bits is None:
                raise Exception("Unable to detect encryption type. File may be corrupted or use unsupported format.")
            
            # Read the encrypted file
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Extract components (skip hidden tag)
            tag_length = tag_length
            salt = data[tag_length:tag_length + 16]         # 16 bytes salt
            iv = data[tag_length + 16:tag_length + 32]      # 16 bytes IV
            ciphertext = data[tag_length + 32:]             # Rest is encrypted data
            
            # Derive key from password
            key = self.derive_key(password, salt, key_length)
            
            # Create cipher and decrypt
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove padding
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext)
            plaintext += unpadder.finalize()
            
            # Create decrypted filename (remove .encrypted extension)
            original_name = Path(file_path).name
            if original_name.endswith('.encrypted'):
                decrypted_filename = original_name[:-10]  # Remove '.encrypted'
            else:
                decrypted_filename = f"{original_name}.decrypted"
            
            decrypted_path = self.decrypted_dir / decrypted_filename
            
            # Write decrypted file
            with open(decrypted_path, 'wb') as f:
                f.write(plaintext)
            
            return decrypted_path, original_name, key_size_bits
            
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")
    
    def get_encrypted_files(self):
        """Get list of encrypted files"""
        if not self.encrypted_dir.exists():
            return []
        
        return [f for f in self.encrypted_dir.iterdir() if f.is_file() and f.name.endswith('.encrypted')]
    
    def decrypt_encrypted_files(self):
        """Main function to decrypt encrypted files"""
        try:
            # Check if there are encrypted files
            files = self.get_encrypted_files()
            
            if not files:
                print("No encrypted files found to decrypt.")
                return
            
            # Display available files
            print(f"\n--- Available Files for Decryption ({len(files)} total) ---")
            for i, file_path in enumerate(files, 1):
                # Try to detect encryption type for display
                try:
                    key_size_bits, _, _ = self.detect_encryption_type(file_path)
                    encryption_info = f"AES-{key_size_bits}" if key_size_bits else "Unknown"
                except:
                    encryption_info = "Unknown"
                
                print(f"{i:2d}. {file_path.name} ({encryption_info})")
            
            # Get user choice for file selection
            while True:
                try:
                    choice = input(f"\nEnter file number to decrypt (1-{len(files)}) or 'all' for all files: ").strip().lower()
                    
                    if choice == 'all':
                        selected_files = files
                        break
                    else:
                        file_index = int(choice) - 1
                        if 0 <= file_index < len(files):
                            selected_files = [files[file_index]]
                            break
                        else:
                            print(f"Invalid choice. Please enter a number between 1 and {len(files)} or 'all'.")
                except ValueError:
                    print("Invalid input. Please enter a number or 'all'.")
            
            # Get password
            password = input("\nEnter decryption password: ").strip()
            
            # Decrypt selected files
            print(f"\nDecrypting files...")
            decrypted_count = 0
            
            for file_path in selected_files:
                try:
                    decrypted_path, original_name, key_size_bits = self.decrypt_file(
                        file_path, password
                    )
                    
                    print(f"✓ {original_name} → {decrypted_path.name} (AES-{key_size_bits})")
                    decrypted_count += 1
                    
                except Exception as e:
                    print(f"✗ Failed to decrypt {file_path.name}: {str(e)}")
            
            print(f"\nDecryption completed! {decrypted_count}/{len(selected_files)} files decrypted successfully.")
            print(f"Decrypted files saved to: {self.decrypted_dir}")
            
        except Exception as e:
            print(f"Error during decryption process: {str(e)}")

def main():
    """Main function for testing AES decryption"""
    aes_decrypt = AESDecryption()
    aes_decrypt.decrypt_encrypted_files()

if __name__ == "__main__":
    main()
