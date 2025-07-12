import os
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import secrets

class AESEncryption:
    def __init__(self):
        self.upload_dir = Path("uploaded_files")
        self.encrypted_dir = Path("encrypted_files")
        self.encrypted_dir.mkdir(exist_ok=True)
        
    def get_key_size_choice(self):
        """Get user's choice for AES key size"""
        print("\nSelect AES encryption strength:")
        print("1. AES-128 (16 bytes key) - Fast, good security")
        print("2. AES-192 (24 bytes key) - Balanced security and performance")
        print("3. AES-256 (32 bytes key) - Maximum security, slower")
        
        while True:
            choice = input("\nEnter your choice (1-3): ").strip()
            
            if choice == '1':
                return 128, 16
            elif choice == '2':
                return 192, 24
            elif choice == '3':
                return 256, 32
            else:
                print("Invalid choice. Please select 1, 2, or 3.")
    
    def get_hidden_tag(self, key_size_bits):
        """Get hidden tag based on encryption key size"""
        if key_size_bits == 128:
            return "(h1k789)"
        elif key_size_bits == 192:
            return "(GP94GF)"
        elif key_size_bits == 256:
            return "(k913h923)"
        else:
            return "(unknown)"
    
    def derive_key(self, password, salt, key_length):
        """Derive encryption key from password using PBKDF2"""
        # Use PBKDF2 with SHA-256 for key derivation
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, key_length)
    
    def encrypt_file(self, file_path, password, key_size_bits, key_length):
        """Encrypt a single file using AES encryption"""
        try:
            # Generate random salt and IV
            salt = secrets.token_bytes(16)  # 16-byte salt
            iv = secrets.token_bytes(16)    # 16-byte IV for AES
            
            # Derive key from password
            key = self.derive_key(password, salt, key_length)
            
            # Read the file
            with open(file_path, 'rb') as f:
                plaintext = f.read()
            
            # Pad the plaintext to be multiple of 16 bytes (AES block size)
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext)
            padded_data += padder.finalize()
            
            # Create cipher and encrypt
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            # Create encrypted filename (without encryption type)
            original_name = Path(file_path).name
            encrypted_filename = f"{original_name}.encrypted"
            encrypted_path = self.encrypted_dir / encrypted_filename
            
            # Get hidden tag based on key size
            hidden_tag = self.get_hidden_tag(key_size_bits)
            
            # Write encrypted file (hidden_tag + salt + iv + ciphertext)
            with open(encrypted_path, 'wb') as f:
                f.write(hidden_tag.encode('utf-8'))  # Hidden tag (first bytes)
                f.write(salt)      # Next 16 bytes: salt
                f.write(iv)        # Next 16 bytes: IV
                f.write(ciphertext) # Rest: encrypted data
            
            return encrypted_path, original_name
            
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")
    
    def get_uploaded_files(self):
        """Get list of uploaded files"""
        if not self.upload_dir.exists():
            return []
        
        return [f for f in self.upload_dir.iterdir() if f.is_file()]
    
    def encrypt_uploaded_files(self):
        """Main function to encrypt uploaded files"""
        try:
            # Check if there are uploaded files
            files = self.get_uploaded_files()
            
            if not files:
                print("No uploaded files found to encrypt.")
                return
            
            # Display available files
            print(f"\n--- Available Files for Encryption ({len(files)} total) ---")
            for i, file_path in enumerate(files, 1):
                print(f"{i:2d}. {file_path.name}")
            
            # Get user choice for file selection
            while True:
                try:
                    choice = input(f"\nEnter file number to encrypt (1-{len(files)}) or 'all' for all files: ").strip().lower()
                    
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
            
            # Get encryption settings
            key_size_bits, key_length = self.get_key_size_choice()
            
            # Get password
            while True:
                password = input("\nEnter encryption password: ").strip()
                if len(password) >= 8:
                    confirm_password = input("Confirm password: ").strip()
                    if password == confirm_password:
                        break
                    else:
                        print("Passwords don't match. Please try again.")
                else:
                    print("Password must be at least 8 characters long.")
            
            # Encrypt selected files
            print(f"\nEncrypting files with AES-{key_size_bits}...")
            encrypted_count = 0
            
            for file_path in selected_files:
                try:
                    encrypted_path, original_name = self.encrypt_file(
                        file_path, password, key_size_bits, key_length
                    )
                    
                    # Delete the original file after successful encryption
                    file_path.unlink()
                    
                    print(f"✓ {original_name} → {encrypted_path.name} (original deleted)")
                    encrypted_count += 1
                    
                except Exception as e:
                    print(f"✗ Failed to encrypt {file_path.name}: {str(e)}")
            
            print(f"\nEncryption completed! {encrypted_count}/{len(selected_files)} files encrypted successfully.")
            print(f"Encrypted files saved to: {self.encrypted_dir}")
            print("Original files have been securely deleted.")
            
        except Exception as e:
            print(f"Error during encryption process: {str(e)}")

def main():
    """Main function for testing AES encryption"""
    aes = AESEncryption()
    aes.encrypt_uploaded_files()

if __name__ == "__main__":
    main()
