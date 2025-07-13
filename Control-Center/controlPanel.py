import os
import sys
from pathlib import Path

# Add the necessary directories to Python path
current_dir = Path(__file__).parent
sys.path.append(str(current_dir.parent / "Encryption"))
sys.path.append(str(current_dir.parent / "Upload"))

try:
    # Import main module functions that already have their own menus
    from upload import main as upload_main
    from AES import main as aes_main
    from AESDecrypt import main as aes_decrypt_main
    from RSA import main as rsa_main, HybridEncryption, RSAKeyManager, RecipientManager
except ImportError as e:
    print(f"Warning: Failed to import required modules: {e}")
    print("Please ensure all encryption modules are available.")

class EncryptionControlPanel:
    """Lightweight control panel that delegates to existing modules"""
    
    def __init__(self):
        # Initialize only what we need for hybrid operations
        try:
            self.hybrid_encryption = HybridEncryption()
            self.rsa_key_manager = RSAKeyManager()
            self.recipient_manager = RecipientManager()
            print("✓ Control Panel initialized successfully")
        except Exception as e:
            print(f"✗ Error initializing control panel: {e}")
            self.components_available = False
            return
        
        self.components_available = True
    
    def display_main_menu(self):
        """Display the main control panel menu"""
        print("\n" + "="*60)
        print("🔐 ENCRYPTION CONTROL PANEL")
        print("="*60)
        print("📁 FILE MANAGEMENT:")
        print("  1. File Manager (Upload/List/Delete)")
        print()
        print("🔒 ENCRYPTION:")
        print("  2. AES Encryption Menu")
        print("  3. AES Decryption Menu")
        print("  4. RSA & Hybrid Encryption Menu")
        print()
        print("🔒🔑 QUICK HYBRID OPERATIONS:")
        print("  5. Encrypt File for Recipient")
        print("  6. Decrypt Package")
        print("  7. List Encrypted Packages")
        print()
        print("ℹ️  SYSTEM:")
        print("  8. System Status")
        print("  9. Help")
        print("  10. Exit")
        print("="*60)
    
    # DELEGATE TO EXISTING MODULES
    def handle_file_manager(self):
        """Delegate to upload.py main menu"""
        try:
            print("\n🔄 Launching File Manager...")
            upload_main()
        except Exception as e:
            print(f"Error launching file manager: {e}")
    
    def handle_aes_encryption(self):
        """Delegate to AES.py main menu"""
        try:
            print("\n🔄 Launching AES Encryption...")
            aes_main()
        except Exception as e:
            print(f"Error launching AES encryption: {e}")
    
    def handle_aes_decryption(self):
        """Delegate to AESDecrypt.py main menu"""
        try:
            print("\n🔄 Launching AES Decryption...")
            aes_decrypt_main()
        except Exception as e:
            print(f"Error launching AES decryption: {e}")
    
    def handle_rsa_hybrid(self):
        """Delegate to RSA.py main menu"""
        try:
            print("\n🔄 Launching RSA & Hybrid Menu...")
            rsa_main()
        except Exception as e:
            print(f"Error launching RSA menu: {e}")
    
    # HYBRID ENCRYPTION FUNCTIONS (Keep these lightweight)
    def handle_quick_hybrid_encrypt(self):
        """Quick hybrid encryption for recipient"""
        try:
            if not self.components_available:
                print("✗ Error: System components not available.")
                return
            
            # List uploaded files
            upload_dir = Path("uploaded_files")
            if not upload_dir.exists():
                print("No uploaded files found. Use File Manager (option 1) to upload files first.")
                return
            
            files = [f for f in upload_dir.iterdir() if f.is_file()]
            if not files:
                print("No uploaded files found. Use File Manager (option 1) to upload files first.")
                return
            
            print("\n--- Quick Hybrid Encryption ---")
            print(f"Available files ({len(files)} total):")
            for i, file_path in enumerate(files, 1):
                file_size = file_path.stat().st_size
                size_str = self.format_file_size(file_size)
                print(f"{i:2d}. {file_path.name} ({size_str})")
            
            # Select file
            file_choice = input(f"\nSelect file to encrypt (1-{len(files)}): ").strip()
            try:
                file_index = int(file_choice) - 1
                if not (0 <= file_index < len(files)):
                    print("Invalid file selection.")
                    return
                selected_file = files[file_index]
            except ValueError:
                print("Invalid input.")
                return
            
            # List recipients
            recipients = self.recipient_manager.load_recipients()
            if not recipients:
                print("No recipients found. Use RSA Menu (option 4) to add recipients first.")
                return
            
            recipient_names = list(recipients.keys())
            print(f"\nAvailable recipients ({len(recipient_names)} total):")
            for i, name in enumerate(recipient_names, 1):
                print(f"{i:2d}. {name} ({recipients[name]['email']})")
            
            # Select recipient
            recipient_choice = input(f"\nSelect recipient (1-{len(recipient_names)}): ").strip()
            try:
                recipient_index = int(recipient_choice) - 1
                if not (0 <= recipient_index < len(recipient_names)):
                    print("Invalid recipient selection.")
                    return
                selected_recipient = recipient_names[recipient_index]
            except ValueError:
                print("Invalid input.")
                return
            
            # Perform hybrid encryption
            print(f"\nEncrypting '{selected_file.name}' for '{selected_recipient}'...")
            result = self.hybrid_encryption.encrypt_file_for_recipient(selected_file, selected_recipient)
            
        except Exception as e:
            print(f"Error during hybrid encryption: {e}")
    
    def handle_quick_hybrid_decrypt(self):
        """Quick hybrid decryption"""
        try:
            if not self.components_available:
                print("✗ Error: System components not available.")
                return
                
            packages = self.hybrid_encryption.list_packages()
            if not packages:
                return
            
            print("\n--- Quick Package Decryption ---")
            
            # Select package
            package_choice = input(f"Select package to decrypt (1-{len(packages)}) or 'q' to quit: ").strip()
            
            if package_choice.lower() == 'q':
                return
            
            try:
                package_index = int(package_choice) - 1
                if not (0 <= package_index < len(packages)):
                    print("Invalid package selection.")
                    return
                selected_package = packages[package_index]
            except ValueError:
                print("Invalid input.")
                return
            
            # List available private keys
            key_pairs = self.rsa_key_manager.list_key_pairs()
            if not key_pairs:
                print("No RSA private keys found. Use RSA Menu (option 4) to generate keys first.")
                return
            
            print(f"\nAvailable private keys ({len(key_pairs)} total):")
            for i, key_pair in enumerate(key_pairs, 1):
                print(f"{i:2d}. {key_pair['name']}")
            
            # Select private key
            key_choice = input(f"Select private key (1-{len(key_pairs)}): ").strip()
            try:
                key_index = int(key_choice) - 1
                if not (0 <= key_index < len(key_pairs)):
                    print("Invalid key selection.")
                    return
                selected_private_key = key_pairs[key_index]['private_key']
            except ValueError:
                print("Invalid input.")
                return
            
            # Get password if needed
            password = input("Enter private key password (press Enter if none): ").strip()
            password = password if password else None
            
            # Perform decryption
            print(f"\nDecrypting package '{selected_package.name}'...")
            result = self.hybrid_encryption.decrypt_package_with_private_key(
                selected_package, selected_private_key, password
            )
            
        except Exception as e:
            print(f"Error during hybrid decryption: {e}")
    
    def handle_list_packages(self):
        """List encrypted packages"""
        try:
            if not self.components_available:
                print("✗ Error: System components not available.")
                return
            self.hybrid_encryption.list_packages()
        except Exception as e:
            print(f"Error listing packages: {e}")
    
    def format_file_size(self, size_bytes):
        """Format file size in human readable format"""
        if size_bytes == 0:
            return "0 B"
        
        size_names = ["B", "KB", "MB", "GB", "TB"]
        import math
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        return f"{s} {size_names[i]}"
    
    # SYSTEM FUNCTIONS
    def handle_system_status(self):
        """Display lightweight system status"""
        print("\n--- System Status ---")
        
        # Check directories
        directories = {
            "uploaded_files": "Uploaded Files",
            "encrypted_files": "AES Encrypted Files", 
            "decrypted_files": "Decrypted Files",
            "rsa_keys": "RSA Keys",
            "recipients": "Recipients",
            "encrypted_packages": "Hybrid Packages"
        }
        
        print("📁 Directories:")
        for dir_name, display_name in directories.items():
            dir_path = Path(dir_name)
            if dir_path.exists():
                file_count = len([f for f in dir_path.iterdir() if f.is_file()])
                folder_count = len([f for f in dir_path.iterdir() if f.is_dir()])
                print(f"  ✓ {display_name}: {file_count} files, {folder_count} folders")
            else:
                print(f"  ✗ {display_name}: Not found")
        
        print(f"\n🎯 Control Panel: {'✓ Ready' if self.components_available else '✗ Issues'}")
    
    def handle_help(self):
        """Display help information"""
        print("\n--- Help & Information ---")
        print("🔐 ENCRYPTION CONTROL PANEL")
        print()
        print("This control panel coordinates all encryption modules:")
        print()
        print("📝 QUICK START:")
        print("  1. Use 'File Manager' to upload files")
        print("  2. Use 'RSA Menu' to generate keys and add recipients")
        print("  3. Use 'Quick Hybrid' to encrypt for recipients")
        print("  4. Recipients use 'Decrypt Package' to decrypt")
        print()
        print("� MODULE DELEGATION:")
        print("  • File Manager → upload.py menu")
        print("  • AES Encryption → AES.py menu")
        print("  • AES Decryption → AESDecrypt.py menu")
        print("  • RSA & Hybrid → RSA.py menu")
        print()
        print("⚡ EFFICIENCY:")
        print("  • Each module has its own interface")
        print("  • Control panel provides quick access")
        print("  • No duplication of functionality")
    
    def run(self):
        """Main control panel loop"""
        print("🔐 Welcome to the Encryption Control Panel!")
        print("   A lightweight hub for all encryption operations")
        
        if not self.components_available:
            print("⚠️  Warning: Some components are not available.")
        
        while True:
            try:
                self.display_main_menu()
                choice = input("\nEnter your choice (1-10): ").strip()
                
                if choice == '1':
                    self.handle_file_manager()
                elif choice == '2':
                    self.handle_aes_encryption()
                elif choice == '3':
                    self.handle_aes_decryption()
                elif choice == '4':
                    self.handle_rsa_hybrid()
                elif choice == '5':
                    self.handle_quick_hybrid_encrypt()
                elif choice == '6':
                    self.handle_quick_hybrid_decrypt()
                elif choice == '7':
                    self.handle_list_packages()
                elif choice == '8':
                    self.handle_system_status()
                elif choice == '9':
                    self.handle_help()
                elif choice == '10':
                    print("\n👋 Thank you for using the Encryption Control Panel!")
                    print("Stay secure! 🔐")
                    break
                else:
                    print("Invalid choice. Please select 1-10.")
                
                # Pause before showing menu again
                if choice != '10':
                    input("\nPress Enter to continue...")
                
            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"Unexpected error: {e}")
                input("Press Enter to continue...")

def main():
    """Main entry point"""
    try:
        # Change to the script's directory for proper relative paths
        script_dir = Path(__file__).parent.parent
        os.chdir(script_dir)
        
        # Initialize and run control panel
        control_panel = EncryptionControlPanel()
        control_panel.run()
        
    except Exception as e:
        print(f"Critical error: {e}")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()
