#!/usr/bin/env python3
"""
AES File Decryption Tool
User-friendly interface for decrypting AES encrypted files
"""

import os
import sys
import getpass
from pathlib import Path
import argparse

# Add current directory to path so we can import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from decryptAPI import AESDecryptionAPI, validate_encrypted_files, get_encryption_info


def get_file_path(prompt: str, file_type: str = "file") -> str:
    """Get file path from user input with validation"""
    while True:
        file_path = input(f"\n{prompt}").strip()
        
        # Remove surrounding quotes if present
        if file_path.startswith('"') and file_path.endswith('"'):
            file_path = file_path[1:-1]
        elif file_path.startswith("'") and file_path.endswith("'"):
            file_path = file_path[1:-1]
        
        if os.path.exists(file_path):
            if os.path.isfile(file_path):
                return file_path
            else:
                print(f"❌ Error: Path exists but is not a file. Please enter a valid {file_type} path.")
        else:
            print(f"❌ Error: {file_type.capitalize()} not found. Please check the path and try again.")


def auto_detect_files(directory: str = None) -> list:
    """Auto-detect encrypted files in a directory"""
    if directory is None:
        directory = os.getcwd()
    
    dir_path = Path(directory)
    encrypted_files = []
    
    # Look for .enc files
    for enc_file in dir_path.glob("*.enc"):
        # Check if corresponding metadata file exists
        base_name = enc_file.stem.replace('_encrypted', '')
        metadata_file = dir_path / f"{base_name}_metadata.json"
        
        if metadata_file.exists():
            encrypted_files.append({
                'encrypted': str(enc_file),
                'metadata': str(metadata_file),
                'base_name': base_name
            })
    
    return encrypted_files


def interactive_mode():
    """Interactive mode for file decryption"""
    print("🔓 AES File Decryption Tool - Interactive Mode")
    print("=" * 60)
    
    while True:
        print("\nChoose an option:")
        print("1. Auto-detect encrypted files in current directory")
        print("2. Auto-detect encrypted files in specific directory")
        print("3. Manually specify file paths")
        print("4. Exit")
        
        choice = input("\nEnter your choice (1-4): ").strip()
        
        if choice == '1':
            # Auto-detect in current directory
            files = auto_detect_files()
            if not files:
                print("❌ No encrypted files found in current directory.")
                continue
            
            print(f"\n📁 Found {len(files)} encrypted file(s):")
            for i, file_info in enumerate(files, 1):
                print(f"   {i}. {file_info['base_name']}")
            
            if len(files) == 1:
                selected = files[0]
            else:
                while True:
                    try:
                        file_num = int(input(f"\nSelect file to decrypt (1-{len(files)}): "))
                        if 1 <= file_num <= len(files):
                            selected = files[file_num - 1]
                            break
                        else:
                            print(f"❌ Please enter a number between 1 and {len(files)}")
                    except ValueError:
                        print("❌ Please enter a valid number")
            
            decrypt_selected_file(selected)
        
        elif choice == '2':
            # Auto-detect in specific directory
            directory = input("\nEnter directory path: ").strip().strip('"')
            if not os.path.exists(directory):
                print("❌ Directory not found.")
                continue
            
            files = auto_detect_files(directory)
            if not files:
                print("❌ No encrypted files found in specified directory.")
                continue
            
            print(f"\n📁 Found {len(files)} encrypted file(s) in {directory}:")
            for i, file_info in enumerate(files, 1):
                print(f"   {i}. {file_info['base_name']}")
            
            if len(files) == 1:
                selected = files[0]
            else:
                while True:
                    try:
                        file_num = int(input(f"\nSelect file to decrypt (1-{len(files)}): "))
                        if 1 <= file_num <= len(files):
                            selected = files[file_num - 1]
                            break
                        else:
                            print(f"❌ Please enter a number between 1 and {len(files)}")
                    except ValueError:
                        print("❌ Please enter a valid number")
            
            decrypt_selected_file(selected)
        
        elif choice == '3':
            # Manual file specification
            encrypted_file = get_file_path("Enter path to encrypted file (.enc): ", "encrypted file")
            metadata_file = get_file_path("Enter path to metadata file (.json): ", "metadata file")
            
            selected = {
                'encrypted': encrypted_file,
                'metadata': metadata_file,
                'base_name': Path(encrypted_file).stem.replace('_encrypted', '')
            }
            
            decrypt_selected_file(selected)
        
        elif choice == '4':
            print("👋 Goodbye!")
            break
        
        else:
            print("❌ Invalid choice. Please enter 1, 2, 3, or 4.")


def decrypt_selected_file(file_info: dict):
    """Decrypt a selected file"""
    encrypted_file = file_info['encrypted']
    metadata_file = file_info['metadata']
    base_name = file_info['base_name']
    
    print(f"\n🔍 Processing: {base_name}")
    print(f"📁 Encrypted file: {encrypted_file}")
    print(f"📋 Metadata file: {metadata_file}")
    
    # Validate files
    print("🔍 Validating files...")
    validation = validate_encrypted_files(encrypted_file, metadata_file)
    
    if not validation['valid']:
        print("❌ File validation failed:")
        for error in validation['errors']:
            print(f"   - {error}")
        return
    
    print(f"✅ Files validated successfully")
    
    # Get encryption info
    try:
        info = get_encryption_info(metadata_file)
        print(f"📊 Encryption type: {info['encryption_type']}")
        print(f"🏷️  Hidden tag: {info['tag']}")
    except Exception as e:
        print(f"⚠️  Could not read encryption info: {e}")
    
    # Get password
    password = getpass.getpass("\n🔑 Enter decryption password: ")
    
    if not password:
        print("❌ No password provided")
        return
    
    # Decrypt file
    try:
        print("🔄 Decrypting file...")
        api = AESDecryptionAPI()
        decrypted_file = api.decrypt_file(encrypted_file, metadata_file, password)
        
        print(f"✅ Decryption successful!")
        print(f"📁 Decrypted file saved: {decrypted_file}")
        
        # Show file info
        file_size = os.path.getsize(decrypted_file)
        print(f"📊 File size: {file_size:,} bytes")
        
        # Ask if user wants to preview content
        preview = input("\n👀 Would you like to preview the content? (y/n): ").lower().strip()
        if preview in ['y', 'yes']:
            preview_file_content(decrypted_file)
            
    except Exception as e:
        print(f"❌ Decryption failed: {e}")
        print(f"💡 Possible causes:")
        print(f"   - Incorrect password")
        print(f"   - Corrupted file")
        print(f"   - Invalid metadata")


def preview_file_content(file_path: str):
    """Preview entire file content if it's text"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            file_size = len(content)
            print(f"\n📖 Complete file content ({file_size:,} characters):")
            print("=" * 60)
            print(content)
            print("=" * 60)
            print(f"📊 Total characters: {file_size:,}")
            print(f"📊 Total lines: {content.count(chr(10)) + 1}")
    except UnicodeDecodeError:
        print(f"📁 File appears to be binary data (not text)")
        print(f"🔍 Try opening with appropriate application")
    except Exception as e:
        print(f"⚠️  Could not preview content: {e}")


def command_line_mode(args):
    """Command line mode for scripted usage"""
    try:
        api = AESDecryptionAPI()
        
        if args.auto and args.base_name:
            # Auto-decrypt mode
            decrypted_file = api.auto_decrypt(args.base_name, args.password, args.directory)
            print(f"✅ Decryption successful: {decrypted_file}")
        
        elif args.encrypted and args.metadata:
            # Manual file mode
            decrypted_file = api.decrypt_file(args.encrypted, args.metadata, args.password)
            print(f"✅ Decryption successful: {decrypted_file}")
        
        else:
            print("❌ Invalid arguments. Use --help for usage information.")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="AES File Decryption Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode
  python decrypt_tool.py
  
  # Auto-decrypt by base name
  python decrypt_tool.py --auto --base-name document --password mypass
  
  # Manual file specification
  python decrypt_tool.py --encrypted file.enc --metadata file.json --password mypass
        """
    )
    
    parser.add_argument('--encrypted', '-e', help='Path to encrypted .enc file')
    parser.add_argument('--metadata', '-m', help='Path to metadata .json file')
    parser.add_argument('--password', '-p', help='Decryption password')
    parser.add_argument('--auto', '-a', action='store_true', help='Auto-decrypt mode')
    parser.add_argument('--base-name', '-b', help='Base filename for auto-decrypt')
    parser.add_argument('--directory', '-d', help='Directory to search in (for auto-decrypt)')
    
    args = parser.parse_args()
    
    # If no arguments provided, run interactive mode
    if len(sys.argv) == 1:
        interactive_mode()
    else:
        # Command line mode
        if not args.password:
            args.password = getpass.getpass("Enter decryption password: ")
        
        command_line_mode(args)


if __name__ == "__main__":
    main()
