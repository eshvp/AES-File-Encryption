import os
import shutil
import sys
from pathlib import Path

# Add the Encryption directory to Python path to import AES module
sys.path.append(str(Path(__file__).parent.parent / "Encryption"))

try:
    from AES import AESEncryption
except ImportError:
    print("Warning: AES encryption module not found. Encryption functionality will be limited.")

def clean_file_path(file_path):
    """Clean file path by removing quotes and trailing parentheses"""
    if not file_path:
        return file_path
    
    # Strip whitespace
    cleaned = file_path.strip()
    
    # Remove surrounding quotes (both single and double)
    if (cleaned.startswith('"') and cleaned.endswith('"')) or \
       (cleaned.startswith("'") and cleaned.endswith("'")):
        cleaned = cleaned[1:-1]
    
    # Remove trailing parentheses that might be accidentally included
    while cleaned.endswith(')'):
        cleaned = cleaned[:-1].strip()
    
    return cleaned

def upload_file():
    """Upload a file to the system"""
    try:
        file_path = input("Enter the file path to upload: ").strip()
        
        # Clean the file path to remove quotes and trailing parentheses
        cleaned_path = clean_file_path(file_path)
        
        if not cleaned_path:
            print("Error: No file path provided.")
            return False
        
        source_path = Path(cleaned_path)
        
        # Check if file exists
        if not source_path.exists():
            print(f"Error: File '{cleaned_path}' does not exist.")
            return False
        
        # Check if it's actually a file (not a directory)
        if not source_path.is_file():
            print(f"Error: '{cleaned_path}' is not a file.")
            return False
        
        # Create uploaded_files directory if it doesn't exist
        upload_dir = Path("uploaded_files")
        upload_dir.mkdir(exist_ok=True)
        
        # Define destination path
        destination = upload_dir / source_path.name
        
        # Check if file already exists in upload directory
        if destination.exists():
            overwrite = input(f"File '{source_path.name}' already exists in upload directory. Overwrite? (y/n): ").strip().lower()
            if overwrite != 'y' and overwrite != 'yes':
                print("Upload cancelled.")
                return False
        
        # Copy the file
        shutil.copy2(source_path, destination)
        
        print(f"✓ File '{source_path.name}' uploaded successfully to 'uploaded_files/' directory.")
        print(f"  Original: {source_path}")
        print(f"  Uploaded: {destination}")
        
        return True
        
    except Exception as e:
        print(f"Error uploading file: {e}")
        return False

def list_uploaded_files():
    """List all uploaded files"""
    try:
        upload_dir = Path("uploaded_files")
        
        # Check if upload directory exists
        if not upload_dir.exists():
            print("No uploaded files found. Upload directory doesn't exist yet.")
            return
        
        # Get all files in the upload directory
        files = [f for f in upload_dir.iterdir() if f.is_file()]
        
        if not files:
            print("No files have been uploaded yet.")
            return
        
        print(f"\n--- Uploaded Files ({len(files)} total) ---")
        for i, file_path in enumerate(files, 1):
            # Get file size
            file_size = file_path.stat().st_size
            size_str = format_file_size(file_size)
            
            # Get last modified time
            import datetime
            mod_time = datetime.datetime.fromtimestamp(file_path.stat().st_mtime)
            mod_time_str = mod_time.strftime("%Y-%m-%d %H:%M:%S")
            
            # Check if file is encrypted (check if corresponding encrypted file exists)
            encrypted_dir = Path("encrypted_files")
            encrypted_status = "Not Encrypted"
            
            if encrypted_dir.exists():
                # Check for encrypted version of this file (new format without AES type)
                encrypted_file_path = encrypted_dir / f"{file_path.name}.encrypted"
                if encrypted_file_path.exists():
                    encrypted_status = "Encrypted"
            
            print(f"{i:2d}. {file_path.name}")
            print(f"     Size: {size_str}")
            print(f"     Modified: {mod_time_str}")
            print(f"     Status: {encrypted_status}")
            print()
        
    except Exception as e:
        print(f"Error listing uploaded files: {e}")

def list_encrypted_files():
    """List all encrypted files"""
    try:
        encrypted_dir = Path("encrypted_files")
        
        # Check if encrypted directory exists
        if not encrypted_dir.exists():
            print("No encrypted files found. Encrypted directory doesn't exist yet.")
            return
        
        # Get all encrypted files in the directory
        files = [f for f in encrypted_dir.iterdir() if f.is_file() and f.name.endswith('.encrypted')]
        
        if not files:
            print("No files have been encrypted yet.")
            return
        
        print(f"\n--- Encrypted Files ({len(files)} total) ---")
        for i, file_path in enumerate(files, 1):
            # Get file size
            file_size = file_path.stat().st_size
            size_str = format_file_size(file_size)
            
            # Get last modified time
            import datetime
            mod_time = datetime.datetime.fromtimestamp(file_path.stat().st_mtime)
            mod_time_str = mod_time.strftime("%Y-%m-%d %H:%M:%S")
            
            print(f"{i:2d}. {file_path.name}")
            print(f"     Size: {size_str}")
            print(f"     Modified: {mod_time_str}")
            print(f"     Status: Encrypted")
            print()
        
    except Exception as e:
        print(f"Error listing encrypted files: {e}")

def format_file_size(size_bytes):
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    import math
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_names[i]}"

def delete_file():
    """Delete a file from the uploaded files directory"""
    try:
        upload_dir = Path("uploaded_files")
        
        # Check if upload directory exists
        if not upload_dir.exists():
            print("No uploaded files found. Upload directory doesn't exist yet.")
            return
        
        # Get all files in the upload directory
        files = [f for f in upload_dir.iterdir() if f.is_file()]
        
        if not files:
            print("No files have been uploaded yet.")
            return
        
        # Display files with numbers
        print(f"\n--- Uploaded Files ({len(files)} total) ---")
        for i, file_path in enumerate(files, 1):
            print(f"{i:2d}. {file_path.name}")
        
        # Get user choice
        while True:
            try:
                choice = input(f"\nEnter the number of the file to delete (1-{len(files)}) or 'q' to quit: ").strip().lower()
                
                if choice == 'q' or choice == 'quit':
                    print("Delete cancelled.")
                    return
                
                file_index = int(choice) - 1
                
                if 0 <= file_index < len(files):
                    selected_file = files[file_index]
                    
                    # Confirm deletion
                    confirm = input(f"Are you sure you want to delete '{selected_file.name}'? (y/n): ").strip().lower()
                    
                    if confirm == 'y' or confirm == 'yes':
                        selected_file.unlink()  # Delete the file
                        print(f"✓ File '{selected_file.name}' has been deleted successfully.")
                    else:
                        print("Delete cancelled.")
                    break
                else:
                    print(f"Invalid choice. Please enter a number between 1 and {len(files)}.")
                    
            except ValueError:
                print("Invalid input. Please enter a number or 'q' to quit.")
        
    except Exception as e:
        print(f"Error deleting file: {e}")

def encrypt_files():
    """Encrypt uploaded files"""
    try:
        # Check if AES module is available
        if 'AESEncryption' not in globals():
            print("Error: AES encryption module not available.")
            print("Please ensure the AES.py file exists in the Encryption directory.")
            return
        
        # Create AES encryption instance and run encryption
        aes_encryptor = AESEncryption()
        aes_encryptor.encrypt_uploaded_files()
        
    except Exception as e:
        print(f"Error during encryption: {e}")

def decrypt_file():
    """Decrypt an encrypted file"""
    # Logic to be implemented
    print("Decrypt file functionality - Coming soon...")
    pass

def exit_program():
    """Exit the program"""
    print("Goodbye!")
    exit()

def main():
    """Main program loop with menu options"""
    while True:
        print("\n=== File Encryption Manager ===")
        print("1. Upload File")
        print("2. List Uploaded Files")
        print("3. List Encrypted Files")
        print("4. Encrypt Files")
        print("5. Decrypt File")
        print("6. Delete File")
        print("7. Exit")
        
        choice = input("\nEnter your choice (1-7): ").strip()
        
        if choice == '1':
            upload_file()
        elif choice == '2':
            list_uploaded_files()
        elif choice == '3':
            list_encrypted_files()
        elif choice == '4':
            encrypt_files()
        elif choice == '5':
            decrypt_file()
        elif choice == '6':
            delete_file()
        elif choice == '7':
            exit_program()
        else:
            print("Invalid choice. Please select 1-7.")

if __name__ == "__main__":
    main()
