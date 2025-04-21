import os
import zlib
import base64
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class SecureZip:
    """A class that handles compression and encryption of text files."""
    
    def __init__(self, password=None):
        """Initialize the SecureZip with an optional password."""
        if password is None:
            self.password = getpass.getpass("Enter password for encryption/decryption: ").encode()
        else:
            self.password = password.encode()
        self.ext = ".seczip"
        
    def _derive_key(self, salt):
        """Derive a key from the password and salt using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 32 bytes = 256 bits for AES-256
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(self.password)
    
    def _encrypt(self, data):
        """Encrypt the data using AES-256 in GCM mode."""
        # Generate a random salt and IV
        salt = os.urandom(16)
        iv = os.urandom(12)  # 12 bytes for GCM mode
        
        # Derive key from password and salt
        key = self._derive_key(salt)
        
        # Create an encryptor object
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Encrypt the data
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        
        # Return the salt, IV, tag and encrypted data
        return salt + iv + encryptor.tag + encrypted_data
    
    def _decrypt(self, data):
        """Decrypt the data using AES-256 in GCM mode."""
        # Extract salt, IV, tag and encrypted data
        salt = data[:16]
        iv = data[16:28]
        tag = data[28:44]
        encrypted_data = data[44:]
        
        # Derive key from password and salt
        key = self._derive_key(salt)
        
        # Create a decryptor object
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt the data
        try:
            return decryptor.update(encrypted_data) + decryptor.finalize()
        except Exception as e:
            print(f"Decryption failed. Incorrect password or corrupted file: {e}")
            return None
    
    def compress_and_encrypt(self, input_file, output_file=None):
        """Compress and encrypt a file."""
        # If no output file is specified, use the input file name with the seczip extension
        if output_file is None:
            output_file = input_file + self.ext
        
        try:
            # Read the input file
            with open(input_file, 'rb') as f:
                data = f.read()
            
            # Compress the data
            compressed_data = zlib.compress(data)
            
            # Encrypt the compressed data
            encrypted_data = self._encrypt(compressed_data)
            
            # Write the encrypted data to the output file
            with open(output_file, 'wb') as f:
                f.write(encrypted_data)
            
            print(f"File compressed and encrypted successfully: {output_file}")
            print(f"Original size: {len(data)} bytes")
            print(f"Compressed size: {len(compressed_data)} bytes")
            print(f"Compressed and encrypted size: {len(encrypted_data)} bytes")
            print(f"Compression ratio: {len(data) / len(compressed_data):.2f}x")
            
            return output_file
        
        except Exception as e:
            print(f"Error compressing and encrypting file: {e}")
            return None
    
    def decrypt_and_decompress(self, input_file, output_file=None):
        """Decrypt and decompress a file."""
        # If no output file is specified, use the input file name without the seczip extension
        if output_file is None:
            if input_file.endswith(self.ext):
                output_file = input_file[:-len(self.ext)]
            else:
                output_file = input_file + ".decoded"
        
        try:
            # Read the input file
            with open(input_file, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt the data
            compressed_data = self._decrypt(encrypted_data)
            if compressed_data is None:
                return None
            
            # Decompress the data
            data = zlib.decompress(compressed_data)
            
            # Write the decrypted and decompressed data to the output file
            with open(output_file, 'wb') as f:
                f.write(data)
            
            print(f"File decrypted and decompressed successfully: {output_file}")
            print(f"Encrypted and compressed size: {len(encrypted_data)} bytes")
            print(f"Compressed size: {len(compressed_data)} bytes")
            print(f"Decompressed size: {len(data)} bytes")
            
            return output_file
        
        except Exception as e:
            print(f"Error decrypting and decompressing file: {e}")
            return None


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Secure Zip - Compress and encrypt text files.')
    parser.add_argument('action', choices=['compress', 'decompress'], help='Action to perform')
    parser.add_argument('input_file', help='Input file path')
    parser.add_argument('-o', '--output', help='Output file path (optional)')
    parser.add_argument('-p', '--password', help='Password for encryption/decryption (optional, will prompt if not provided)')
    
    args = parser.parse_args()
    
    secure_zip = SecureZip(args.password)
    
    if args.action == 'compress':
        secure_zip.compress_and_encrypt(args.input_file, args.output)
    else:  # decompress
        secure_zip.decrypt_and_decompress(args.input_file, args.output)


if __name__ == "__main__":
    main() 