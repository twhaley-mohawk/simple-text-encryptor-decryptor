import cryptography
from cryptography.fernet import Fernet
import argparse
import os
import sys

def parse_arguments_and_select_mode():
    parser = argparse.ArgumentParser(
        description='A simple text encryptor/decryptor script by Taylor Whaley for Python for Networking course, 2024',
        epilog="Note: See '<command> --help' to read how to use a specific mode."
        )
    #The user has to select a mode so we know what arguments to require.
    subparsers = parser.add_subparsers(dest='mode', help='Mode to use - encrypt a file, decrypt a previously encrypted file, or generate a new key to use for encryption', required=True)
    #Encryption mode arguments - we need an input, an output, and a key.
    parser_encrypt = subparsers.add_parser('encrypt', help='Encrypt an unencrypted file')
    parser_encrypt.add_argument('--in', type=str, dest='inputFile', help='Input file to encrypt', required=True)
    parser_encrypt.add_argument('--out', type=str, help='Output file after encryption is performed', required=True)
    parser_encrypt.add_argument('--key', type=str, help="Private key to use for encryption. If you don't have one yet, use the keygen mode first", required=True)
    #Decryption mode arguments - we need an input, an output, and a key.
    parser_decrypt = subparsers.add_parser('decrypt', help='Decrypt an encrypted file')
    parser_decrypt.add_argument('--in', type=str, dest='inputFile', help='Input file to decrypt', required=True)
    parser_decrypt.add_argument('--out', type=str, help='Output file after decryption is performed', required=True)
    parser_decrypt.add_argument('--key', type=str, help="Private key to use for decryption. This must be the same key that was used for encryption", required=True)
    #Key generation mode arguments - We don't need anything, except an output file target if they want to specify one. Otherwise, we'll use a default location.
    parser_keygen = subparsers.add_parser('keygen', help='Generate a key file to use for encryption')
    parser_keygen.add_argument('--out', type=str, help='Where to store the key after creation. (default: private.key)', default='private.key')
    #Parse the given arguments and select the appropriate mode
    args = parser.parse_args()
    modes = {
        'encrypt': encrypt_file,
        'decrypt': decrypt_file,
        'keygen': generate_new_key,
    }
    if args.mode in modes:
        mode_function = modes[args.mode]
        mode_function(args)
    else:
        print(f"Unknown mode: {args.mode}")
        parser.print_help()

def encrypt_file(args):
    try:
        inputFile = args.inputFile #We use inputFile for this because "in" is a reserved word
        outputFile = args.out
        keyFile = args.key
        key = read_file(keyFile)
        key = Fernet(key)
        unencrypted_file = read_file(inputFile)
        if check_if_output_file_exists(outputFile):
            encryptedData = key.encrypt(unencrypted_file)
            write_output_file(outputFile,encryptedData)
            print(f"Encrypted contents written to {outputFile}")
        else:
            print("File encryption cancelled.")
            sys.exit(1)
    except Exception as e:
        print("Error while trying to encrypt file: ")
        print(e)

def decrypt_file(args):
    try:
        inputFile = args.inputFile #We use inputFile for this because "in" is a reserved word
        outputFile = args.out
        keyFile = args.key
        key = read_file(keyFile)
        key = Fernet(key)
        encrypted_file = read_file(inputFile)
        if check_if_output_file_exists(outputFile):
            unencryptedData = key.decrypt(encrypted_file)
            write_output_file(outputFile,unencryptedData)
            print(f"Decrypted contents written to {outputFile}")
        else:
            print("File encryption cancelled.")
            sys.exit(1)
    except Exception as e:
        print("Error while trying to decrypt file: ")
        print(e)
    
    
    print(args)

def check_if_output_file_exists(outputFile):
    #Here we check if the output file the user specified already exists or not. If it doesn't exist, all good, we can write.
    #If it does already exist, the user must confirm before we proceed, so we are sure not to accidentally overwrite something important.
    if os.path.exists(outputFile):
        proceed_choice = ""
        proceed_choices = ["yes", "y", "no", "n"]
        while proceed_choice not in proceed_choices:
            proceed_choice = input(f"A file at {outputFile} already exists - is it ok to overwrite it? (yes/no): ").strip().lower()
        if proceed_choice in ["yes", "y"]:
            print(f"Received confirmation to proceed. Overwriting file at {outputFile} with new key...")
            return True
        else:
            return False
    else:
        return True
        
def generate_new_key(args):
    try:
        outputFile = args.out
        #If a file by the name of the key already exists, get confirmation before overwriting it.
        if check_if_output_file_exists(outputFile):
            write_key_file(outputFile)
        else:
            print("Key generation cancelled.")
            sys.exit(1) #Exit with error code because we didn't get the key generated
    except Exception as e:
        print(e)

def write_key_file(outputFile):
    try:
        with open (outputFile, 'wb') as keyFile:
            key = Fernet.generate_key()
            keyFile.write(key)
        print(f"New private key created at {outputFile}")
    except PermissionError as e:
        print(e)
        print("This error typically occurs if the file specified in --out already exists but is a folder, not a file, thus it cannot be overwritten.")

def write_output_file(outputFile, content):
    try:
        with open (outputFile, 'wb') as output:
            output.write(content)
    except Exception as e:
        print(e)

def read_file(filePath, binary=True):
    #With this function we can read files in binary or regular mode as desired.
    mode = 'rb' if binary else 'r'
    try:
        with open(filePath, mode) as file:
            content = file.read()
            return content
    except Exception as e:
        print(f"Error while reading file from {filePath}:")
        print(e)
        sys.exit(1)

def read_key_file(keyFile):
    #Deprecated, remove once read_file is thoroughly tested
    try:
        with open (keyFile, 'rb') as file:
            key = file.read()
            return key
    except Exception as e:
        print("Error while reading the key file:")
        print(e)
        sys.exit(1)
        
if __name__ == "__main__":
    try:
        parse_arguments_and_select_mode()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)