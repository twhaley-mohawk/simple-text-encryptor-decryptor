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
    parser_encrypt.add_argument('--in', type=str, help='Input file to encrypt', required=True)
    parser_encrypt.add_argument('--out', type=str, help='Output file after encryption is performed', required=True)
    parser_encrypt.add_argument('--key', type=str, help="Private key to use for encryption. If you don't have one yet, use the keygen mode first", required=True)
    #Decryption mode arguments - we need an input, an output, and a key.
    parser_decrypt = subparsers.add_parser('decrypt', help='Decrypt an encrypted file')
    parser_decrypt.add_argument('--in', type=str, help='Input file to decrypt', required=True)
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
    print(args)

def decrypt_file(args):
    print(args)

def generate_new_key(args):
    try:
        outputFile = args.out
        #If a file by the name of the key already exists, get confirmation before overwriting it.
        if os.path.exists(outputFile):
            proceed_choice = ""
            proceed_choices = ["yes", "y", "no", "n"]
            while proceed_choice not in proceed_choices:
                proceed_choice = input(f"A file at {outputFile} already exists - is it ok to overwrite it? (yes/no): ").strip().lower()
            if proceed_choice in ["yes", "y"]:
                print(f"Received confirmation to proceed. Overwriting file at {outputFile} with new key...")
                write_key_file(outputFile)
            else:
                print("Key generation cancelled.")
                sys.exit(1) #Exit with error code because we didn't get the key generated
        else:
            write_key_file(outputFile)
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

if __name__ == "__main__":
    try:
        parse_arguments_and_select_mode()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)