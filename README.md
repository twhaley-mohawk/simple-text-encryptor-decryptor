# simple-text-encryptor-decryptor

A simple text encryption/decryption tool by Taylor Whaley for Python for Networking class in 2024. Uses fernet from [cryptography](https://pypi.org/project/cryptography/) to perform this. GUI implemented using [gooey](https://github.com/chriskiehl/Gooey). Developed on Python 3.10.12.

How to Setup
-------------

Clone this project to your local directory
	
	git clone https://github.com/twhaley-mohawk/simple-text-encryptor-decryptor
	
Create and activate a virtual environment (Optional, but recommended)

	python3 -m venv envName
	source envName/bin/activate # On windows use envName\Scripts\activate
	
Install the required packages

	pip install -r requirements.txt
	
Then simply run with Python and you'll be presented with a simple GUI
	
	python3 ./sted.py # On windows you don't need to specify python3
	
Usage Notes
-------------
This project supports basic encryption/decryption using a 32-byte base64 encoded private key. If you don't have a private key already, you can quickly create one.
