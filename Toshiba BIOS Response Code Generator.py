"""
Toshiba BIOS Response Code Generator

Copyright (c) 2024 [ABDULRAHMAN MUHAMMAD 'TFD']

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import hashlib
import re
import uuid
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def get_serial_number():
    """Retrieve the serial number of the Toshiba laptop."""
    # Add code here to retrieve the serial number from the system
    # For testing purposes, let's generate a UUID as a serial number
    return str(uuid.uuid1())

def validate_challenge_code(challenge_code):
    """Validate the format of the challenge code."""
    # Challenge code format regex pattern
    pattern = r'^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$'
    return re.match(pattern, challenge_code)

def generate_response_code(serial_number, challenge_code):
    """Generate a response code based on the serial number and challenge code."""
    # Check if the challenge code format is valid
    if not validate_challenge_code(challenge_code):
        print("Invalid challenge code format.")
        return None

    # Concatenate the serial number and challenge code
    combined_data = serial_number + challenge_code

    # Pad the combined data
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(combined_data.encode()) + padder.finalize()

    # Generate a key and IV for AES encryption
    key = hashlib.sha256(serial_number.encode()).digest()[:32]
    iv = hashlib.sha256(challenge_code.encode()).digest()[:16]

    # Encrypt the padded data using AES encryption in ECB mode
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Encode the encrypted data using hexadecimal
    response_code = encrypted_data.hex()

    # Take the first 25 characters of the response code
    response_code = response_code[:25]

    # Format the response code with dashes every 5 characters
    formatted_response_code = '-'.join(response_code[i:i+5] for i in range(0, len(response_code), 5))

    return formatted_response_code.upper()  # Convert to uppercase

def main():
    """Main function to generate response code."""
    # Retrieve the serial number of the Toshiba laptop
    serial_number = input("Enter PC serial number: ")

    challenge_code = input("Enter challenge code : ")  # Input challenge code

    # Generate response code
    response_code = generate_response_code(serial_number, challenge_code)

    if response_code:
        # Display the generated response code
        print("Generated Response Code:", response_code)

if __name__ == "__main__":
    main()


