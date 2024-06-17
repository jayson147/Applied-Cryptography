

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os



def CustomAESMode(key: bytes, iv: bytes, plaintext: str) -> str:


    # MY IMPLEMENTATION


    """
    Custom AES mode of encryption that uses ECB mode under the hood.

    key (bytes): The encryption key for AES.

    iv (bytes): The initialization vector for the first block of plaintext.

    plaintext (str): The plaintext to be encrypted.

    str: The ciphertext represented as a hex string.

    """


    # Ensure the plaintext is a multiple of 16 bytes, pad 

    padding_length = 16 - (len(plaintext) % 16)
    plaintext_padded = plaintext.encode() + bytes([padding_length] * padding_length)

    # Split the plaintext into blocks of 16 bytes

    plaintext_blocks = [plaintext_padded[i:i+16] for i in range(0, len(plaintext_padded), 16)]

    # Instantiate an AES-ECB encryptor

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    # Initialize variables

    ciphertext = b''
    previous_block = iv

    # Encrypt each block of plaintext

    for block in plaintext_blocks:

        # XOR plaintext block with the previous ciphertext (or IV for the first block)

        block_to_encrypt = bytes([_a ^ _b for _a, _b in zip(block, previous_block)])

        # Encrypt the block and update the previous_block

        encrypted_block = encryptor.update(block_to_encrypt)
        ciphertext += encrypted_block
        previous_block = encrypted_block

    # Finalize the encryption and return the hex representation of the ciphertext
        
    return ciphertext.hex()

# -- END OF YOUR CODERUNNER SUBMISSION CODE


# MAIN
if __name__ == "__main__":
    key = bytes.fromhex("06a9214036b8a15b512e03d534120006")
    iv = bytes.fromhex("3dafba429d9eb430b422da802c9fac41")
    txt = "This is a text"

    # Call the custom AES mode function and print the result
    print(CustomAESMode(key, iv, txt))
