

import hashlib
import os
from cryptography.hazmat.primitives import hashes, hmac

def CustomHMAC(key: bytes, text: str) -> str:

    """
    Implements HMAC using SHA256 as specified in RFC-2104.

   
    key (bytes): Secret key for HMAC, of any length up to 64 bytes. Longer keys are hashed to fit.

    text (str): The message or data to be authenticated.

    
    str: The HMAC as a hexadecimal string.

    """

    # Constants based on SHA256

    B = 64  # Block size in bytes
    L = 32  # Output size in bytes

    # Ensure key is of appropriate length

    if len(key) > B:

        # If key is longer than B bytes, it's hashed to fit
        key = hashlib.sha256(key).digest()

    elif len(key) < B:

        # If key is shorter, it's padded with zeros to B bytes
        key += bytes(B - len(key))

    # Define ipad and opad

    ipad = bytes([0x36] * B)
    opad = bytes([0x5C] * B)

    # Step 2: XOR key with ipad

    k_ipad = bytes(x ^ y for x, y in zip(key, ipad))

    # Step 3: append the data 'text' to the result from step 2

    step3 = k_ipad + text.encode()

    # Step 4 : apply SHA256 to the result from step 3

    step4 = hashlib.sha256(step3).digest()

    # Step 5:  XOR key with opad

    k_opad = bytes(x ^ y for x, y in zip(key, opad))

    # Step 6 : append the result from step 4 to the result from step 5

    step6 = k_opad + step4

    # Step 7: apply SHA256 to the result from step 6 and return the hex digest

    final_hash = hashlib.sha256(step6).digest()

    return final_hash.hex()



# -- END OF YOUR CODERUNNER SUBMISSION CODE

def HMAC_from_Cryptography(key: bytes, text: str) -> str:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(text.encode())
    signature = h.finalize().hex()

    return signature

# MAIN

if __name__ == "__main__":

    # Generate a random 16-byte key

    k = os.urandom(16)  # Key is <class 'bytes'>
    txt = "hello world!!!!"  # Text to be authenticated

    # Display the custom HMAC result
    print(CustomHMAC(k, txt))


    # Testing and debugging
    key = os.urandom(16)  # Generates a random key
    text = "hello world!!!!"

    # custom HMAC function's result
    custom_hmac_result = CustomHMAC(key, text)

    # Using the provided debugging function
    debug_hmac_result = HMAC_from_Cryptography(key, text)

    # Compare the two results
    print(f"Custom HMAC: {custom_hmac_result}")
    print(f"Debug HMAC:  {debug_hmac_result}")

    # Check if they match
    assert custom_hmac_result == debug_hmac_result, "Mismatch found, debug needed."


