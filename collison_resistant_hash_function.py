
# Necessary imports for the functionality

from itertools import product  # Used for generating all possible message combinations
import hashlib  # Provides access to SHA-256 hash function


def ds_hash(message: str) -> int:

    hash_value = 0

    for ch in message:

        hash_value = (hash_value * 71) + ord(ch)

    return hash_value & 0x7FFFFFFF

# Function to generate a SHA-256 hash

def sha256_hash(message: str) -> str:

    """
    Generates a SHA-256 hash of the given message.

   
    message (str): The input message to hash.

   
    str: The hexadecimal representation of the SHA-256 hash of the message.
    
    """

    # Convert the message to bytes, required for hashing

    message_bytes = message.encode('utf-8')

    # Create a SHA-256 hash object from the message bytes

    hash_object = hashlib.sha256(message_bytes)

    # Return the hash value in hexadecimal format

    return hash_object.hexdigest()

# Function to test the collision resistance of the custom hash function

def myAttack() -> bool:

    # MY IMPLEMENTATION

    """
    Attempts to find a collision in the custom hash function (ds_hash) to test its collision resistance.
    A collision occurs when two different messages produce the same hash value.

    Returns:

    - bool: True if a collision is found, False otherwise.
    """

    # Store hash values and their corresponding messages to detect collisions
    seen_hashes = {}

    # Define the alphabet used in generating messages

    alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

    # Specify the length of messages to test

    message_length = 64  

    # Generate all possible messages of the specified length

    for message_tuple in product(alphabet, repeat=message_length):

        message = ''.join(message_tuple)

        hash_value = ds_hash(message)  # Hash the message using the custom hash function
        
        # Check if the hash value has already been encountered

        if hash_value in seen_hashes:

            # Collision found: two different messages have the same hash value


            return False  # Return True indicating the hash function is not collision-resistant
        
        else:

            # Store the message and its hash value for future collision checks

            seen_hashes[hash_value] = message

            
    return True



# MAIN
if __name__ == "__main__":

    # Test the collision resistance of the custom hash function

    collision_found = myAttack()

    print("Collision found:", collision_found)

    # Example usage of both hash functions for comparison

    message = "Example message"

    ds_hash_value = ds_hash(message)  # Custom hash function

    sha256_hash_value = sha256_hash(message)  # SHA-256 hash function

    # Display the results for comparison

    print(f"ds_hash result: {ds_hash_value}")
    
    print(f"SHA-256 result: {sha256_hash_value}")
