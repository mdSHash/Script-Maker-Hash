import re
import hashlib
from concurrent.futures import ThreadPoolExecutor

def detect_hash_type(encoded_hash):
    # Define regex patterns for different hash types
    md5_pattern = r'^[a-f0-9]{32}$'
    sha1_pattern = r'^[a-f0-9]{40}$'
    sha256_pattern = r'^[a-f0-9]{64}$'
    sha512_pattern = r'^[a-f0-9]{128}$'

    # Check the hash against each pattern to determine its type
    if re.match(md5_pattern, encoded_hash):
        hash_type = "MD5"
    elif re.match(sha1_pattern, encoded_hash):
        hash_type = "SHA1"
    elif re.match(sha256_pattern, encoded_hash):
        hash_type = "SHA256"
    elif re.match(sha512_pattern, encoded_hash):
        hash_type = "SHA512"
    else:
        hash_type = "Unknown"

    return hash_type

def crack_hash(passwords, encoded_hash, hash_type):
    # Try each password in the list until a match is found
    for password in passwords:
        if hash_type == "MD5":
            if hashlib.md5(password.encode()).hexdigest() == encoded_hash:
                return password
        elif hash_type == "SHA1":
            if hashlib.sha1(password.encode()).hexdigest() == encoded_hash:
                return password
        elif hash_type == "SHA256":
            if hashlib.sha256(password.encode()).hexdigest() == encoded_hash:
                return password
        elif hash_type == "SHA512":
            if hashlib.sha512(password.encode()).hexdigest() == encoded_hash:
                return password

    return None

def decrypt_hash(encoded_hash, hash_type):
    try:
        # Load list of common passwords into a list for faster lookup
        with open('word_list.txt') as f:
            passwords = [line.strip() for line in f]
    except FileNotFoundError:
        print("Error: Word list file not found")
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None

    # Split the password list into chunks for parallel processing
    CHUNK_SIZE = 10000
    chunks = [passwords[i:i+CHUNK_SIZE] for i in range(0, len(passwords), CHUNK_SIZE)]

    # Use multiple threads to search for the hash in parallel
    with ThreadPoolExecutor() as executor:
        results = [executor.submit(crack_hash, chunk, encoded_hash, hash_type) for chunk in chunks]

        for future in results:
            password = future.result()
            if password is not None:
                return password

    return None

def add_word_to_list(word):
    try:
        # Encrypt the word to a hash
        md5_hash = hashlib.md5(word.encode()).hexdigest()

        # Open word list file for appending
        with open('word_list.txt', 'a+') as f:
            # Check if the word is already in the file
            f.seek(0)
            if word in f.read():
                print(f"'{word}' is already in the word list file")
            else:
                # Add the word and its hash to the file
                f.write(f"{word}\n")
                print(f"Added '{word}' with MD5 hash '{md5_hash}' to the word list file")

            # Update the last_file_size attribute
            add_word_to_list.last_file_size = f.tell()

    except Exception as e:
        print(f"Error: {e}")

# Set initial file size for word list file
add_word_to_list.last_file_size = 0

if __name__ == '__main__':
    print("Welcome to the Script Maker Hash v1.0")
    print("Author : Script Maker")
    while True:
        # Prompt user for input
        mode = input("Enter '1' to create a hash, '2' to decrypt a hash, '3' to add a word to the word list file, or 'q' to quit: ")
        if mode not in ['1', '2', '3', 'q']:
            print("Invalid input")
            continue
        elif mode == 'q':
            break

        # Create a hash
        if mode == '1':
            while True:
                hash_type = input("Enter the hash type (MD5, SHA1, SHA256, or SHA512): ").upper()
                if hash_type not in ['MD5', 'SHA1', 'SHA256', 'SHA512']:
                    print("Invalid input")
                    continue
                else:
                    break

            word = input("Enter the word to hash: ")
            if hash_type == "MD5":
                hashed_word = hashlib.md5(word.encode()).hexdigest()
            elif hash_type == "SHA1":
               hashed_word = hashlib.sha1(word.encode()).hexdigest()
            elif hash_type == "SHA256":
                hashed_word = hashlib.sha256(word.encode()).hexdigest()
            elif hash_type == "SHA512":
                hashed_word = hashlib.sha512(word.encode()).hexdigest()
            # Save word to word list file
            with open('word_list.txt', 'a') as f:
                f.write(f"{word}\n")
            print(f"The hash of '{word}' using {hash_type} is: {hashed_word}")

        # Decrypt a hash
        elif mode == '2':
            encoded_hash = input("Enter the encoded hash: ")
            hash_type = detect_hash_type(encoded_hash)
            if hash_type == "Unknown":
                print("Error: Unable to determine the hash type")
            else:
                password = decrypt_hash(encoded_hash, hash_type)
                if password is None:
                    print("Password not found")
                else:
                    print(f"The password for hash '{encoded_hash}' is: {password}")

        # Add a word to the word list file
        elif mode == '3':
            word = input("Enter the word to add: ")
            add_word_to_list(word)
            while True:
                choice = input("Would you like to add another word? (Y/N): ").upper()
                if choice not in ['Y', 'N']:
                    print("Invalid input")
                    continue
                elif choice == 'Y':
                    word = input("Enter the word to add: ")
                    add_word_to_list(word)
                else:
                    break

    print("Thank you for using Script Maker Hash v1.0")
