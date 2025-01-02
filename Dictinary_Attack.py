import os
import time
import hashlib
from concurrent.futures import ThreadPoolExecutor

def load_dictionary(file_path): 
    """Load passwords from a dictionary file.""" 
    try: 
        with open(file_path, 'r') as file: 
            return [line.strip() for line in file.readlines()] 
    except FileNotFoundError: 
        print(f"Dictionary file not found at: {file_path}") 
        return [] 

def hash_password(password, algorithm="md5"):
    """Hash a password using the specified algorithm."""
    try:
        hash_obj = hashlib.new(algorithm)
        hash_obj.update(password.encode())
        return hash_obj.hexdigest()
    except ValueError:
        raise ValueError(f"Unsupported hashing algorithm: {algorithm}")

def attempt_password(attempt, user_password, case_sensitive, hashed, algorithm, results):
    """Attempt to match the password."""
    if hashed:
        attempt_hash = hash_password(attempt, algorithm)
        match = attempt_hash == user_password
    else:
        match = attempt == user_password if case_sensitive else attempt.lower() == user_password.lower()
    
    if match:
        results.append(attempt)

def dictionary_attack(dictionary, user_password, case_sensitive=True, hashed=False, algorithm="md5", log_file="attempts.log"):
    """Simulate a dictionary attack with advanced features."""
    start_time = time.time()
    attempts = 0
    results = []

    with open(log_file, "w") as log, ThreadPoolExecutor() as executor:
        futures = []
        for attempt in dictionary:
            attempts += 1
            futures.append(executor.submit(attempt_password, attempt, user_password, case_sensitive, hashed, algorithm, results))
            log.write(f"{attempt}\n")
        
        for future in futures:
            future.result()

    end_time = time.time()

    if results:
        return f"Password found: {results[0]} (Attempts: {attempts}, Time: {end_time - start_time:.2f} seconds)"
    else:
        return f"Password not found in the dictionary. (Attempts: {attempts}, Time: {end_time - start_time:.2f} seconds)"

if __name__ == "__main__": 
    # Hardcoded dictionary file path
    dictionary_file = "IS/password.txt"
    
    if not os.path.exists(dictionary_file):
        print(f"Error: File not found at {dictionary_file}")
    else:
        password_list = load_dictionary(dictionary_file)
        
        if password_list:
            user_password = input("Enter the password to test against the dictionary: ").strip()
            mode = input("Do you want to match plain text or hashed passwords? (plain/hashed): ").strip().lower()

            if mode == "hashed":
                hash_algorithm = input("Enter the hash algorithm (e.g., md5, sha256): ").strip()
                user_password = input(f"Enter the hashed password ({hash_algorithm}): ").strip()
                case_sensitive = False  # Case sensitivity irrelevant for hashed mode
                result = dictionary_attack(password_list, user_password, case_sensitive, hashed=True, algorithm=hash_algorithm)
            else:
                case_sensitive = input("Should the search be case-sensitive? (yes/no): ").strip().lower() in ['yes', 'y']
                result = dictionary_attack(password_list, user_password, case_sensitive)

            print(result)
