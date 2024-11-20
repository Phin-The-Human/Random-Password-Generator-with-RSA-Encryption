import random as r
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import serialization

# Password generation function
letters = "abcdefghijklmnopqrstuvwxyz"
digits = "0123456789"
special_characters = "!@#$%*^|()_+"

def generate_password(length, upper_case, use_digits, use_special_characters):
    if length <= 0:
        return "Password length must be greater than 0."
    
    character_pool = letters  # Start with lowercase letters

    # Add uppercase letters if required
    if upper_case == "y":
        character_pool += letters.upper()

    # Add digits if required
    if use_digits == "y":
        character_pool += digits

    # Add special characters if required
    if use_special_characters == "y":
        character_pool += special_characters

    if not character_pool:
        return "No characters available to generate password."

    # Generate the password
    password = ''.join(r.choice(character_pool) for _ in range(length))
    return password

# RSA Key Pair Generation
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Encrypt password using RSA
def encrypt_password(password, public_key):
    encrypted = public_key.encrypt(
        password.encode('utf-8'),
        OAEP(
            mgf=MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )
    return encrypted

# Decrypt password using RSA
def decrypt_password(encrypted_password, private_key):
    decrypted = private_key.decrypt(
        encrypted_password,
        OAEP(
            mgf=MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )
    return decrypted.decode('utf-8')

# Main Program
def main():
    private_key, public_key = generate_rsa_keys()  # Generate RSA keys

    while True:
        print("\n         -- Password generator with RSA encryption --    "" \nChoose option:")
        print("1: Generate password")
        print("2: Exit the program")
        choice = int(input("Enter your choice: "))
        if choice == 1:
            length = int(input("Provide password length: "))
            upper_case = input("Use uppercase letters? (y/n): ").lower().strip()
            use_digits = input("Use digits? (y/n): ").lower().strip()
            use_special_characters = input("Use special characters? (y/n): ").lower().strip()
            
            generated_password = generate_password(length, upper_case, use_digits, use_special_characters)
            
            if "Password length" in generated_password or "No characters" in generated_password:
                print(generated_password)
            else:
                print(f"Generated Password: {generated_password}")

                # Encrypt the password
                encrypted_password = encrypt_password(generated_password, public_key)
                print(f"Encrypted Password (RSA): {encrypted_password}")

                # Decrypt the password
                decrypted_password = decrypt_password(encrypted_password, private_key)
                print(f"Decrypted Password: {decrypted_password}")
        elif choice == 2:
            print("Bye!")
            break
        else:
            print("Please enter a correct value!")

if __name__ == "__main__":
    main()
