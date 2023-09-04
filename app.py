import streamlit as st
import hashlib
import string
import random

# Function to generate passwords with digits, letters, and special characters
def generate_passwords():
    characters = string.ascii_letters + string.digits + string.punctuation
    passwords = []
    for length in range(4, 11):
        for _ in range(100):  # Generate 100 random passwords for each length
            password = ''.join([
                random.choice(string.ascii_lowercase),
                random.choice(string.ascii_uppercase),
                random.choice(string.digits),
                random.choice(string.punctuation)
            ] + [random.choice(characters) for _ in range(length - 4)])
            passwords.append(password)
    return passwords

# Function to create a dictionary with hash as key and password as value
def create_password_dictionary(passwords):
    password_dict = {}
    for password in passwords:
        hash_value = hashlib.sha256(password.encode()).hexdigest()
        password_dict[hash_value] = password
    return password_dict

# Function to convert a password to hash
def password_to_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Function to check if a user-provided hash exists in the dictionary
def check_password(hash_value, password_dict):
    if hash_value in password_dict:
        return password_dict[hash_value]
    else:
        return None

# Main Streamlit app
def main():
    st.title("Password Hashing App")
    st.sidebar.header("Options")

    passwords = generate_passwords()
    password_dict = create_password_dictionary(passwords)

    choice = st.sidebar.radio("Choose an option:", ["Convert password to hash", "Check hash against dictionary"])

    if choice == "Convert password to hash":
        st.header("Convert Password to Hash")
        password = st.text_input("Enter a password (4 to 10 characters):")
        if password:
            if len(password) < 4 or len(password) > 10:
                st.error("Invalid password length. Please enter a password between 4 and 10 characters.")
            else:
                hash_value = password_to_hash(password)
                st.success(f"Hash value for the password: {hash_value}")

    elif choice == "Check hash against dictionary":
        st.header("Check Hash Against Dictionary")
        user_hash = st.text_input("Enter a hash to check:")
        if user_hash:
            result = check_password(user_hash, password_dict)
            if result:
                st.success(f"Password for the hash: {result}")
            else:
                st.error("Hash not found in the dictionary.")

if __name__ == "__main__":
    main()
    
