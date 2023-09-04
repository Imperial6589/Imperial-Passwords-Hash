import streamlit as st
import hashlib

# Function to generate passwords of varying lengths from 4 to 6 digits
def generate_passwords():
    passwords = []
    for length in range(4, 7):
        for i in range(10 ** (length - 1), 10 ** length):
            password = str(i)
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

# Streamlit app
def main():
    st.title("Password Hashing App by:Mohd Altamish")
    st.markdown(
        """
        <style>
        body {
            background-image: url('https://www.pexels.com/photo/view-of-street-from-a-glass-window-531880/');  /* Replace 'background.jpg' with your image file's name */
            background-size: cover;
            background-repeat: no-repeat;
        }
        </style>
        """,
        unsafe_allow_html=True
    )


    passwords = generate_passwords()
    password_dict = create_password_dictionary(passwords)

    choice = st.selectbox("Choose an option:", ["Generate hash for a password", "Enter the hash to know your password"])

    if choice == "Generate hash for a password":
        password = st.text_input("Enter a password (4 to 6 digits): ")
        if password:
            if len(password) < 4 or len(password) > 6:
                st.error("Invalid password length. Please enter a password between 4 and 6 digits.")
            else:
                hash_value = password_to_hash(password)
                st.success(f"Hash value for {password}: {hash_value}")

    elif choice == "Enter the hash to know your password":
        user_hash = st.text_input("Enter a hash to check: ")
        if user_hash:
            result = check_password(user_hash, password_dict)
            if result:
                st.success(f"Password for hash: {result}")
            else:
                st.error("Hash not found in the dictionary.")

if __name__ == "__main__":
    main()
                    
