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
    st.markdown(
        """
        <style>
        /* Add your custom CSS styles here */
        body {
            font-family: Arial, sans-serif;
            background-color: #f5f5f5;
        }
        .stApp {
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background-color: #fff;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        .st-h1 {
            font-size: 32px;
            margin-bottom: 20px;
        }
        .st-sidebar {
            background-color: #333;
            color: #fff;
            padding: 20px;
            border-radius: 10px;
        }
        .st-selectbox {
            width: 100%;
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 5px;
        }
        .st-text-input {
            width: 100%;
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 5px;
        }
        .st-button {
            background-color: #0072b8;
            color: #fff;
            border: none;
            border-radius: 5px;
            padding: 10px 20px;
            cursor: pointer;
        }
        .st-button:hover {
            background-color: #005a9d;
        }
        .st-success {
            color: #008000;
        }
        .st-error {
            color: #ff0000;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    st.title("Password Hashing App by Mohd Altamish")
    st.markdown('<div class="stApp">', unsafe_allow_html=True)

    st.sidebar.markdown('<div class="st-sidebar">', unsafe_allow_html=True)
    st.sidebar.header("Menu")

    menu_options = ["Generate hash for a password", "Enter the hash to know your password"]
    choice = st.sidebar.selectbox("Choose an option:", menu_options)

    if choice == "Generate hash for a password":
        st.subheader("Generate Hash")
        password = st.text_input("Enter a password (4 to 6 digits):", type="password")
        if password:
            if len(password) < 4 or len(password) > 6:
                st.error("Invalid password length. Please enter a password between 4 and 6 digits.")
            else:
                hash_value = password_to_hash(password)
                st.success(f"Hash value for {password}: {hash_value}")

    elif choice == "Enter the hash to know your password":
        st.subheader("Check Password")
        user_hash = st.text_input("Enter a hash to check:")
        if user_hash:
            result = check_password(user_hash, password_dict)
            if result:
                st.success(f"Password for hash {user_hash}: {result}")
            else:
                st.error("Hash not found in the dictionary.")

    st.markdown("</div>", unsafe_allow_html=True)

if __name__ == "__main__":
    passwords = generate_passwords()
    password_dict = create_password_dictionary(passwords)
    main()
                          
