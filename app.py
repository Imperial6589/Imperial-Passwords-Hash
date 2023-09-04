import streamlit as st
import bcrypt

# Function to hash a password
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password

# Function to check if a password matches its hash
def check_password(input_password, hashed_password):
    return bcrypt.checkpw(input_password.encode(), hashed_password)

# Function to create a dictionary with hash as key and password as value
def create_password_dictionary(passwords):
    password_dict = {}
    for password in passwords:
        hashed_password = hash_password(password)
        password_dict[hashed_password.decode()] = password  # Convert bytes to string
    return password_dict

# Main Streamlit app
def main():
    st.title("Password Hashing App")
    st.sidebar.header("Options")

    choice = st.sidebar.radio("Choose an option:", ["Hash a password", "Check a password"])

    if choice == "Hash a password":
        st.header("Hash a Password")
        password = st.text_input("Enter a password:")
        if password:
            hashed_password = hash_password(password)
            st.success(f"Hashed Password: {hashed_password}")

    elif choice == "Check a password":
        st.header("Check a Password")
        hashed_password = st.text_input("Enter a hashed password:")
        if hashed_password:
            st.info("Note: This functionality requires access to the original password, which is not typical in practice.")
            input_hash = st.text_input("Enter a hash to find the password:")
            
            # Create a dictionary with hash as key and password as value
            passwords = ["password1", "password2", "password3"]  # Replace with your list of passwords
            password_dict = create_password_dictionary(passwords)

            if input_hash:
                if input_hash in password_dict:
                    st.success(f"Password for the hash: {password_dict[input_hash]}")
                else:
                    st.error("Hash not found in the dictionary.")

if __name__ == "__main__":
    main()
                                                         
