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
        input_password = st.text_input("Enter a password to check:")
        if hashed_password and input_password:
            if check_password(input_password, hashed_password):
                st.success("Password Match: The input password matches the hashed password.")
            else:
                st.error("Password Mismatch: The input password does not match the hashed password.")

if __name__ == "__main__":
    main()
    
