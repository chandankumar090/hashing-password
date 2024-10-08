import bcrypt


# Function to hash a password
def hash_password(password: str) -> str:
    # Generate a salt
    salt = bcrypt.gensalt()
    # Hash the password
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')


# Function to check if a password matches the hash
def check_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


# Simple demo app
if __name__ == "__main__":
    print("1. Register")
    print("2. Login")

    choice = input("Choose an option (1 or 2): ")

    if choice == '1':
        # Register: hash a new password
        password = input("Enter a new password: ")
        hashed_password = hash_password(password)
        print(f"Your hashed password is: {hashed_password}")

        # In real apps, you would store this hashed password in a database
        with open("hashed_password.txt", "w") as file:
            file.write(hashed_password)
        print("Password saved successfully!")

    elif choice == '2':
        # Login: verify password
        password = input("Enter your password: ")

        try:
            with open("hashed_password.txt", "r") as file:
                stored_hashed_password = file.read().strip()

            if check_password(password, stored_hashed_password):
                print("Login successful!")
            else:
                print("Invalid password!")

        except FileNotFoundError:
            print("No password found. Please register first.")

    else:
        print("Invalid option selected!")
