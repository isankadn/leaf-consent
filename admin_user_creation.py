import bcrypt
import sqlite3
import argparse

def create_admin_user(username, password):
    db_path = 'instance/no_consent.db'  # Replace with the path to your SQLite database file
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt).decode()

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("INSERT INTO user (username, password_hash) VALUES (?, ?)", (username, hashed_password))

    conn.commit()
    conn.close()

    print(f"User {username} created successfully.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Create a new admin user.')
    parser.add_argument('username', help='Username for the new admin user')
    parser.add_argument('password', help='Password for the new admin user')

    args = parser.parse_args()

    create_admin_user(args.username, args.password)
