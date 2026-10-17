from getpass import getpass
from secrets import token_urlsafe

from pwdlib import PasswordHash

MIN_PASSWORD_LENGTH = 8


def main():
    while True:
        password = getpass(
            f"Choose administrator password "
            f"(minimum {MIN_PASSWORD_LENGTH} characters): "
        )

        if len(password) < MIN_PASSWORD_LENGTH:
            print("Password must contain at least 8 characters.\n")
            continue

        confirmation = getpass("Enter the password again: ")

        if password != confirmation:
            print("Passwords do not match. Please try again.\n")
            continue

        break

    password_hash = PasswordHash.recommended().hash(password)

    print("\nCopy these settings into your .env file:\n")
    print("ADMIN_USERNAME=admin")
    print(f"ADMIN_PASSWORD_HASH='{password_hash}'")
    print(f"SESSION_SECRET={token_urlsafe(48)}")
    print("APP_ORIGIN=http://127.0.0.1:8000")
    print("COOKIE_SECURE=false")


if __name__ == "__main__":
    main()