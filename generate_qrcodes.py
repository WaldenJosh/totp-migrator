import json
import sys
import pyotp
import qrcode
import getpass
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
import hashlib
import os

def generate_key_from_password(password):
    """Generate a key for encryption/decryption from a password."""
    key = hashlib.sha256(password.encode()).digest()
    return urlsafe_b64encode(key)


def decrypt_seeds(data, password):
    """Decrypt the 'secret' field for each account in the JSON data using the provided password."""
    key = generate_key_from_password(password)
    fernet = Fernet(key)

    for account in data.get("accounts", []):
        if 'secret' in account and account['secret']:
            account['secret'] = fernet.decrypt(
                account['secret'].encode()).decode()

    data['encrypted'] = False
    return data


def generate_qr_codes(json_path, output_dir='qr_codes'):
    try:
        with open(json_path, 'r') as json_file:
            data = json.load(json_file)

        if data.get('encrypted', False):
            password = getpass.getpass("Enter decryption password: ")
            try:
                data = decrypt_seeds(data, password)
            except Exception as e:
                print(f"Error decrypting seeds: {e}")
                return
        else:
            print("Warning: The seeds are stored in plain text and are unprotected.")

        accounts = data.get("accounts", [])
        if not accounts:
            print("No TOTP accounts found in the JSON file.")
            return

        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)

        for account in accounts:
            secret = account.get('secret', '').replace(' ', '')
            issuer = account.get('issuerName', 'UnknownIssuer')
            user = account.get('userName', 'UnknownUser')
            
            # Create TOTP URI for QR code
            totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=user, issuer_name=issuer)
            
            # Generate QR code
            img = qrcode.make(totp_uri)
            
            # Save QR code image
            img_path = os.path.join(output_dir, f"{issuer}_{user}.png")
            img.save(img_path)
            print(f"QR code for {issuer} ({user}) saved to {img_path}.")

    except FileNotFoundError:
        print(f"Error: The file {json_path} was not found.")
    except json.JSONDecodeError:
        print(f"Error: Failed to parse JSON from the file {json_path}.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python generate_qrcodes.py <json_file_path>")
    else:
        json_file_path = sys.argv[1]
        generate_qr_codes(json_file_path)
