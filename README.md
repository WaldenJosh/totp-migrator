# TOTP Migrator

## Overview

**TOTP Migrator** is a quick and simple tool designed to facilitate the migration of TOTP (Time-based One-Time Password) secrets from an authenticator app to a new app. Some apps provide an option to export TOTP secrets into a JSON file, but many other apps do not support importing this format. This tool decrypts (if needed) the exported secrets and generates QR codes that can be scanned to easily import the accounts into a new authenticator app.

In addition to supporting exports, **TOTP Migrator** is compatible with JSON data generated by [CLIAuthenticator](https://github.com/WaldenJosh/CLIAuthenticator), allowing you to work seamlessly between the two tools.

## Features
- Decrypt and read TOTP secrets from an exported authenticator app JSON file.
- Generate QR codes for each account, making it easy to transfer TOTP secrets to a new authenticator app.
- Cross-compatibility with [CLIAuthenticator](https://github.com/WaldenJosh/CLIAuthenticator), including support for encrypted JSON files created by that tool.
  
## Requirements

- Python 3.x
- `pyotp`
- `qrcode`
- `cryptography`

Install the dependencies using pip:

```bash
pip install pyotp qrcode cryptography
```

## Cross-Compatibility with CLIAuthenticator

If you are using [CLIAuthenticator](https://github.com/WaldenJosh/CLIAuthenticator) to generate TOTP codes from the command line, the `totp-migrator` tool can read the encrypted JSON data exported from CLIAuthenticator. This cross-compatibility ensures that secrets stored and encrypted by CLIAuthenticator can be decrypted and used to generate QR codes for migration purposes.

- Both tools use the same encryption mechanism, allowing seamless transitions between generating TOTP codes in the CLI and migrating them to another app.

## Usage

To use the tool, run the following command:

```bash
python generate_qrcodes.py <json_file_path>
```

### Example:

```bash
python generate_qrcodes.py export.json
```

If the file is encrypted, you will be prompted to enter a password to decrypt the TOTP secrets.

## Output

QR codes will be saved as `.png` files in the `qr_codes/` directory (created automatically if it doesn't exist). Each QR code file will be named according to the format `<Issuer>_<User>.png`.

## Error Handling

- If the JSON file is encrypted but the wrong password is provided, the tool will notify you.
- If no accounts are found in the JSON file, the tool will notify you.

## Notes

- **Security Warning**: If the exported JSON file contains unencrypted TOTP secrets, you will be warned that these secrets are stored in plain text.
- This tool is intended for personal use. Please be cautious when handling TOTP secrets, especially in plain text.

## License

This project is licensed under the MIT License.
```