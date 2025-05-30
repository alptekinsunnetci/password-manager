# Password Manager

A secure, modular password manager written in Go with SQLite database backend.

## Features

- ✅ **Secure Encryption**: AES-256-GCM encryption with PBKDF2 key derivation
- ✅ **Password Generation**: Customizable password generation with strength validation
- ✅ **SQLite Database**: Local database storage
- ✅ **Modular Architecture**: Clean, maintainable code structure
- ✅ **CLI Interface**: Easy-to-use command-line interface
- ✅ **Search Functionality**: Search passwords by service, username, or URL
- ✅ **Password Strength Analysis**: Validate password strength

## Installation

1. Clone the repository:
```bash
git clone https://github.com/alptekinsunnetci/password-manager.git
cd password-manager
```

2. Install dependencies:
```bash
go mod download
```

3. Build the application:
```bash
go build -o password-manager cmd/main.go
```

## Usage

Run the application:
```bash
./password-manager
```

Follow the CLI prompts to:
- Add new passwords
- Retrieve existing passwords
- Generate secure passwords
- Search and manage your password vault

## Security

- Passwords are encrypted using AES-256-GCM
- Master password is used for key derivation with PBKDF2
- Encrypted passwords are stored in local SQLite database
- Passwords are never displayed in plain text in list/search views
