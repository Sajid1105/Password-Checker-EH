
# Password Fortress 🔒

A secure password manager with GUI and CLI interfaces for password strength analysis, generation, and breach checking.

## Features 🛡️

- **Real-Time Strength Analysis** with visual feedback
- **Breach Checking** via HaveIBeenPwned API
- **Smart Password Generation** with options for:
  - Random complex passwords
  - Memorable passphrases
- **Pattern Detection** for common vulnerabilities:
  - Sequential numbers
  - Keyboard patterns
  - Repeated characters
- **Cross-Platform Support** (Windows/Linux/macOS)
- **Clipboard Security** with auto-clear functionality
- **Batch Processing** for multiple passwords
- **Export Results** in JSON/CSV formats

## Installation 💻

### Requirements
- Python 3.8+
- Tkinter (usually included with Python)

```bash
# Clone repository
git clone https://github.com/Sajid1105/Password-Checker-EH.git
cd Password-Checker-EH

# Install dependencies
pip install zxcvbn-python requests
OR 
python -m pip install requests zxcvbn rich

# For Linux users (if Tkinter missing):
sudo apt-get install python3-tk
```

## Usage 🚀

### GUI Mode
```bash
python password_manager.py
```
- Enter password to analyze in real-time
- Generate new passwords with one click
- Toggle password visibility
- Export analysis reports

### CLI Mode
```bash
# Check password strength
python password_manager.py --check "YourPassword123!"

# Generate random password
python password_manager.py --generate --length 20

# Generate passphrase
python password_manager.py --generate --passphrase

# Batch process passwords from file
python password_manager.py --batch passwords.txt --format csv
```

## Security Features 🔐

- SHA-1 hashing with k-anonymity for breach checks
- SystemSecure random number generation
- Automatic clipboard clearing (30s timeout)
- Banned password list filtering
- Complexity requirements enforcement

## Dependencies 📦

- `zxcvbn-python`: Password strength estimation
- `requests`: API communication
- `tkinter`: GUI components

