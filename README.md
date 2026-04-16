

# 🔐 Password Fortress

A modern password analysis tool that evaluates password strength, detects breaches, and simulates real-world attack scenarios through an interactive web interface.

---

## 🚀 Features

* **Real-time password analysis**
* **Breach detection** using Have I Been Pwned
* **Strength estimation** powered by zxcvbn
* **Attack simulation**

  * Estimated guesses
  * Crack time (fast vs realistic scenarios)
* **Secure password generator**
* **Pattern detection**

  * Repeated characters
  * Sequential numbers
  * Keyboard patterns
* **Clipboard support**
* **Clean dark UI with responsive layout**

---

## 🧱 Tech Stack

* Python (Flask)
* HTML / CSS / JavaScript
* zxcvbn
* Have I Been Pwned

---

## 📦 Installation

```bash
git clone https://github.com/Sajid1105/Password-Checker-EH.git
cd Password-Checker-EH

pip install flask requests zxcvbn-python
```

---

## ▶️ Usage

### Run the web application

```bash
python app.py
```

Open in browser:

```
http://127.0.0.1:5000
```

---

### Optional: CLI / Desktop Mode

```bash
python password_manager.py
```

---

## ⚙️ How It Works

1. Password is analyzed locally using zxcvbn for strength and entropy.
2. A SHA-1 hash is generated.
3. Only the first 5 characters of the hash are sent to the HIBP API (k-anonymity model).
4. Remaining hash comparison is done locally.
5. Results include:

   * Strength score
   * Breach count
   * Pattern issues
   * Crack time estimates

---

## 📁 Project Structure

```bash
.
├── app.py
├── password_manager.py
├── templates/
│   └── index.html
├── static/
│   ├── style.css
│   └── script.js
```

---

## 🔐 Security Notes

* Passwords are never transmitted in full
* Uses k-anonymity for breach queries
* No password storage
* Secure random generation for passwords

---

## 📌 Future Improvements

* User accounts and encrypted storage
* Rate limiting for API requests
* Offline breach dataset support
* Deployment-ready configuration

---
