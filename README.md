##  Password Cracking Toolkit

##  Overview

This project is a **GUI-based Password Cracking Tool** developed using Python and Tkinter. It supports multiple password cracking techniques like **Wordlist Attack** and **Rainbow Table Attack** to recover hashed passwords.

---

##  Features

* Wordlist-based password cracking
* Rainbow table lookup
* User-friendly GUI (Tkinter)
* File input support (hash + wordlist)
* Multi-threaded execution
* Real-time output display
* Dark-themed interface

---

## Technologies Used

* Python
* Tkinter (GUI)
* hashlib
* JSON
* PIL (Image handling)
* threading

---

## How It Works

### 1. Wordlist Attack

* Loads hash file
* Loads password wordlist
* Compares hashed words with input hashes
* Displays cracked passwords

### 2. Rainbow Table Attack

* Loads precomputed hash-password table
* Matches input hash
* Returns original password if found

---

##  Project Structure

```
project/
│── main.py
│── assets/
│   └── bg.png
│── data/
│   └── rainbow_table.json
│── sample_hashes.txt
│── wordlist.txt
```

---

##  Installation

```bash id="install123"
pip install pillow
```

---

##  Run the Application

```bash id="run123"
python main.py
```

---

##  Input Requirements

* **Hash File** → `.txt` (one hash per line)
* **Wordlist File** → `.txt` (one password per line)
* **Rainbow Table** → JSON format

---

##  Supported Hash Types

* MD5
* SHA-256
* SHA-512 (Rainbow Table dependent)

---

##  Future Enhancements

* Brute-force attack module
* GPU acceleration
* Larger rainbow tables
* Hash type auto-detection
* Web-based interface

---

##  Disclaimer

This tool is developed **for educational purposes only**. Do not use it for illegal activities.

---

## Author

Chamarathi Harika
B.Tech – CSE (Data Science)
