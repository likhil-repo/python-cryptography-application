'''
BEFORE USING THIS CRYPTOGRAPHIC TECHNIQUES TO ENCRYPT/DECRYPT THE DATA 
install these requirements
1. crypto
2. pycryptodome

** NOTE :            $$$$$ 
when you are running this program in Android, make sure you must copy this whole program and paste it in a new file and run that file without saving that file
                             $$$$$$


'''

import hashlib
from tkinter import *
from Crypto.Cipher import AES, DES, ARC4
from Crypto.Util.Padding import pad, unpad
import base64

# Encryption Function
def encrypt_text(text, cipher_type, key):
    try:
        if cipher_type == "AES":
            if len(key) != 16:
                return "AES key must be 16 bytes long"
            cipher = AES.new(key.encode(), AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(text.encode())
            return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')
        elif cipher_type == "DES":
            if len(key) != 8:
                return "DES key must be 8 bytes long"
            cipher = DES.new(key.encode(), DES.MODE_CBC, iv=b'\x00' * 8)
            padded_text = pad(text.encode(), DES.block_size)
            ciphertext = cipher.encrypt(padded_text)
            return base64.b64encode(cipher.iv + ciphertext).decode('utf-8')
        elif cipher_type == "ARC4":
            cipher = ARC4.new(key.encode())
            ciphertext = cipher.encrypt(text.encode())
            return base64.b64encode(ciphertext).decode('utf-8')
    except Exception as e:
        return str(e)

# Decryption Function
def decrypt_text(text, cipher_type, key):
    try:
        text = base64.b64decode(text)
        if cipher_type == "AES":
            if len(key) != 16:
                return "AES key must be 16 bytes long"
            nonce = text[:16]
            tag = text[16:32]
            ciphertext = text[32:]
            cipher = AES.new(key.encode(), AES.MODE_EAX, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext.decode('utf-8')
        elif cipher_type == "DES":
            if len(key) != 8:
                return "DES key must be 8 bytes long"
            iv = text[:8]
            ciphertext = text[8:]
            cipher = DES.new(key.encode(), DES.MODE_CBC, iv=iv)
            plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)
            return plaintext.decode('utf-8')
        elif cipher_type == "ARC4":
            cipher = ARC4.new(key.encode())
            plaintext = cipher.decrypt(text)
            return plaintext.decode('utf-8')
    except Exception as e:
        return str(e)

# Process Function (Encryption/Decryption/Hashing)
def process_text():
    text = input_text.get("1.0", END).strip()
    operation_type = operation_choice.get()
    hash_type = hash_choice.get()
    key = key_entry.get()

    if not text:
        output_text.delete("1.0", END)
        output_text.insert(END, "Please enter some text.")
        return

    if operation_type == "Encrypt":
        if hash_type in ["AES", "DES", "ARC4"]:
            if not key:
                processed_text = "Please enter a key for encryption."
            else:
                processed_text = encrypt_text(text, hash_type, key)
        else:
            processed_text = hash_text(text, hash_type)
    elif operation_type == "Decrypt":
        if hash_type in ["AES", "DES", "ARC4"]:
            if not key:
                processed_text = "Please enter a key for decryption."
            else:
                processed_text = decrypt_text(text, hash_type, key)
        else:
            processed_text = "Hashing algorithms cannot be decrypted."

    output_text.delete("1.0", END)
    output_text.insert(END, processed_text)

# Hashing Function
def hash_text(text, hash_type):
    if hash_type == "MD5":
        return hashlib.md5(text.encode()).hexdigest()
    elif hash_type == "SHA1":
        return hashlib.sha1(text.encode()).hexdigest()
    elif hash_type == "SHA224":
        return hashlib.sha224(text.encode()).hexdigest()
    elif hash_type == "SHA256":
        return hashlib.sha256(text.encode()).hexdigest()
    elif hash_type == "SHA384":
        return hashlib.sha384(text.encode()).hexdigest()
    elif hash_type == "SHA512":
        return hashlib.sha512(text.encode()).hexdigest()

# GUI
root = Tk()
root.title("Hash & Encryption/Decryption Tool")

Label(root, text="Input Text").grid(row=0, column=0, padx=10, pady=5)
input_text = Text(root, height=5, width=40)
input_text.grid(row=0, column=1, padx=10, pady=5)

Label(root, text="Operation Type").grid(row=1, column=0, padx=10, pady=5)
operation_choice = StringVar(root)
operation_choice.set("Encrypt")
operation_menu = OptionMenu(root, operation_choice, "Encrypt", "Decrypt")
operation_menu.grid(row=1, column=1, padx=10, pady=5)

Label(root, text="Hash/Encryption Type").grid(row=2, column=0, padx=10, pady=5)
hash_choice = StringVar(root)
hash_choice.set("MD5")
hash_menu = OptionMenu(root, hash_choice, "MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "AES", "DES", "ARC4")
hash_menu.grid(row=2, column=1, padx=10, pady=5)

Label(root, text="Key (For AES/DES/ARC4)").grid(row=3, column=0, padx=10, pady=5)
key_entry = Entry(root, width=40)
key_entry.grid(row=3, column=1, padx=10, pady=5)

Button(root, text="Process Text", command=process_text).grid(row=4, column=1, padx=10, pady=5)

Label(root, text="Output").grid(row=5, column=0, padx=10, pady=5)
output_text = Text(root, height=5, width=40)
output_text.grid(row=5, column=1, padx=10, pady=5)

root.mainloop()
