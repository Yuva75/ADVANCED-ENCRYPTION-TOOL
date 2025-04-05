import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

def generate_key():
    return os.urandom(32)

def save_key(key, filepath):
    with open(filepath, 'wb') as f:
        f.write(base64.b64encode(key))

def load_key(filepath):
    with open(filepath, 'rb') as f:
        return base64.b64decode(f.read())

def pad(data):
    padding_len = 16 - (len(data) % 16)
    return data + bytes([padding_len] * padding_len)

def unpad(data):
    padding_len = data[-1]
    return data[:-padding_len]

def encrypt_file(input_file, output_file, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(input_file, 'rb') as f:
        plaintext = f.read()

    padded = pad(plaintext)
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    with open(output_file, 'wb') as f:
        f.write(iv + ciphertext)

def decrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpad(padded_plaintext)

    with open(output_file, 'wb') as f:
        f.write(plaintext)

# GUI
def encrypt_action():
    input_file = filedialog.askopenfilename(title="Select file to encrypt")
    output_file = filedialog.asksaveasfilename(title="Save encrypted file as")
    key_file = filedialog.asksaveasfilename(title="Save key file as")

    if not input_file or not output_file or not key_file:
        return

    key = generate_key()
    save_key(key, key_file)
    encrypt_file(input_file, output_file, key)
    messagebox.showinfo("Success", f"File encrypted.\nKey saved to: {key_file}")

def decrypt_action():
    input_file = filedialog.askopenfilename(title="Select file to decrypt")
    output_file = filedialog.asksaveasfilename(title="Save decrypted file as")
    key_file = filedialog.askopenfilename(title="Select key file")


    if not input_file or not output_file or not key_file:
        return

    key = load_key(key_file)
    decrypt_file(input_file, output_file, key)
    messagebox.showinfo("Success", "File decrypted.")

    def load_key(filepath):
     try:
        with open(filepath, 'rb') as f:
            data = f.read()
            return base64.b64decode(data)
     except (base64.binascii.Error, ValueError) as e:
        messagebox.showerror("Key Error", "Invalid key file selected. Please choose the correct key used during encryption.")
        raise

# App UI
app = tk.Tk()
app.title("AES-256 File Encryptor")
app.geometry("300x200")

tk.Label(app, text="AES-256 File Encryption Tool", font=("Helvetica", 14)).pack(pady=20)
tk.Button(app, text="Encrypt File", command=encrypt_action, width=20).pack(pady=5)
tk.Button(app, text="Decrypt File", command=decrypt_action, width=20).pack(pady=5)
tk.Button(app, text="Exit", command=app.quit, width=20).pack(pady=20)

app.mainloop()
