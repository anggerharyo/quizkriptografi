import tkinter as tk
from tkinter import filedialog, messagebox
import numpy as np
import string

# Vigenere Cipher Implementation
def vigenere_encrypt(plaintext, key):
    ciphertext = ""
    key = key.upper()
    key_length = len(key)
    for i, letter in enumerate(plaintext):
        if letter.isalpha():
            shift = ord(key[i % key_length]) - ord('A')
            encrypted_letter = chr((ord(letter.upper()) - ord('A') + shift) % 26 + ord('A'))
            ciphertext += encrypted_letter
        else:
            ciphertext += letter
    return ciphertext

def vigenere_decrypt(ciphertext, key):
    plaintext = ""
    key = key.upper()
    key_length = len(key)
    for i, letter in enumerate(ciphertext):
        if letter.isalpha():
            shift = ord(key[i % key_length]) - ord('A')
            decrypted_letter = chr((ord(letter.upper()) - ord('A') - shift) % 26 + ord('A'))
            plaintext += decrypted_letter
        else:
            plaintext += letter
    return plaintext

# Playfair Cipher Implementation
def generate_playfair_matrix(key):
    key = key.upper().replace('J', 'I')  # Replace J with I
    matrix = []
    used_letters = set()

    for char in key:
        if char not in used_letters and char.isalpha():
            matrix.append(char)
            used_letters.add(char)

    for char in string.ascii_uppercase.replace('J', ''):
        if char not in used_letters:
            matrix.append(char)

    return [matrix[i:i + 5] for i in range(0, 25, 5)]

def find_position(char, matrix):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == char:
                return row, col
    return None

def playfair_encrypt(plaintext, key):
    matrix = generate_playfair_matrix(key)
    plaintext = plaintext.upper().replace('J', 'I').replace(" ", "")
    ciphertext = ""

    # Preprocessing the plaintext
    pairs = []
    i = 0
    while i < len(plaintext):
        char1 = plaintext[i]
        char2 = plaintext[i + 1] if i + 1 < len(plaintext) else 'X'
        
        if char1 == char2:
            pairs.append((char1, 'X'))
            i += 1
        else:
            pairs.append((char1, char2))
            i += 2

    # Encrypting the pairs
    for char1, char2 in pairs:
        row1, col1 = find_position(char1, matrix)
        row2, col2 = find_position(char2, matrix)

        if row1 == row2:
            ciphertext += matrix[row1][(col1 + 1) % 5]
            ciphertext += matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:
            ciphertext += matrix[(row1 + 1) % 5][col1]
            ciphertext += matrix[(row2 + 1) % 5][col2]
        else:
            ciphertext += matrix[row1][col2]
            ciphertext += matrix[row2][col1]

    return ciphertext

def playfair_decrypt(ciphertext, key):
    matrix = generate_playfair_matrix(key)
    ciphertext = ciphertext.upper().replace(" ", "")
    plaintext = ""

    # Decrypting the pairs
    pairs = [(ciphertext[i], ciphertext[i+1]) for i in range(0, len(ciphertext), 2)]

    for char1, char2 in pairs:
        row1, col1 = find_position(char1, matrix)
        row2, col2 = find_position(char2, matrix)

        if row1 == row2:
            plaintext += matrix[row1][(col1 - 1) % 5]
            plaintext += matrix[row2][(col2 - 1) % 5]
        elif col1 == col2:
            plaintext += matrix[(row1 - 1) % 5][col1]
            plaintext += matrix[(row2 - 1) % 5][col2]
        else:
            plaintext += matrix[row1][col2]
            plaintext += matrix[row2][col1]

    # Remove padding 'X' if it was added during encryption
    if len(plaintext) > 1 and plaintext[-1] == 'X':
        plaintext = plaintext[:-1]

    return plaintext

# Hill Cipher Implementation (3x3 matrix)
keyMatrix = [[0] * 3 for _ in range(3)]
messageVector = [[0] for _ in range(3)]
cipherMatrix = [[0] for _ in range(3)]

def getKeyMatrix(key):
    k = 0
    for i in range(3):
        for j in range(3):
            keyMatrix[i][j] = ord(key[k]) % 65
            k += 1

def encrypt(messageVector):
    for i in range(3):
        cipherMatrix[i][0] = 0
        for x in range(3):
            cipherMatrix[i][0] += (keyMatrix[i][x] * messageVector[x][0])
        cipherMatrix[i][0] = cipherMatrix[i][0] % 26

def decrypt(ciphertext):
    det = int(np.round(np.linalg.det(keyMatrix)))
    det_inv = pow(det, -1, 26)
    adjugate = np.round(det * np.linalg.inv(keyMatrix)).astype(int) % 26
    inverse_matrix = (det_inv * adjugate) % 26

    decryptedText = []

    for i in range(0, len(ciphertext), 3):
        block = ciphertext[i:i+3]

        while len(block) < 3:
            block += 'X'

        for j in range(3):
            messageVector[j][0] = ord(block[j]) % 65

        decrypted_block = np.dot(inverse_matrix, messageVector) % 26

        for j in range(3):
            decryptedText.append(chr(int(decrypted_block[j][0]) + 65))

    return ''.join(decryptedText)

def process_hill_cipher(message, key, operation='encrypt'):
    message = message.upper().replace(" ", "")
    key = key.upper()

    getKeyMatrix(key)

    while len(message) % 3 != 0:
        message += 'X'

    result = ""

    if operation == 'encrypt':
        for i in range(0, len(message), 3):
            for j in range(3):
                messageVector[j][0] = ord(message[i + j]) % 65
            encrypt(messageVector)
            for j in range(3):
                result += chr(cipherMatrix[j][0] + 65)
    elif operation == 'decrypt':
        result = decrypt(message)

    return result

# GUI Setup
class CipherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cipher Program")

        # Text input section
        self.text_input_label = tk.Label(root, text="Input Message:")
        self.text_input_label.pack()

        self.text_input = tk.Text(root, height=5, width=40)
        self.text_input.pack()

        self.file_button = tk.Button(root, text="Upload Text File", command=self.upload_file)
        self.file_button.pack()

        # Key input section
        self.key_label = tk.Label(root, text="Input Key (min 12 chars):")
        self.key_label.pack()

        self.key_input = tk.Entry(root)
        self.key_input.pack()

        # Cipher selection
        self.cipher_label = tk.Label(root, text="Select Cipher:")
        self.cipher_label.pack()

        self.cipher_option = tk.StringVar(value="Vigenere")
        self.vigenere_radio = tk.Radiobutton(root, text="Vigenere", variable=self.cipher_option, value="Vigenere")
        self.playfair_radio = tk.Radiobutton(root, text="Playfair", variable=self.cipher_option, value="Playfair")
        self.hill_radio = tk.Radiobutton(root, text="Hill", variable=self.cipher_option, value="Hill")

        self.vigenere_radio.pack()
        self.playfair_radio.pack()
        self.hill_radio.pack()

        # Encrypt/Decrypt buttons
        self.encrypt_button = tk.Button(root, text="Encrypt", command=self.encrypt_message)
        self.decrypt_button = tk.Button(root, text="Decrypt", command=self.decrypt_message)

        self.encrypt_button.pack()
        self.decrypt_button.pack()

        # Output section
        self.output_label = tk.Label(root, text="Output:")
        self.output_label.pack()

        self.output_text = tk.Text(root, height=5, width=40)
        self.output_text.pack()

        # Save output to file
        self.save_button = tk.Button(root, text="Save Output to File", command=self.save_to_file)
        self.save_button.pack()

    def upload_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, 'r') as file:
                file_content = file.read()
                self.text_input.delete("1.0", tk.END)
                self.text_input.insert(tk.END, file_content)

    def encrypt_message(self):
        message = self.text_input.get("1.0", tk.END).strip()
        key = self.key_input.get().strip()

        if not message or not key:
            messagebox.showwarning("Input Error", "Please provide both message and key!")
            return

        if len(key) < 9:
            messagebox.showwarning("Key Error", "Key must be at least 9 characters long for Hill Cipher.")
            return

        cipher_type = self.cipher_option.get()
        if cipher_type == "Vigenere":
            result = vigenere_encrypt(message, key)
        elif cipher_type == "Playfair":
            result = playfair_encrypt(message, key)
        elif cipher_type == "Hill":
            result = process_hill_cipher(message, key, operation='encrypt')

        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, result)

    def decrypt_message(self):
        message = self.text_input.get("1.0", tk.END).strip()
        key = self.key_input.get().strip()

        if not message or not key:
            messagebox.showwarning("Input Error", "Please provide both message and key!")
            return

        cipher_type = self.cipher_option.get()
        if cipher_type == "Vigenere":
            result = vigenere_decrypt(message, key)
        elif cipher_type == "Playfair":
            result = playfair_decrypt(message, key)
        elif cipher_type == "Hill":
            result = process_hill_cipher(message, key, operation='decrypt')

        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, result)

    def save_to_file(self):
        output = self.output_text.get("1.0", tk.END).strip()
        if output:
            file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
            if file_path:
                with open(file_path, 'w') as file:
                    file.write(output)
                messagebox.showinfo("Success", "File saved successfully!")
        else:
            messagebox.showwarning("Save Error", "No output to save!")

# Run the app
root = tk.Tk()
app = CipherApp(root)
root.mainloop()
