import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from PIL import Image
import os

# 💡 Platform-specific DnD support
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
except ImportError:
    raise ImportError("Please install tkinterdnd2: pip install tkinterdnd2")

class ImageEncryptorApp:
    def __init__(self, master):
        self.master = master
        master.title("🔐 Image Encryption Tool with Drag & Drop")
        master.geometry("400x300")
        master.configure(bg="#f0f0f0")

        self.label = tk.Label(master, text="Drag & Drop an image or use Select Image", bg="#f0f0f0")
        self.label.pack(pady=10)

        # Drag and Drop Area
        self.drop_area = tk.Label(master, text="📁 Drop Image Here", relief="groove", bg="#e0e0e0", width=40, height=5)
        self.drop_area.pack(pady=5)
        self.drop_area.drop_target_register(DND_FILES)
        self.drop_area.dnd_bind('<<Drop>>', self.handle_drop)
        self.drop_area.dnd_bind('<<DragEnter>>', lambda e: self.drop_area.configure(bg="#d0f0d0"))
        self.drop_area.dnd_bind('<<DragLeave>>', lambda e: self.drop_area.configure(bg="#e0e0e0"))

        self.choose_button = tk.Button(master, text="Select Image", command=self.select_image)
        self.choose_button.pack()

        self.password_label = tk.Label(master, text="Enter password:", bg="#f0f0f0")
        self.password_label.pack(pady=(10, 0))

        self.password_entry = tk.Entry(master, show='*', width=30)
        self.password_entry.pack()

        self.encrypt_button = tk.Button(master, text="Encrypt", command=self.encrypt_image)
        self.encrypt_button.pack(pady=5)

        self.decrypt_button = tk.Button(master, text="Decrypt", command=self.decrypt_image)
        self.decrypt_button.pack()

        self.image_path = None

    def handle_drop(self, event):
        path = event.data.strip('{}')  # Remove curly braces if any
        if os.path.isfile(path):
            self.image_path = path
            messagebox.showinfo("File Dropped", f"Selected file:\n{path}")
        else:
            messagebox.showerror("Error", "Dropped item is not a file.")

    def select_image(self):
        self.image_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg;*.jpeg;*.bmp;*.enc")])
        if self.image_path:
            messagebox.showinfo("Selected", f"Selected file:\n{self.image_path}")

    def encrypt_image(self):
        if not self.image_path or not self.password_entry.get():
            messagebox.showerror("Error", "Image and password required.")
            return

        with open(self.image_path, 'rb') as f:
            img_data = f.read()

        salt = get_random_bytes(16)
        key = PBKDF2(self.password_entry.get(), salt, dkLen=32, count=100000)
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(img_data)

        enc_file = self.image_path + ".enc"
        with open(enc_file, 'wb') as f:
            f.write(salt + cipher.nonce + tag + ciphertext)

        messagebox.showinfo("Success", f"Encrypted image saved as:\n{enc_file}")

    def decrypt_image(self):
        if not self.image_path or not self.password_entry.get():
            messagebox.showerror("Error", "Encrypted file and password required.")
            return

        with open(self.image_path, 'rb') as f:
            data = f.read()

        salt = data[:16]
        nonce = data[16:32]
        tag = data[32:48]
        ciphertext = data[48:]

        try:
            key = PBKDF2(self.password_entry.get(), salt, dkLen=32, count=100000)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)

            output_path = os.path.splitext(self.image_path)[0] + "_decrypted.jpg"
            with open(output_path, 'wb') as out_img:
                out_img.write(decrypted_data)

            messagebox.showinfo("Success", f"Decrypted image saved as:\n{output_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")


if __name__ == "__main__":
    root = TkinterDnD.Tk()  # Use TkinterDnD.Tk() for root window
    app = ImageEncryptorApp(root)
    root.mainloop()
