# 🔐 Image Encryption Tool with Drag & Drop

This is a Python-based graphical application for encrypting and decrypting images using AES encryption. The tool provides an easy-to-use interface for users to securely encrypt and decrypt their images with a password, utilizing drag-and-drop functionality.

## Features

- **Drag & Drop**: Users can drag an image file onto the application window to select it.
- **File Selection**: Users can also manually select an image through a standard file dialog.
- **Password Protection**: Users must enter a password to encrypt or decrypt images.
- **AES Encryption**: Images are encrypted using AES in GCM mode.
- **Encrypted Files**: The encrypted images are saved with a `.enc` extension.
- **Decryption**: Encrypted files can be decrypted back to their original form using the correct password.
- **Cross-platform**: The application works on Windows, macOS, and Linux.

## Requirements

Before you can run the application, make sure you have the following dependencies installed:

- Python 3.x
- `pycryptodome` for AES encryption
- `tkinter` for the graphical user interface
- `tkinterdnd2` for drag-and-drop functionality
- `Pillow` (PIL) for image processing (optional, if you want to handle image manipulation)

To install the required libraries, use the following commands:

```bash
pip install pycryptodome
pip install tkinterdnd2
pip install pillow
