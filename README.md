# PDF Encryption and Decryption

A graphical user interface (GUI) tool written in Python for encrypting and decrypting PDF files. This application allows you to encrypt your sensitive PDFs with a password, and decrypt them either with a known password or by attempting to discover it using a list of common passwords.

## Features

- **PDF Encryption**: Encrypts any PDF file with a user-defined password to ensure secure storage.
- **PDF Decryption**: Decrypts encrypted PDF files with either a known password or attempts automatic password discovery using a list of common passwords.
- **Automatic Password Discovery**: Uses a pre-defined list of common passwords to try and decrypt a PDF automatically.
- **Show/Hide Password**: Option to toggle password visibility when entering it.
- **Dark/Light Mode**: Toggle between dark and light themes for the GUI.
- **PDF Information Viewer**: Displays metadata of any selected PDF, such as the number of pages, title, author, and creator.
- **User-Friendly Interface**: Built using Tkinter for an intuitive and simple-to-use GUI.

## Installation

Clone the repository and navigate into the project directory:

```bash
git clone https://github.com/C4rbo/pdf-encrypt-decrypt.git
cd pdf-encrypt-decrypt
```

Install the required Python libraries:

```bash
pip install PyPDF2
```

You may also need to install `tkinter` if it's not already available on your system.

## Usage

Run the Python script to launch the application:

```bash
python pdf_tool.py
```

### Functionalities

- **Encrypt PDF**: Choose a PDF file, set a password, and save the encrypted PDF.
- **Decrypt PDF**: Choose an encrypted PDF and decrypt it by entering a known password or attempting to discover the password automatically.
- **View PDF Info**: Get metadata from any selected PDF file, such as the number of pages, title, author, and creator.
- **Toggle Theme**: Switch between light and dark mode for the interface.

### Example Walkthrough

1. Open the application and click the "Encrypt PDF" button.
2. Select a PDF file from your system.
3. Enter a password in the text field.
4. Save the encrypted PDF in your preferred directory.
5. To decrypt, select an encrypted PDF and either enter the password or allow the tool to try common passwords.

### Common Password Discovery

If you don't remember the password for a PDF, the tool will attempt to discover it using a list of common passwords such as `1234`, `password`, `admin`, etc.

## Legal Disclaimer

This tool is for educational purposes and authorized usage only. Encrypt or decrypt files that you have permission to modify. Unauthorized tampering with files may be illegal. The author assumes no responsibility for any misuse of this tool.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

## Contributing

Contributions are welcome! If you have suggestions for improvements or find any bugs, please open an issue or submit a pull request on GitHub.

## Author

- C4rbo (https://github.com/C4rbo)
