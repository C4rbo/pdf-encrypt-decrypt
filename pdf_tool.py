import PyPDF2
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import time

# Extended list of common passwords for automatic discovery
common_passwords = ['1234', 'password', 'admin', 'welcome', 'letmein', '12345', 'qwerty', 'password123', 'iloveyou', 'sunshine', 'princess', 'abc123']

# Function to encrypt a PDF file
def encrypt_pdf():
    input_pdf = filedialog.askopenfilename(title="Select PDF File", filetypes=[("PDF files", "*.pdf")])
    if not input_pdf:
        return

    output_pdf = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")], title="Save Encrypted PDF")
    if not output_pdf:
        return

    password = password_entry.get()
    if not validate_password(password):
        return

    start_time = time.time()

    try:
        # Open the original PDF
        with open(input_pdf, 'rb') as file:
            reader = PyPDF2.PdfReader(file)
            writer = PyPDF2.PdfWriter()

            # Copy each page from the original PDF to the writer object
            for page_num in range(len(reader.pages)):
                writer.add_page(reader.pages[page_num])

            # Encrypt the new PDF with the provided password
            writer.encrypt(password)

            # Save the new encrypted PDF to the selected path
            with open(output_pdf, 'wb') as encrypted_file:
                writer.write(encrypted_file)

        elapsed_time = time.time() - start_time
        messagebox.showinfo("Success", f"PDF successfully encrypted and saved to {output_pdf}\nTime taken: {elapsed_time:.2f} seconds")

        # Option to open the encrypted PDF after saving
        if messagebox.askyesno("Open File", "Would you like to open the encrypted PDF?"):
            os.startfile(output_pdf)

        # Clear password entry field
        password_entry.delete(0, tk.END)
    except Exception as e:
        messagebox.showerror("Error", f"Error during encryption: {e}")

# Function to decrypt a PDF file
def decrypt_pdf():
    input_pdf = filedialog.askopenfilename(title="Select Encrypted PDF", filetypes=[("PDF files", "*.pdf")])
    if not input_pdf:
        return

    output_pdf = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")], title="Save Decrypted PDF")
    if not output_pdf:
        return

    password = password_entry.get()

    start_time = time.time()

    try:
        # Open the encrypted PDF
        with open(input_pdf, 'rb') as file:
            reader = PyPDF2.PdfReader(file)

            # Check if the PDF is encrypted
            if reader.is_encrypted:
                if password:
                    # Attempt to decrypt with the provided password
                    if not reader.decrypt(password):
                        messagebox.showwarning("Error", "Incorrect password! Decryption failed.")
                        return
                else:
                    # Attempt to discover the password automatically
                    found_password = None
                    for pwd in common_passwords:
                        if reader.decrypt(pwd):
                            found_password = pwd
                            break

                    if found_password:
                        messagebox.showinfo("Success", f"Password successfully found: {found_password}")
                    else:
                        messagebox.showerror("Error", "Failed to find password automatically.")
                        return

            writer = PyPDF2.PdfWriter()

            # Copy pages from the decrypted PDF to the new PDF
            for page_num in range(len(reader.pages)):
                writer.add_page(reader.pages[page_num])

            # Save the decrypted PDF
            with open(output_pdf, 'wb') as decrypted_file:
                writer.write(decrypted_file)

        elapsed_time = time.time() - start_time
        messagebox.showinfo("Success", f"PDF successfully decrypted and saved to {output_pdf}\nTime taken: {elapsed_time:.2f} seconds")

        # Option to open the decrypted PDF
        if messagebox.askyesno("Open File", "Would you like to open the decrypted PDF?"):
            os.startfile(output_pdf)

        # Clear password entry field
        password_entry.delete(0, tk.END)
    except Exception as e:
        messagebox.showerror("Error", f"Error during decryption: {e}")

# Function to display PDF file information
def view_pdf_info():
    input_pdf = filedialog.askopenfilename(title="Select PDF", filetypes=[("PDF files", "*.pdf")])
    if not input_pdf:
        return

    try:
        with open(input_pdf, 'rb') as file:
            reader = PyPDF2.PdfReader(file)

            # If the PDF is encrypted, inform the user
            if reader.is_encrypted:
                messagebox.showwarning("Info", "This PDF is encrypted. Please decrypt it to view information.")
                return

            info = reader.metadata
            num_pages = len(reader.pages)

            # Display metadata and page count
            info_text = f"Number of Pages: {num_pages}\n"
            info_text += f"Title: {info.title if info.title else 'N/A'}\n"
            info_text += f"Author: {info.author if info.author else 'N/A'}\n"
            info_text += f"Creator: {info.creator if info.creator else 'N/A'}"

            messagebox.showinfo("PDF Information", info_text)

    except Exception as e:
        messagebox.showerror("Error", f"Error reading PDF: {e}")

# Validate that the password is at least 4 characters long
def validate_password(password):
    if len(password) < 4:
        messagebox.showwarning("Error", "Password must be at least 4 characters long!")
        return False
    return True

# Toggle theme (dark/light) for the GUI
def toggle_theme():
    if theme_var.get() == "dark":
        root.configure(bg="black")
        password_label.configure(bg="black", fg="white")
    else:
        root.configure(bg="white")
        password_label.configure(bg="white", fg="black")

# Toggle password visibility
def toggle_password_visibility():
    if show_password_var.get():
        password_entry.config(show="")
    else:
        password_entry.config(show="*")

# GUI Setup
root = tk.Tk()
root.title("Encrypt/Decrypt PDF")
root.geometry("500x400")
root.resizable(False, False)

# Global style settings
style = ttk.Style(root)
style.configure('TButton', font=('Arial', 10), padding=10)

# Password label and entry
password_label = tk.Label(root, text="Password:", font=("Arial", 12))
password_label.pack(pady=10)

password_entry = tk.Entry(root, show="*", width=30, font=("Arial", 12))
password_entry.pack(pady=10)

# Show/Hide Password checkbox
show_password_var = tk.BooleanVar()
show_password_check = tk.Checkbutton(root, text="Show Password", variable=show_password_var, command=toggle_password_visibility)
show_password_check.pack()

# Button Frame
button_frame = tk.Frame(root)
button_frame.pack(pady=10)

# Encrypt PDF button
encrypt_button = ttk.Button(button_frame, text="Encrypt PDF", command=encrypt_pdf)
encrypt_button.grid(row=0, column=0, padx=10)

# Decrypt PDF button
decrypt_button = ttk.Button(button_frame, text="Decrypt PDF", command=decrypt_pdf)
decrypt_button.grid(row=0, column=1, padx=10)

# View PDF Info button
info_button = ttk.Button(button_frame, text="View PDF Info", command=view_pdf_info)
info_button.grid(row=1, column=0, columnspan=2, pady=10)

# Theme toggle (light/dark mode)
theme_var = tk.StringVar(value="light")
theme_toggle = ttk.Checkbutton(root, text="Dark Theme", variable=theme_var, onvalue="dark", offvalue="light", command=toggle_theme)
theme_toggle.pack(pady=10)

# Start the GUI
root.mainloop()
