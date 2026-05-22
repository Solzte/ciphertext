"""Simple desktop GUI for the ciphertext toolkit."""

from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from ciphertext.crypto import CryptoError, decrypt, decrypt_file, encrypt, encrypt_file


class CiphertextApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Ciphertext")
        self.geometry("760x560")
        self.minsize(640, 480)
        self._build_ui()

    def _build_ui(self) -> None:
        container = ttk.Frame(self, padding=16)
        container.pack(fill=tk.BOTH, expand=True)

        ttk.Label(container, text="Password").pack(anchor=tk.W)
        self.password_entry = ttk.Entry(container, show="*")
        self.password_entry.pack(fill=tk.X, pady=(4, 12))

        notebook = ttk.Notebook(container)
        notebook.pack(fill=tk.BOTH, expand=True)

        text_tab = ttk.Frame(notebook, padding=8)
        file_tab = ttk.Frame(notebook, padding=8)
        notebook.add(text_tab, text="Text")
        notebook.add(file_tab, text="File")

        self._build_text_tab(text_tab)
        self._build_file_tab(file_tab)

    def _build_text_tab(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="Input").pack(anchor=tk.W)
        self.input_text = scrolledtext.ScrolledText(parent, height=10, wrap=tk.WORD)
        self.input_text.pack(fill=tk.BOTH, expand=True, pady=(4, 12))

        ttk.Label(parent, text="Output").pack(anchor=tk.W)
        self.output_text = scrolledtext.ScrolledText(parent, height=10, wrap=tk.WORD, state=tk.DISABLED)
        self.output_text.pack(fill=tk.BOTH, expand=True, pady=(4, 12))

        buttons = ttk.Frame(parent)
        buttons.pack(fill=tk.X)
        ttk.Button(buttons, text="Encrypt", command=self._encrypt_text).pack(side=tk.LEFT)
        ttk.Button(buttons, text="Decrypt", command=self._decrypt_text).pack(side=tk.LEFT, padx=8)
        ttk.Button(buttons, text="Copy Output", command=self._copy_output).pack(side=tk.LEFT)

    def _build_file_tab(self, parent: ttk.Frame) -> None:
        path_row = ttk.Frame(parent)
        path_row.pack(fill=tk.X, pady=(0, 12))

        ttk.Label(path_row, text="Selected file").pack(anchor=tk.W)
        self.file_path = tk.StringVar()
        ttk.Entry(path_row, textvariable=self.file_path).pack(fill=tk.X, pady=(4, 8), side=tk.LEFT, expand=True)
        ttk.Button(path_row, text="Browse", command=self._browse_file).pack(side=tk.LEFT, padx=(8, 0))

        buttons = ttk.Frame(parent)
        buttons.pack(fill=tk.X)
        ttk.Button(buttons, text="Encrypt File", command=self._encrypt_file).pack(side=tk.LEFT)
        ttk.Button(buttons, text="Decrypt File", command=self._decrypt_file).pack(side=tk.LEFT, padx=8)

        ttk.Label(parent, text="Result").pack(anchor=tk.W, pady=(16, 4))
        self.file_result = scrolledtext.ScrolledText(parent, height=12, wrap=tk.WORD, state=tk.DISABLED)
        self.file_result.pack(fill=tk.BOTH, expand=True)

    def _password(self) -> str:
        password = self.password_entry.get()
        if not password:
            raise CryptoError("Password cannot be empty.")
        return password

    def _set_output(self, widget: scrolledtext.ScrolledText, value: str) -> None:
        widget.configure(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.insert(tk.END, value)
        widget.configure(state=tk.DISABLED)

    def _encrypt_text(self) -> None:
        try:
            result = encrypt(self.input_text.get("1.0", tk.END).strip(), self._password())
        except CryptoError as exc:
            messagebox.showerror("Encryption failed", str(exc))
            return
        self._set_output(self.output_text, result)

    def _decrypt_text(self) -> None:
        try:
            result = decrypt(self.input_text.get("1.0", tk.END).strip(), self._password())
        except CryptoError as exc:
            messagebox.showerror("Decryption failed", str(exc))
            return
        self._set_output(self.output_text, result)

    def _copy_output(self) -> None:
        value = self.output_text.get("1.0", tk.END).strip()
        if not value:
            return
        self.clipboard_clear()
        self.clipboard_append(value)
        messagebox.showinfo("Copied", "Output copied to clipboard.")

    def _browse_file(self) -> None:
        path = filedialog.askopenfilename()
        if path:
            self.file_path.set(path)

    def _encrypt_file(self) -> None:
        path = self.file_path.get().strip()
        if not path:
            messagebox.showerror("Missing file", "Choose a file first.")
            return
        try:
            output = encrypt_file(path, self._password())
        except CryptoError as exc:
            messagebox.showerror("Encryption failed", str(exc))
            return
        self._set_output(self.file_result, f"Encrypted file created:\n{output}")

    def _decrypt_file(self) -> None:
        path = self.file_path.get().strip()
        if not path:
            messagebox.showerror("Missing file", "Choose a file first.")
            return
        try:
            output = decrypt_file(path, self._password())
        except CryptoError as exc:
            messagebox.showerror("Decryption failed", str(exc))
            return
        self._set_output(self.file_result, f"Decrypted file created:\n{output}")


def main() -> None:
    app = CiphertextApp()
    app.mainloop()


if __name__ == "__main__":
    main()
