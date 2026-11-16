"""Secure File Transfer - Tkinter GUI client.  Run: python gui_client.py"""
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import config
from client import AuthError, SecureClient, human


class App:
    def __init__(self, root):
        self.root, self.client = root, None
        root.title("Secure File Transfer (AES-256)")
        root.geometry("640x560")

        box = ttk.LabelFrame(root, text="Connection")
        box.pack(fill="x", padx=10, pady=6)
        self.host = self._field(box, "Server IP", config.HOST, 0, 0)
        self.passphrase = self._field(box, "Shared passphrase", "", 0, 2, show="*")
        self.user = self._field(box, "Username", "", 1, 0)
        self.password = self._field(box, "Password", "", 1, 2, show="*")
        ttk.Button(box, text="Login", command=lambda: self.connect(False)).grid(row=2, column=1, pady=4)
        ttk.Button(box, text="Register", command=lambda: self.connect(True)).grid(row=2, column=2, pady=4)

        files = ttk.LabelFrame(root, text="My files on server")
        files.pack(fill="both", expand=True, padx=10, pady=6)
        self.listbox = tk.Listbox(files, height=8)
        self.listbox.pack(fill="both", expand=True, padx=5, pady=5)

        bar = ttk.Frame(root)
        bar.pack(fill="x", padx=10)
        for text, cmd in (("Upload", self.upload), ("Upload corrupted (demo)", lambda: self.upload(True)),
                          ("Download", self.download), ("Delete", self.delete), ("Refresh", self.refresh)):
            ttk.Button(bar, text=text, command=cmd).pack(side="left", padx=3, pady=4)

        self.progress = ttk.Progressbar(root, maximum=100)
        self.progress.pack(fill="x", padx=10, pady=4)
        self.log = tk.Text(root, height=9, state="disabled")
        self.log.pack(fill="both", padx=10, pady=6)

    def _field(self, parent, label, default, row, col, show=None):
        ttk.Label(parent, text=label).grid(row=row, column=col, sticky="e", padx=4, pady=2)
        var = tk.StringVar(value=default)
        ttk.Entry(parent, textvariable=var, show=show, width=22).grid(row=row, column=col + 1, padx=4)
        return var

    def write(self, text):
        self.log.config(state="normal")
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.log.config(state="disabled")

    def on_progress(self, done, total):
        self.progress["value"] = done * 100 / total if total else 100
        self.root.update_idletasks()

    def connect(self, register):
        if self.client:
            self.client.close()
        try:
            self.client = SecureClient(self.passphrase.get(), self.host.get())
            self.client.connect()
            action = self.client.register if register else self.client.login
            r = action(self.user.get(), self.password.get())
        except AuthError as e:
            return messagebox.showerror("Authentication", str(e))
        except OSError as e:
            return messagebox.showerror("Connection", f"Could not connect: {e}")
        self.write(r["msg"])
        if r["ok"]:
            self.refresh()

    def need_login(self):
        if not (self.client and self.client.username):
            messagebox.showwarning("Not logged in", "Please login first.")
            return False
        return True

    def refresh(self):
        if not self.need_login():
            return
        self.listbox.delete(0, "end")
        for f in self.client.list_files()["files"]:
            self.listbox.insert("end", f"{f['name']}   ({human(f['size'])})")

    def selected(self):
        sel = self.listbox.curselection()
        return self.listbox.get(sel[0]).split("   (")[0] if sel else None

    def upload(self, tamper=False):
        if not self.need_login():
            return
        path = filedialog.askopenfilename()
        if path:
            r = self.client.upload(path, self.on_progress, tamper)
            p = self.client.last_preview
            if p:
                self.write(f"original: {p[0]}  ->  encrypted: {p[1]}")
            self.write(r["msg"])
            self.refresh()

    def download(self):
        name = self.selected()
        if self.need_login() and name:
            folder = filedialog.askdirectory() or "."
            r = self.client.download(name, folder, self.on_progress)
            self.write(r["msg"] + (f" -> {r['path']}" if r["ok"] else ""))

    def delete(self):
        name = self.selected()
        if self.need_login() and name:
            self.write(self.client.delete(name)["msg"])
            self.refresh()


if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()
