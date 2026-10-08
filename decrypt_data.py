#!/usr/bin/env python3
"""
App de escritorio (Tkinter + customtkinter) para desencriptar los valores
cifrados de un data.json de configuracion (formato legacy AES-256-GCM) y
guardar el resultado en una base SQLite local.

Formato de cada valor cifrado (antes de base64):
    nonceSize:int32-LE(4) | nonce(nonceSize) | tagSize:int32-LE(4) | tag(tagSize) | ciphertext

Arquitectura (MVC):
    seid_model.py       - logica de cifrado/desencriptado y persistencia (sin UI)
    seid_view.py         - construccion de la interfaz grafica (sin logica de negocio)
    seid_controller.py   - conecta la vista con el modelo (eventos, hilos, validaciones)

La frase de 32 caracteres se puede precargar desde una variable de entorno
(ver seid_model.PHRASE_ENV_VAR); si existe un archivo .env en esta carpeta,
se carga automaticamente al iniciar.

Requisitos:
    pip install -r requirements.txt

Ejecutar:
    python decrypt_data.py
"""

from dotenv import load_dotenv

import customtkinter as ctk

from seid_controller import DecryptController


def main():
    load_dotenv()
    root = ctk.CTk()
    DecryptController(root)
    root.mainloop()


if __name__ == "__main__":
    main()
