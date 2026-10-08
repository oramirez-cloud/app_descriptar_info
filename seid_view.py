"""
Vista (MVC): construccion de la interfaz grafica (customtkinter).

Solo arma y expone widgets; no conoce la logica de cifrado ni de persistencia
(eso vive en seid_model.py). Los botones de accion invocan callbacks que le
pasa el controlador por constructor, en vez de depender de el directamente.
"""

import os
import tkinter as tk
from tkinter import filedialog, messagebox

import customtkinter as ctk

from seid_model import PHRASE_ENV_VAR

ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")


def _hex_to_rgb(color: str):
    color = color.lstrip("#")
    return tuple(int(color[i:i + 2], 16) for i in (0, 2, 4))


def _rgb_to_hex(rgb):
    return "#%02x%02x%02x" % rgb


def _draw_horizontal_gradient(canvas: tk.Canvas, width: int, height: int, start: str, end: str):
    rgb_start = _hex_to_rgb(start)
    rgb_end = _hex_to_rgb(end)
    steps = max(width, 1)
    for i in range(steps):
        ratio = i / steps
        rgb = tuple(int(rgb_start[c] + (rgb_end[c] - rgb_start[c]) * ratio) for c in range(3))
        canvas.create_line(i, 0, i, height, fill=_rgb_to_hex(rgb))


class DecryptView:
    FONT_MONO = ("Consolas", 10)
    FONT_BASE = ("Segoe UI", 11)
    FONT_SMALL = ("Segoe UI", 9)
    FONT_CARD_TITLE = ("Segoe UI Semibold", 13)

    BODY_BG = "#eef3f7"
    CARD_BG = "#ffffff"
    CARD_BORDER = "#e1e7ee"
    FIELD_BG = "#f7fafc"
    HEADER_START = "#0a2e3a"
    HEADER_END = "#0e8aa3"
    ACCENT = "#0e7490"
    ACCENT_HOVER = "#0b5c73"
    ACCENT_SOFT = "#e5f2f5"
    TEXT_PRIMARY = "#1f2937"
    TEXT_MUTED = "#64748b"

    def __init__(self, root: ctk.CTk, callbacks: dict):
        self.root = root
        self.callbacks = callbacks

        root.title("Desencriptador data.json (SEID)")
        root.geometry("920x980")
        root.minsize(760, 680)
        root.configure(fg_color=self.BODY_BG)

        self._build_header(root)

        tabview = ctk.CTkTabview(
            root,
            fg_color=self.BODY_BG,
            segmented_button_fg_color="#e3edf1",
            segmented_button_selected_color=self.ACCENT,
            segmented_button_selected_hover_color=self.ACCENT_HOVER,
            segmented_button_unselected_color="#e3edf1",
            text_color=self.TEXT_PRIMARY,
            border_width=0,
        )
        tabview.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        tab_data_json = tabview.add("data.json (legacy)")
        tab_api_payload = tabview.add("Payload de API (RSA + AES-GCM)")

        self._build_data_json_tab(tab_data_json)
        self._build_api_payload_tab(tab_api_payload)

    # -----------------------------------------------------------------
    # Construccion de la UI
    # -----------------------------------------------------------------

    def _build_header(self, root):
        canvas = tk.Canvas(root, height=96, highlightthickness=0, bd=0)
        canvas.pack(fill="x", side="top")
        self._header_canvas = canvas
        canvas.bind("<Configure>", self._redraw_header)

    def _redraw_header(self, event=None):
        canvas = self._header_canvas
        width = canvas.winfo_width()
        height = canvas.winfo_height()
        if width <= 1 or height <= 1:
            return
        canvas.delete("all")
        _draw_horizontal_gradient(canvas, width, height, self.HEADER_START, self.HEADER_END)
        canvas.create_text(
            24, height * 0.38, text="Desencriptador data.json", anchor="w",
            fill="white", font=("Segoe UI Semibold", 20),
        )
        canvas.create_text(
            24, height * 0.72, text="SEID  ·  AES-256-GCM  ·  RSA-OAEP", anchor="w",
            fill="#cdeef4", font=self.FONT_SMALL,
        )

    def _card(self, parent, title: str, expand: bool = False) -> ctk.CTkFrame:
        card = ctk.CTkFrame(
            parent, corner_radius=14, fg_color=self.CARD_BG,
            border_width=1, border_color=self.CARD_BORDER,
        )
        card.pack(fill="both" if expand else "x", expand=expand, pady=(0, 14))
        ctk.CTkLabel(
            card, text=title, font=self.FONT_CARD_TITLE, text_color=self.TEXT_PRIMARY, anchor="w",
        ).pack(fill="x", padx=16, pady=(14, 6))
        return card

    def _styled_text(self, parent, height_rows, mono=True, **kwargs):
        return ctk.CTkTextbox(
            parent, height=height_rows * 22, corner_radius=10,
            border_width=1, border_color=self.CARD_BORDER, fg_color=self.FIELD_BG,
            text_color=self.TEXT_PRIMARY,
            font=self.FONT_MONO if mono else self.FONT_BASE,
            **kwargs,
        )

    def _primary_button(self, parent, text, command):
        return ctk.CTkButton(
            parent, text=text, command=command, corner_radius=8,
            fg_color=self.ACCENT, hover_color=self.ACCENT_HOVER, text_color="white",
            font=("Segoe UI Semibold", 12), height=40,
        )

    def _secondary_button(self, parent, text, command, state="normal"):
        return ctk.CTkButton(
            parent, text=text, command=command, corner_radius=8,
            fg_color="transparent", hover_color=self.ACCENT_SOFT,
            border_width=1, border_color=self.ACCENT, text_color=self.ACCENT,
            font=self.FONT_SMALL, height=30, state=state,
        )

    def _switch(self, parent, text, variable, command):
        return ctk.CTkSwitch(
            parent, text=text, variable=variable, command=command,
            progress_color=self.ACCENT, button_color="white",
            font=self.FONT_BASE, text_color=self.TEXT_PRIMARY,
        )

    def _entry(self, parent, textvariable=None, show=None, state="normal"):
        kwargs = {}
        if show is not None:
            kwargs["show"] = show
        return ctk.CTkEntry(
            parent, textvariable=textvariable, corner_radius=8,
            border_width=1, border_color=self.CARD_BORDER, fg_color=self.FIELD_BG,
            text_color=self.TEXT_PRIMARY, height=34, state=state, **kwargs,
        )

    def _build_data_json_tab(self, tab):
        main = ctk.CTkScrollableFrame(tab, fg_color="transparent")
        main.pack(fill="both", expand=True)

        # --- Card: entrada ---
        card_input = self._card(main, "1. JSON de entrada", expand=True)
        input_header = ctk.CTkFrame(card_input, fg_color="transparent")
        input_header.pack(fill="x", padx=16)
        ctk.CTkLabel(
            input_header, text="Pega aqui el contenido literal del data.json:",
            text_color=self.TEXT_MUTED, font=self.FONT_SMALL,
        ).pack(side="left")
        self._secondary_button(
            input_header, "Cargar desde archivo...", self.callbacks["on_browse_input"],
        ).pack(side="right")

        self.json_input_text = self._styled_text(card_input, height_rows=10)
        self.json_input_text.pack(fill="both", expand=True, padx=16, pady=(8, 16))
        self.json_input_text.bind("<<Modified>>", self._on_json_text_modified)

        # --- Card: credenciales ---
        card_creds = self._card(main, "2. Credenciales")
        ctk.CTkLabel(
            card_creds, text="Frase (32 caracteres):", text_color=self.TEXT_MUTED, font=self.FONT_SMALL,
        ).pack(anchor="w", padx=16)

        creds_row = ctk.CTkFrame(card_creds, fg_color="transparent")
        creds_row.pack(fill="x", padx=16, pady=(4, 0))
        self.phrase_var = tk.StringVar(value=os.environ.get(PHRASE_ENV_VAR, ""))
        self.phrase_entry = self._entry(creds_row, textvariable=self.phrase_var, show="*")
        self.phrase_entry.pack(side="left", fill="x", expand=True)

        self.show_phrase_var = tk.BooleanVar(value=False)
        self._switch(
            creds_row, "Mostrar", self.show_phrase_var, self._toggle_phrase_visibility,
        ).pack(side="left", padx=(12, 0))

        if os.environ.get(PHRASE_ENV_VAR):
            ctk.CTkLabel(
                card_creds, text=f"Precargada desde la variable de entorno {PHRASE_ENV_VAR}",
                text_color=self.TEXT_MUTED, font=self.FONT_SMALL, anchor="w",
            ).pack(fill="x", padx=16, pady=(6, 0))

        ctk.CTkFrame(card_creds, height=14, fg_color="transparent").pack()

        # --- Card: opciones de salida ---
        card_output = self._card(main, "3. Opciones de salida (opcional)")

        self.save_sqlite_enabled = tk.BooleanVar(value=False)
        self._switch(
            card_output, "Tambien guardar en SQLite", self.save_sqlite_enabled, self._toggle_sqlite_output,
        ).pack(anchor="w", padx=16)

        sqlite_row = ctk.CTkFrame(card_output, fg_color="transparent")
        sqlite_row.pack(fill="x", padx=16, pady=(6, 14))
        self.output_db_var = tk.StringVar(value=os.path.join(os.getcwd(), "decrypted_data.sqlite3"))
        self.sqlite_entry = self._entry(sqlite_row, textvariable=self.output_db_var, state="disabled")
        self.sqlite_entry.pack(side="left", fill="x", expand=True)
        self.sqlite_browse_btn = self._secondary_button(
            sqlite_row, "Guardar como...", self.callbacks["on_browse_output_db"], state="disabled",
        )
        self.sqlite_browse_btn.pack(side="left", padx=(8, 0))

        self.export_json_enabled = tk.BooleanVar(value=False)
        self._switch(
            card_output, "Tambien exportar a archivo JSON en claro (contendra credenciales)",
            self.export_json_enabled, self._toggle_json_export,
        ).pack(anchor="w", padx=16)

        json_row = ctk.CTkFrame(card_output, fg_color="transparent")
        json_row.pack(fill="x", padx=16, pady=(6, 16))
        self.output_json_var = tk.StringVar(value="")
        self.json_entry = self._entry(json_row, textvariable=self.output_json_var, state="disabled")
        self.json_entry.pack(side="left", fill="x", expand=True)
        self.json_browse_btn = self._secondary_button(
            json_row, "Guardar como...", self.callbacks["on_browse_output_json"], state="disabled",
        )
        self.json_browse_btn.pack(side="left", padx=(8, 0))

        # --- Boton de accion ---
        self.decrypt_btn = self._primary_button(main, "Desencriptar", self.callbacks["on_decrypt"])
        self.decrypt_btn.pack(fill="x", pady=(0, 14))

        # --- Card: estado ---
        card_status = self._card(main, "Estado")
        self.log_text = self._styled_text(card_status, height_rows=5, mono=False, state="disabled")
        self.log_text.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        # --- Card: resultado ---
        card_result = self._card(main, "JSON desencriptado", expand=True)
        result_header = ctk.CTkFrame(card_result, fg_color="transparent")
        result_header.pack(fill="x", padx=16)
        ctk.CTkLabel(
            result_header, text="Resultado:", text_color=self.TEXT_MUTED, font=self.FONT_SMALL,
        ).pack(side="left")
        self._secondary_button(result_header, "Copiar al portapapeles", self._copy_result).pack(side="right")

        self.result_text = self._styled_text(card_result, height_rows=14)
        self.result_text.pack(fill="both", expand=True, padx=16, pady=(8, 16))

    def _on_json_text_modified(self, event=None):
        if self.json_input_text.edit_modified():
            self.callbacks["on_json_text_modified"]()
            self.json_input_text.edit_modified(False)

    def _build_api_payload_tab(self, tab):
        main = ctk.CTkScrollableFrame(tab, fg_color="transparent")
        main.pack(fill="both", expand=True)

        info = (
            "Esto desencripta un payload de API distinto al data.json: una AES key por-request "
            "va envuelta en RSA dentro del header X-Payload-Key, y el body viaja como "
            "nonce(12)+ciphertext+tag(16) sin length-prefix. Necesitas la llave privada RSA "
            "(sacala del JSON ya desencriptado en la otra pestaña)."
        )
        ctk.CTkLabel(
            main, text=info, wraplength=760, justify="left", text_color=self.TEXT_MUTED, font=self.FONT_SMALL,
        ).pack(fill="x", pady=(0, 14))

        card_pem = self._card(main, "1. Llave privada RSA (PEM)")
        pem_header = ctk.CTkFrame(card_pem, fg_color="transparent")
        pem_header.pack(fill="x", padx=16)
        ctk.CTkLabel(
            pem_header, text="Viene del data.json ya desencriptado:",
            text_color=self.TEXT_MUTED, font=self.FONT_SMALL,
        ).pack(side="left")
        self._secondary_button(
            pem_header, "Buscar PEM en el resultado de la otra pestaña", self.callbacks["on_autofill_pem"],
        ).pack(side="right")

        self.rsa_pem_text = self._styled_text(card_pem, height_rows=9, wrap="none")
        self.rsa_pem_text.pack(fill="both", expand=True, padx=16, pady=(8, 16))

        card_key = self._card(main, "2. X-Payload-Key (header HTTP)")
        ctk.CTkLabel(
            card_key, text="Base64 — NO es la frase de 32 caracteres.",
            text_color=self.TEXT_MUTED, font=self.FONT_SMALL,
        ).pack(anchor="w", padx=16)
        self.payload_key_text = self._styled_text(card_key, height_rows=3, wrap="char")
        self.payload_key_text.pack(fill="both", expand=True, padx=16, pady=(6, 16))

        card_payload = self._card(main, '3. Payload cifrado ("encrypted")')
        ctk.CTkLabel(
            card_payload, text='Valor del campo "encrypted" de la respuesta, en base64.',
            text_color=self.TEXT_MUTED, font=self.FONT_SMALL,
        ).pack(anchor="w", padx=16)
        self.api_payload_text = self._styled_text(card_payload, height_rows=5, wrap="char")
        self.api_payload_text.pack(fill="both", expand=True, padx=16, pady=(6, 16))

        self.decrypt_payload_btn = self._primary_button(
            main, "Desencriptar payload", self.callbacks["on_decrypt_payload"],
        )
        self.decrypt_payload_btn.pack(fill="x", pady=(0, 14))

        card_result = self._card(main, "Resultado", expand=True)
        result_header = ctk.CTkFrame(card_result, fg_color="transparent")
        result_header.pack(fill="x", padx=16)
        ctk.CTkLabel(
            result_header, text="Texto plano:", text_color=self.TEXT_MUTED, font=self.FONT_SMALL,
        ).pack(side="left")
        self._secondary_button(
            result_header, "Copiar al portapapeles", self._copy_api_payload_result,
        ).pack(side="right")

        self.api_payload_result_text = self._styled_text(card_result, height_rows=10)
        self.api_payload_result_text.pack(fill="both", expand=True, padx=16, pady=(8, 16))

    # -----------------------------------------------------------------
    # Interacciones puramente de UI (no tocan el modelo)
    # -----------------------------------------------------------------

    def _toggle_phrase_visibility(self):
        self.phrase_entry.configure(show="" if self.show_phrase_var.get() else "*")

    def _toggle_json_export(self):
        state = "normal" if self.export_json_enabled.get() else "disabled"
        self.json_entry.configure(state=state)
        self.json_browse_btn.configure(state=state)

    def _toggle_sqlite_output(self):
        state = "normal" if self.save_sqlite_enabled.get() else "disabled"
        self.sqlite_entry.configure(state=state)
        self.sqlite_browse_btn.configure(state=state)

    def _copy_result(self):
        self.copy_to_clipboard(self.get_result_json())

    def _copy_api_payload_result(self):
        self.copy_to_clipboard(self.get_api_payload_result())

    def copy_to_clipboard(self, content: str):
        content = content.strip()
        if not content:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(content)

    # -----------------------------------------------------------------
    # Dialogos (archivo / mensajes / seleccion)
    # -----------------------------------------------------------------

    def ask_open_json_file(self):
        return filedialog.askopenfilename(
            title="Selecciona data.json",
            filetypes=[("JSON", "*.json"), ("Todos los archivos", "*.*")],
        ) or None

    def ask_save_sqlite_path(self):
        return filedialog.asksaveasfilename(
            title="Guardar base SQLite",
            defaultextension=".sqlite3",
            filetypes=[("SQLite", "*.sqlite3"), ("Todos los archivos", "*.*")],
            initialfile="decrypted_data.sqlite3",
        ) or None

    def ask_save_json_path(self):
        return filedialog.asksaveasfilename(
            title="Guardar JSON desencriptado",
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("Todos los archivos", "*.*")],
            initialfile="decrypted_data.json",
        ) or None

    def show_error(self, title: str, message: str):
        messagebox.showerror(title, message)

    def show_warning(self, title: str, message: str):
        messagebox.showwarning(title, message)

    def show_info(self, title: str, message: str):
        messagebox.showinfo(title, message)

    def ask_choice(self, title: str, message: str, options: list[str]):
        """Dialogo modal con una lista de opciones. Devuelve el indice elegido o None."""
        dialog = ctk.CTkToplevel(self.root)
        dialog.title(title)
        dialog.configure(fg_color=self.BODY_BG)
        dialog.transient(self.root)
        dialog.resizable(False, False)
        dialog.after(50, dialog.grab_set)

        selected = {"index": None}

        ctk.CTkLabel(
            dialog, text=message, wraplength=440, justify="left", text_color=self.TEXT_PRIMARY,
        ).pack(padx=16, pady=(16, 8), anchor="w")

        list_frame = ctk.CTkFrame(dialog, fg_color="white", corner_radius=10, border_width=1, border_color=self.CARD_BORDER)
        list_frame.pack(fill="both", expand=True, padx=16)
        scrollbar = tk.Scrollbar(list_frame, orient="vertical")
        listbox = tk.Listbox(
            list_frame, height=min(8, len(options)), width=60,
            yscrollcommand=scrollbar.set, exportselection=False,
            relief="flat", borderwidth=0, highlightthickness=0,
        )
        scrollbar.config(command=listbox.yview)
        listbox.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=8)
        scrollbar.pack(side="right", fill="y", padx=(0, 8), pady=8)
        for option in options:
            listbox.insert("end", option)
        listbox.selection_set(0)

        def confirm(event=None):
            selection = listbox.curselection()
            if selection:
                selected["index"] = selection[0]
            dialog.destroy()

        def cancel():
            dialog.destroy()

        listbox.bind("<Double-Button-1>", confirm)

        button_row = ctk.CTkFrame(dialog, fg_color="transparent")
        button_row.pack(fill="x", padx=16, pady=16)
        self._secondary_button(button_row, "Cancelar", cancel).pack(side="right", padx=(8, 0))
        self._primary_button(button_row, "Usar esta", confirm).pack(side="right")

        dialog.update_idletasks()
        x = self.root.winfo_rootx() + (self.root.winfo_width() - dialog.winfo_width()) // 2
        y = self.root.winfo_rooty() + (self.root.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{max(x, 0)}+{max(y, 0)}")

        self.root.wait_window(dialog)
        return selected["index"]

    # -----------------------------------------------------------------
    # Accesores usados por el controlador
    # -----------------------------------------------------------------

    def after(self, delay_ms: int, func, *args):
        return self.root.after(delay_ms, func, *args)

    def get_json_input(self) -> str:
        return self.json_input_text.get("1.0", "end").strip()

    def set_json_input(self, text: str):
        self.json_input_text.delete("1.0", "end")
        self.json_input_text.insert("1.0", text)
        self.json_input_text.see("1.0")
        self.json_input_text.edit_modified(False)

    def get_passphrase(self) -> str:
        return self.phrase_var.get()

    def is_save_sqlite_enabled(self) -> bool:
        return self.save_sqlite_enabled.get()

    def get_output_db_path(self) -> str:
        return self.output_db_var.get().strip()

    def set_output_db_path(self, path: str):
        self.output_db_var.set(path)

    def is_export_json_enabled(self) -> bool:
        return self.export_json_enabled.get()

    def get_export_json_path(self) -> str:
        return self.output_json_var.get().strip()

    def set_export_json_path(self, path: str):
        self.output_json_var.set(path)

    def set_decrypt_button_enabled(self, enabled: bool):
        self.decrypt_btn.configure(state="normal" if enabled else "disabled")

    def set_payload_button_enabled(self, enabled: bool):
        self.decrypt_payload_btn.configure(state="normal" if enabled else "disabled")

    def log(self, message: str):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", message + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def set_result_json(self, text: str):
        self.result_text.delete("1.0", "end")
        self.result_text.insert("1.0", text)
        self.result_text.see("1.0")

    def get_result_json(self) -> str:
        return self.result_text.get("1.0", "end")

    def get_rsa_pem(self) -> str:
        return self.rsa_pem_text.get("1.0", "end")

    def set_rsa_pem(self, text: str):
        self.rsa_pem_text.delete("1.0", "end")
        self.rsa_pem_text.insert("1.0", text)
        self.rsa_pem_text.see("1.0")

    def get_payload_key(self) -> str:
        return self.payload_key_text.get("1.0", "end")

    def get_api_payload(self) -> str:
        return self.api_payload_text.get("1.0", "end")

    def get_api_payload_result(self) -> str:
        return self.api_payload_result_text.get("1.0", "end")

    def set_api_payload_result(self, text: str):
        self.api_payload_result_text.delete("1.0", "end")
        self.api_payload_result_text.insert("1.0", text)
        self.api_payload_result_text.see("1.0")
