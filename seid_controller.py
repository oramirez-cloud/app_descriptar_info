"""
Controlador (MVC): conecta los eventos de la vista con el modelo.

No construye widgets (eso es de seid_view.DecryptView) ni implementa
criptografia (eso es de seid_model): solo orquesta - valida entradas, corre
el trabajo pesado en un hilo aparte, y vuelca los resultados en la vista.
"""

import json
import os
import threading

import customtkinter as ctk

import seid_model as model
from seid_view import DecryptView


class DecryptController:
    def __init__(self, root: ctk.CTk):
        self.source_label = "pegado manualmente en la app"
        self.view = DecryptView(root, callbacks={
            "on_decrypt": self.on_decrypt,
            "on_decrypt_payload": self.on_decrypt_api_payload,
            "on_browse_input": self.browse_input,
            "on_browse_output_db": self.browse_output_db,
            "on_browse_output_json": self.browse_output_json,
            "on_autofill_pem": self.autofill_rsa_pem,
            "on_json_text_modified": self.on_json_text_modified,
        })

    # -----------------------------------------------------------------
    # Pestaña data.json (legacy)
    # -----------------------------------------------------------------

    def on_json_text_modified(self):
        self.source_label = "pegado/editado manualmente en la app"

    def browse_input(self):
        path = self.view.ask_open_json_file()
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
        except OSError as exc:
            self.view.show_error("Error", f"No se pudo leer el archivo: {exc}")
            return
        self.view.set_json_input(content)
        self.source_label = os.path.abspath(path)

    def browse_output_db(self):
        path = self.view.ask_save_sqlite_path()
        if path:
            self.view.set_output_db_path(path)

    def browse_output_json(self):
        path = self.view.ask_save_json_path()
        if path:
            self.view.set_export_json_path(path)

    def on_decrypt(self):
        json_text = self.view.get_json_input()
        passphrase = self.view.get_passphrase()
        output_db = self.view.get_output_db_path() if self.view.is_save_sqlite_enabled() else None
        export_json_path = self.view.get_export_json_path() if self.view.is_export_json_enabled() else None

        if not json_text:
            self.view.show_error("Falta informacion", "Pega el JSON de entrada o cargalo desde un archivo.")
            return
        if not passphrase:
            self.view.show_error("Falta informacion", "Ingresa la frase de 32 caracteres.")
            return
        if self.view.is_save_sqlite_enabled() and not output_db:
            self.view.show_error("Falta informacion", "Indica donde guardar la base SQLite, o desmarca esa opcion.")
            return
        if self.view.is_export_json_enabled() and not export_json_path:
            self.view.show_error("Falta informacion", "Indica donde guardar el JSON exportado, o desmarca esa opcion.")
            return

        self.view.set_decrypt_button_enabled(False)
        self.view.clear_log()
        self.view.log("Procesando...")

        thread = threading.Thread(
            target=self._decrypt_worker,
            args=(json_text, passphrase, output_db, export_json_path, self.source_label),
            daemon=True,
        )
        thread.start()

    def _decrypt_worker(self, json_text, passphrase, output_db, export_json_path, source_label):
        try:
            result = model.run_decryption_from_text(json_text, passphrase, output_db, export_json_path, source_label)
        except ValueError as exc:
            self.view.after(0, self._on_decrypt_error, str(exc))
            return
        except Exception as exc:
            self.view.after(0, self._on_decrypt_error, f"Error inesperado: {type(exc).__name__}: {exc}")
            return
        self.view.after(0, self._on_decrypt_success, result)

    def _on_decrypt_error(self, message: str):
        self.view.set_decrypt_button_enabled(True)
        self.view.clear_log()
        self.view.log(f"ERROR: {message}")
        self.view.show_error("Error", message)

    def _on_decrypt_success(self, result: dict):
        self.view.set_decrypt_button_enabled(True)
        self.view.clear_log()
        self.view.set_result_json(json.dumps(result["decrypted"], ensure_ascii=False, indent=2))

        failed = result["failed"]
        ok_count = result["candidates"] - len(failed)

        self.view.log(f"Valores candidatos a cifrado encontrados: {result['candidates']}")
        self.view.log(f"Desencriptados correctamente: {ok_count}")
        self.view.log(f"Fallidos: {len(failed)}")
        if result["output_db"]:
            self.view.log(f"Snapshot guardado en SQLite: {result['output_db']} (snapshot_id={result['snapshot_id']})")
        if result["export_json_path"]:
            self.view.log(f"JSON en claro exportado en: {result['export_json_path']}")
            self.view.log("  -> Contiene credenciales. Protegelo y bórralo cuando termines.")

        if failed:
            self.view.log("\nCampos que no se pudieron desencriptar:")
            for path, error in failed:
                self.view.log(f"  - {path}: {error}")
            self.view.log("\nSi todos fallaron, lo mas probable es que la frase sea incorrecta.")
            self.view.show_warning(
                "Terminado con errores",
                f"{len(failed)} valor(es) no se pudieron desencriptar. Revisa el detalle en la ventana."
            )
        elif result["candidates"] == 0:
            self.view.log("\nNo se encontro ningun valor con el formato cifrado esperado (nonceSize=12 al inicio del base64).")
            self.view.log("El JSON de entrada quedo igual: probablemente no es el data.json con el formato legacy, o los valores ya estan en claro.")
            self.view.show_warning(
                "Nada para desencriptar",
                "No se encontro ningun valor con el formato cifrado esperado. El JSON quedo igual al de entrada."
            )
        else:
            self.view.show_info("Listo", f"Los {result['candidates']} valor(es) cifrados se desencriptaron correctamente.")

    # -----------------------------------------------------------------
    # Pestaña Payload de API
    # -----------------------------------------------------------------

    def autofill_rsa_pem(self):
        content = self.view.get_result_json()
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            self.view.show_warning(
                "No encontrado",
                "El resultado de la pestana data.json no es JSON valido. "
                "Desencripta primero el data.json ahi, o pega la llave manualmente."
            )
            return

        # Busqueda amplia (no exacta): cualquier campo cuyo nombre contenga "private",
        # para no depender de que se llame exactamente "PrivateKeyPem" (puede haber mas
        # de una llave RSA en el JSON con nombres distintos segun para que se use cada una).
        matches = model.find_all_entries_by_key_substring(data, "private")
        if not matches:
            self.view.show_warning(
                "No encontrado",
                "No se encontro ningun campo con 'private' en el nombre dentro del resultado "
                "de la pestana data.json. Desencripta primero el data.json ahi, o pega la llave "
                "manualmente."
            )
            return

        if len(matches) == 1:
            pem_value = matches[0][2]
        else:
            labels = []
            for path, key_name, _ in matches:
                environment = model.environment_for_path(data, path)
                label = f"{key_name} — {path}"
                labels.append(f"{environment} — {label}" if environment else label)
            self.view.show_warning(
                "Varias llaves encontradas",
                f"Se encontraron {len(matches)} campos con 'private' en el nombre (puede ser una "
                "por entorno, o llaves distintas para distintos usos). Si usaste la que no "
                "corresponde a este request, el desencriptado del payload va a fallar (padding "
                "RSA invalido). Elegi la correcta en la siguiente ventana."
            )
            index = self.view.ask_choice(
                "Elegir llave privada RSA",
                "Esta request fue capturada contra un backend especifico: elegi la llave que "
                "corresponda (mira el nombre del campo y el 'Environment' de cada una en el "
                "JSON desencriptado si no estas seguro cual es).",
                labels,
            )
            if index is None:
                return
            pem_value = matches[index][2]

        self.view.set_rsa_pem(pem_value.strip())

    def on_decrypt_api_payload(self):
        pem_text = self.view.get_rsa_pem().strip()
        wrapped_key_b64 = self.view.get_payload_key().strip()
        payload_b64 = self.view.get_api_payload().strip()

        if not pem_text:
            self.view.show_error("Falta informacion", "Pega la llave privada RSA (PEM).")
            return
        if not wrapped_key_b64:
            self.view.show_error("Falta informacion", "Pega el valor del header X-Payload-Key.")
            return
        if not payload_b64:
            self.view.show_error("Falta informacion", 'Pega el payload cifrado (campo "encrypted").')
            return

        self.view.set_payload_button_enabled(False)
        self.view.set_api_payload_result("")

        thread = threading.Thread(
            target=self._decrypt_api_payload_worker,
            args=(pem_text, wrapped_key_b64, payload_b64),
            daemon=True,
        )
        thread.start()

    def _decrypt_api_payload_worker(self, pem_text, wrapped_key_b64, payload_b64):
        try:
            plaintext, scheme = model.decrypt_api_payload_full(pem_text, wrapped_key_b64, payload_b64)
        except ValueError as exc:
            self.view.after(0, self._on_api_payload_error, str(exc))
            return
        except Exception as exc:
            self.view.after(0, self._on_api_payload_error, f"Error inesperado: {type(exc).__name__}: {exc}")
            return
        self.view.after(0, self._on_api_payload_success, plaintext, scheme)

    def _on_api_payload_error(self, message: str):
        self.view.set_payload_button_enabled(True)
        self.view.set_api_payload_result(f"ERROR\n\n{message}")
        self.view.show_error(
            "Error",
            "No se pudo desencriptar el payload. El detalle (con diagnostico, si aplica) "
            "quedo en el cuadro de Resultado — copialo con el boton si lo necesitas compartir."
        )

    def _on_api_payload_success(self, plaintext: str, scheme: str):
        self.view.set_payload_button_enabled(True)
        self.view.set_api_payload_result(plaintext)
        self.view.show_info("Listo", f"Payload desencriptado correctamente (padding RSA usado: {scheme}).")
