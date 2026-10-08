"""
Modelo (MVC): logica de cifrado/desencriptado y persistencia.

No importa nada de Tkinter/ttkbootstrap: es logica pura, reutilizable desde
la UI, desde tests, o desde una CLI si hiciera falta.
"""

import base64
import binascii
import datetime
import json
import os
import sqlite3

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes

PHRASE_ENV_VAR = "SEID_CRYPTO_PHRASE"
NONCE_SIZE_EXPECTED = 12
TAG_SIZE_EXPECTED = 16


# ---------------------------------------------------------------------------
# data.json (legacy): envelope base64 -> AES-256-GCM
# ---------------------------------------------------------------------------

def parse_envelope(value: str):
    """Devuelve (nonce, tag, ciphertext) si value tiene el formato legacy, o None."""
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None

    if len(raw) < 4:
        return None

    nonce_size = int.from_bytes(raw[0:4], "little", signed=False)
    if nonce_size != NONCE_SIZE_EXPECTED:
        return None

    offset = 4
    if len(raw) < offset + nonce_size + 4:
        return None
    nonce = raw[offset:offset + nonce_size]
    offset += nonce_size

    tag_size = int.from_bytes(raw[offset:offset + 4], "little", signed=False)
    if tag_size != TAG_SIZE_EXPECTED:
        return None
    offset += 4

    if len(raw) < offset + tag_size:
        return None
    tag = raw[offset:offset + tag_size]
    offset += tag_size

    ciphertext = raw[offset:]
    return nonce, tag, ciphertext


def decrypt_envelope(nonce: bytes, tag: bytes, ciphertext: bytes, key: bytes) -> str:
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)
    return plaintext.decode("utf-8")


def walk(obj, path: str, key: bytes, stats: dict):
    if isinstance(obj, dict):
        return {k: walk(v, f"{path}.{k}" if path else k, key, stats) for k, v in obj.items()}

    if isinstance(obj, list):
        return [walk(v, f"{path}[{i}]", key, stats) for i, v in enumerate(obj)]

    if isinstance(obj, str):
        envelope = parse_envelope(obj)
        if envelope is None:
            return obj

        stats["candidates"] += 1
        nonce, tag, ciphertext = envelope
        try:
            return decrypt_envelope(nonce, tag, ciphertext, key)
        except InvalidTag:
            stats["failed"].append((path, "tag invalido (frase incorrecta o dato corrupto)"))
            return obj
        except UnicodeDecodeError:
            stats["failed"].append((path, "el texto desencriptado no es UTF-8 valido"))
            return obj
        except Exception as exc:  # defensivo: no exponer el valor cifrado en el mensaje
            stats["failed"].append((path, f"error inesperado: {type(exc).__name__}"))
            return obj

    return obj


def find_all_entries_by_key_substring(obj, substring: str, path: str = ""):
    """Busca recursivamente, sin importar mayusculas/minusculas, todas las claves cuyo
    nombre contenga substring y cuyo valor sea un string. Devuelve una lista de
    (path, key_name, value). Mas permisivo que un match exacto: encuentra 'PrivateKeyPem',
    'RsaPrivateKey', 'ApiPrivateKeyPem', etc. aunque no se llamen todas igual."""
    substring_lower = substring.lower()
    matches = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            child_path = f"{path}.{k}" if path else k
            if substring_lower in k.lower() and isinstance(v, str):
                matches.append((child_path, k, v))
            matches.extend(find_all_entries_by_key_substring(v, substring, child_path))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            matches.extend(find_all_entries_by_key_substring(item, substring, f"{path}[{i}]"))
    return matches


def environment_for_path(root_data, path: str):
    """Si root_data es una lista y path empieza con '[i]', devuelve data[i]['Environment']
    (o None). Sirve para mostrarle al usuario a que entorno pertenece cada coincidencia."""
    if not (isinstance(root_data, list) and path.startswith("[")):
        return None
    try:
        index = int(path[1:path.index("]")])
        item = root_data[index]
    except (ValueError, IndexError):
        return None
    return item.get("Environment") if isinstance(item, dict) else None


def init_db(conn: sqlite3.Connection):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS config_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_file TEXT NOT NULL,
            created_at TEXT NOT NULL,
            full_json TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS decrypt_errors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_id INTEGER NOT NULL,
            item_index INTEGER,
            environment TEXT,
            json_path TEXT NOT NULL,
            error TEXT NOT NULL,
            FOREIGN KEY (snapshot_id) REFERENCES config_snapshots(id)
        )
    """)
    conn.commit()


def decrypt_json_text(json_text: str, passphrase: str):
    """Parsea json_text, desencripta los valores candidatos y devuelve (data, decrypted, stats)."""
    try:
        data = json.loads(json_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"El texto ingresado no es JSON valido: {exc}")

    if not isinstance(data, (list, dict)):
        raise ValueError("Se esperaba que la raiz del JSON fuera un objeto o un array.")

    key = passphrase.encode("utf-8")
    if len(key) != 32:
        raise ValueError(
            f"La frase debe ocupar exactamente 32 bytes UTF-8 (recibidos: {len(key)}). "
            "Revisa que no tenga caracteres especiales que ocupen mas de 1 byte."
        )

    stats = {"candidates": 0, "failed": []}
    decrypted = walk(data, "", key, stats)
    return data, decrypted, stats


def save_snapshot(output_db: str | None, source_label: str, data, decrypted, stats: dict,
                   export_json_path: str | None = None):
    """Arma el resumen; si output_db se indica, ademas guarda el snapshot en SQLite (opcional)."""
    snapshot_id = None

    if output_db:
        conn = sqlite3.connect(output_db)
        try:
            init_db(conn)
            created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
            cur = conn.execute(
                "INSERT INTO config_snapshots (source_file, created_at, full_json) VALUES (?, ?, ?)",
                (source_label, created_at, json.dumps(decrypted, ensure_ascii=False)),
            )
            snapshot_id = cur.lastrowid

            for path, error in stats["failed"]:
                item_index = None
                environment = None
                if path.startswith("[") and "]" in path:
                    try:
                        item_index = int(path[1:path.index("]")])
                        item = data[item_index]
                        if isinstance(item, dict):
                            environment = item.get("Environment")
                    except (ValueError, IndexError):
                        pass
                conn.execute(
                    "INSERT INTO decrypt_errors (snapshot_id, item_index, environment, json_path, error) VALUES (?, ?, ?, ?, ?)",
                    (snapshot_id, item_index, environment, path, error),
                )
            conn.commit()
        finally:
            conn.close()

    if export_json_path:
        with open(export_json_path, "w", encoding="utf-8") as f:
            json.dump(decrypted, f, ensure_ascii=False, indent=2)

    return {
        "snapshot_id": snapshot_id,
        "candidates": stats["candidates"],
        "failed": stats["failed"],
        "decrypted": decrypted,
        "output_db": os.path.abspath(output_db) if output_db else None,
        "export_json_path": os.path.abspath(export_json_path) if export_json_path else None,
    }


def run_decryption_from_text(json_text: str, passphrase: str, output_db: str | None = None,
                              export_json_path: str | None = None,
                              source_label: str = "pegado manualmente en la app"):
    """Desencripta JSON pegado como texto. Guarda en SQLite solo si se indica output_db."""
    data, decrypted, stats = decrypt_json_text(json_text, passphrase)
    return save_snapshot(output_db, source_label, data, decrypted, stats, export_json_path)


def run_decryption(input_path: str, passphrase: str, output_db: str | None = None,
                    export_json_path: str | None = None):
    """Desencripta un data.json desde disco. Guarda en SQLite solo si se indica output_db."""
    if not os.path.isfile(input_path):
        raise ValueError(f"No se encontro el archivo de entrada '{input_path}'.")

    with open(input_path, "r", encoding="utf-8") as f:
        json_text = f.read()

    data, decrypted, stats = decrypt_json_text(json_text, passphrase)
    return save_snapshot(output_db, os.path.abspath(input_path), data, decrypted, stats, export_json_path)


# ---------------------------------------------------------------------------
# Payload de API: AES key por-request envuelta en RSA (header X-Payload-Key)
#   - X-Payload-Key (base64) = AES-256 key (32 bytes) cifrada con RSA (normalmente 256
#     bytes decodificados = RSA-2048), usando la llave privada RSA que viene dentro del
#     data.json (NO es la frase de 32 caracteres / SEID_CRYPTO_PHRASE).
#   - El body "encrypted" (base64) = nonce(12) | ciphertext | tag(16), concatenados
#     SIN length-prefix (a diferencia del formato legacy del data.json).
# ---------------------------------------------------------------------------

RSA_PADDING_SCHEMES = [
    ("OAEP-SHA256", lambda: rsa_padding.OAEP(mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)),
    ("OAEP-SHA1", lambda: rsa_padding.OAEP(mgf=rsa_padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None)),
    ("PKCS1v15", lambda: rsa_padding.PKCS1v15()),
]


def load_rsa_private_key_from_pem(pem_text: str):
    """Carga una llave privada RSA desde texto PEM. Tolera \\n literales en vez de saltos reales."""
    candidates = [pem_text, pem_text.replace("\\r\\n", "\n").replace("\\n", "\n")]
    last_error = None
    for candidate in candidates:
        try:
            return load_pem_private_key(candidate.encode("utf-8"), password=None)
        except Exception as exc:
            last_error = exc
    raise ValueError(f"No se pudo leer la llave privada RSA (PEM invalido): {last_error}")


def normalize_base64_payload(raw_text: str) -> str:
    """Acepta el valor base64 tal cual, o el JSON completo (p.ej. {"encrypted": "..."})
    tal como se copia del panel de Payload/Response de las devtools - que ademas suele
    traer \\u002B en vez de '+'. Devuelve el base64 limpio en cualquiera de los dos casos."""
    text = raw_text.strip()
    if not text.startswith("{") and not text.startswith('"'):
        return text

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return text

    if isinstance(parsed, str):
        return parsed.strip()

    if isinstance(parsed, dict):
        if isinstance(parsed.get("encrypted"), str):
            return parsed["encrypted"].strip()
        string_values = [v for v in parsed.values() if isinstance(v, str)]
        if len(string_values) == 1:
            return string_values[0].strip()

    return text


def unwrap_aes_key(private_key, wrapped_key_b64: str) -> tuple[bytes, str]:
    """Desencripta (RSA) el X-Payload-Key y devuelve (aes_key_bytes, esquema_usado)."""
    wrapped_key_b64 = normalize_base64_payload(wrapped_key_b64)
    try:
        wrapped = base64.b64decode(wrapped_key_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"X-Payload-Key no es base64 valido: {exc}")

    last_error = None
    for name, padding_factory in RSA_PADDING_SCHEMES:
        try:
            key_bytes = private_key.decrypt(wrapped, padding_factory())
        except Exception as exc:
            last_error = exc
            continue
        if len(key_bytes) == 32:
            return key_bytes, name
        last_error = ValueError(f"con padding {name} el resultado midio {len(key_bytes)} bytes (se esperaban 32)")

    raise ValueError(
        "No se pudo desenvolver una AES key de 32 bytes con ningun padding RSA probado "
        f"(OAEP-SHA256, OAEP-SHA1, PKCS1v15). Verifica que la llave privada sea la correcta. "
        f"Ultimo error: {last_error}"
    )


def diagnose_unwrap_failure(private_key, wrapped_key_b64: str) -> str:
    """Arma un reporte linea por linea de por que fallo el unwrap de X-Payload-Key: tamanos,
    el resultado (exito/excepcion) de cada esquema de padding probado, y un chequeo de bajo
    nivel (RSA sin padding) para ver si el resultado tiene o no pinta de PKCS1v1.5 valido.
    Pensado para copiar/pegar el resultado tal cual, no para parsearlo."""
    lines = []
    key_size_bytes = private_key.key_size // 8
    lines.append(f"Llave privada: {private_key.key_size} bits ({key_size_bytes} bytes de modulo)")

    try:
        wrapped = base64.b64decode(normalize_base64_payload(wrapped_key_b64), validate=True)
    except (binascii.Error, ValueError) as exc:
        lines.append(f"X-Payload-Key no es base64 valido: {exc}")
        return "\n".join(lines)

    lines.append(f"X-Payload-Key decodificado: {len(wrapped)} bytes (se esperaban {key_size_bytes})")
    if len(wrapped) != key_size_bytes:
        lines.append(
            "-> El tamano NO coincide con el modulo de la llave: la llave y el X-Payload-Key "
            "no son del mismo par, o uno de los dos se copio mal/incompleto."
        )

    for name, padding_factory in RSA_PADDING_SCHEMES:
        try:
            key_bytes = private_key.decrypt(wrapped, padding_factory())
            lines.append(f"{name}: sin excepcion, resultado de {len(key_bytes)} bytes (se esperaban 32)")
        except Exception as exc:
            lines.append(f"{name}: fallo ({type(exc).__name__}: {exc})")

    if len(wrapped) == key_size_bytes:
        try:
            numbers = private_key.private_numbers()
            c = int.from_bytes(wrapped, "big")
            m = pow(c, numbers.d, numbers.public_numbers.n)
            raw = m.to_bytes(key_size_bytes, "big")
            looks_like_pkcs1 = raw[0] == 0 and raw[1] == 2
            lines.append(f"RSA sin padding (diagnostico de bajo nivel): primeros 4 bytes = {raw[:4].hex()}")
            if looks_like_pkcs1:
                lines.append("-> Tiene estructura de padding PKCS1v1.5 valido (empieza con 00 02).")
            else:
                lines.append(
                    "-> NO tiene estructura de padding RSA valido (deberia empezar con 00 02 y no es "
                    "asi). Esto confirma que esta llave privada NO es la que cifro este X-Payload-Key "
                    "puntual (par de llaves distinto, o el X-Payload-Key es de otra request/instancia)."
                )
        except Exception as exc:
            lines.append(f"No se pudo hacer el diagnostico de bajo nivel: {type(exc).__name__}: {exc}")

    return "\n".join(lines)


def decrypt_api_payload(aes_key: bytes, payload_b64: str) -> str:
    """Desencripta el body 'encrypted' de la API: nonce(12) | ciphertext | tag(16), sin length-prefix."""
    payload_b64 = normalize_base64_payload(payload_b64)
    try:
        raw = base64.b64decode(payload_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"El payload no es base64 valido: {exc}")

    if len(raw) < NONCE_SIZE_EXPECTED + TAG_SIZE_EXPECTED:
        raise ValueError(f"El payload es demasiado corto ({len(raw)} bytes) para contener nonce+tag.")

    nonce = raw[:NONCE_SIZE_EXPECTED]
    ciphertext_and_tag = raw[NONCE_SIZE_EXPECTED:]

    aesgcm = AESGCM(aes_key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext_and_tag, None)
    except InvalidTag:
        raise ValueError("Tag invalido: la AES key desenvuelta no corresponde a este payload (o esta corrupto).")
    return plaintext.decode("utf-8")


def decrypt_api_payload_full(pem_text: str, wrapped_key_b64: str, payload_b64: str):
    """Flujo completo: PEM -> private key -> RSA-unwrap de la AES key -> AES-GCM decrypt del payload.
    Si falla el unwrap del RSA, le agrega al mensaje de error un diagnostico detallado
    (ver diagnose_unwrap_failure) para no tener que reproducirlo aparte."""
    private_key = load_rsa_private_key_from_pem(pem_text)
    try:
        aes_key, scheme = unwrap_aes_key(private_key, wrapped_key_b64)
    except ValueError as exc:
        trace = diagnose_unwrap_failure(private_key, wrapped_key_b64)
        raise ValueError(f"{exc}\n\n--- Diagnostico ---\n{trace}") from exc
    plaintext = decrypt_api_payload(aes_key, payload_b64)
    return plaintext, scheme
