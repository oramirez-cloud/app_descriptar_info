"use strict";

/*
 * Desencriptador data.json (SEID) - version navegador.
 * Todo corre client-side con la Web Crypto API nativa: no hay backend, no hay
 * instalacion. Abrir index.html directo en el navegador alcanza.
 *
 * Formato legacy de cada valor cifrado en data.json (antes de base64):
 *   nonceSize:int32-LE(4) | nonce(nonceSize) | tagSize:int32-LE(4) | tag(tagSize) | ciphertext
 *
 * Payload de API (X-Payload-Key): RSA-OAEP-SHA256 sobre el STRING base64 de la AES key
 * (no los 32 bytes crudos) -> por eso, tras el RSA-decrypt, hay que volver a decodificar
 * en base64 una vez mas para llegar a los 32 bytes reales.
 */

const NONCE_SIZE_EXPECTED = 12;
const TAG_SIZE_EXPECTED = 16;

// ---------------------------------------------------------------------------
// Helpers de base64 / bytes
// ---------------------------------------------------------------------------

function base64ToBytes(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function bytesToBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

// ---------------------------------------------------------------------------
// data.json (legacy): envelope base64 -> AES-256-GCM
// ---------------------------------------------------------------------------

function parseEnvelope(value) {
  let raw;
  try {
    raw = base64ToBytes(value);
  } catch (e) {
    return null;
  }
  if (raw.length < 4) return null;

  const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  const nonceSize = view.getUint32(0, true);
  if (nonceSize !== NONCE_SIZE_EXPECTED) return null;

  let offset = 4;
  if (raw.length < offset + nonceSize + 4) return null;
  const nonce = raw.slice(offset, offset + nonceSize);
  offset += nonceSize;

  const tagSize = view.getUint32(offset, true);
  if (tagSize !== TAG_SIZE_EXPECTED) return null;
  offset += 4;

  if (raw.length < offset + tagSize) return null;
  const tag = raw.slice(offset, offset + tagSize);
  offset += tagSize;

  const ciphertext = raw.slice(offset);
  return { nonce, tag, ciphertext };
}

async function decryptEnvelope(nonce, tag, ciphertext, keyBytes) {
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
  const combined = new Uint8Array(ciphertext.length + tag.length);
  combined.set(ciphertext, 0);
  combined.set(tag, ciphertext.length);

  let plainBuf;
  try {
    plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, combined);
  } catch (e) {
    throw new Error("tag invalido (frase incorrecta o dato corrupto)");
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(plainBuf);
  } catch (e) {
    throw new Error("el texto desencriptado no es UTF-8 valido");
  }
}

async function walk(obj, path, keyBytes, stats) {
  if (Array.isArray(obj)) {
    const result = [];
    for (let i = 0; i < obj.length; i++) {
      result.push(await walk(obj[i], `${path}[${i}]`, keyBytes, stats));
    }
    return result;
  }
  if (obj !== null && typeof obj === "object") {
    const result = {};
    for (const k of Object.keys(obj)) {
      result[k] = await walk(obj[k], path ? `${path}.${k}` : k, keyBytes, stats);
    }
    return result;
  }
  if (typeof obj === "string") {
    const envelope = parseEnvelope(obj);
    if (!envelope) return obj;
    stats.candidates++;
    try {
      return await decryptEnvelope(envelope.nonce, envelope.tag, envelope.ciphertext, keyBytes);
    } catch (e) {
      stats.failed.push([path, e.message]);
      return obj;
    }
  }
  return obj;
}

function findAllEntriesByKeySubstring(obj, substring, path = "") {
  const needle = substring.toLowerCase();
  let matches = [];
  if (Array.isArray(obj)) {
    obj.forEach((item, i) => {
      matches = matches.concat(findAllEntriesByKeySubstring(item, substring, `${path}[${i}]`));
    });
  } else if (obj !== null && typeof obj === "object") {
    for (const [k, v] of Object.entries(obj)) {
      const childPath = path ? `${path}.${k}` : k;
      if (k.toLowerCase().includes(needle) && typeof v === "string") {
        matches.push([childPath, k, v]);
      }
      matches = matches.concat(findAllEntriesByKeySubstring(v, substring, childPath));
    }
  }
  return matches;
}

function environmentForPath(rootData, path) {
  if (!(Array.isArray(rootData) && path.startsWith("["))) return null;
  const closeIdx = path.indexOf("]");
  if (closeIdx === -1) return null;
  const index = parseInt(path.slice(1, closeIdx), 10);
  if (Number.isNaN(index)) return null;
  const item = rootData[index];
  return item && typeof item === "object" && "Environment" in item ? item.Environment : null;
}

async function decryptJsonText(jsonText, passphrase) {
  let data;
  try {
    data = JSON.parse(jsonText);
  } catch (e) {
    throw new Error(`El texto ingresado no es JSON valido: ${e.message}`);
  }
  if (data === null || typeof data !== "object") {
    throw new Error("Se esperaba que la raiz del JSON fuera un objeto o un array.");
  }

  const keyBytes = new TextEncoder().encode(passphrase);
  if (keyBytes.length !== 32) {
    throw new Error(
      `La frase debe ocupar exactamente 32 bytes UTF-8 (recibidos: ${keyBytes.length}). ` +
      "Revisa que no tenga caracteres especiales que ocupen mas de 1 byte."
    );
  }

  const stats = { candidates: 0, failed: [] };
  const decrypted = await walk(data, "", keyBytes, stats);
  return { data, decrypted, stats };
}

// ---------------------------------------------------------------------------
// Payload de API: AES key por-request envuelta en RSA (header X-Payload-Key)
// ---------------------------------------------------------------------------

function normalizeBase64Payload(rawText) {
  const text = rawText.trim();
  if (!text.startsWith("{") && !text.startsWith('"')) return text;

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    return text;
  }

  if (typeof parsed === "string") return parsed.trim();

  if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
    if (typeof parsed.encrypted === "string") return parsed.encrypted.trim();
    const stringValues = Object.values(parsed).filter((v) => typeof v === "string");
    if (stringValues.length === 1) return stringValues[0].trim();
  }

  return text;
}

function pemToDer(pemText) {
  const body = pemText
    .replace(/-----BEGIN [^-]+-----/, "")
    .replace(/-----END [^-]+-----/, "")
    .replace(/\\r\\n/g, "\n")
    .replace(/\\n/g, "\n")
    .replace(/\s+/g, "");
  return base64ToBytes(body);
}

async function importRsaPrivateKeyFromPem(pemText) {
  let der;
  try {
    der = pemToDer(pemText);
  } catch (e) {
    throw new Error(`No se pudo leer la llave privada RSA (PEM invalido): ${e.message}`);
  }
  try {
    return await crypto.subtle.importKey(
      "pkcs8",
      der.buffer,
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["decrypt"]
    );
  } catch (e) {
    throw new Error(
      "No se pudo leer la llave privada RSA (solo se soporta PKCS#8, es decir texto que "
      + `empiece con '-----BEGIN PRIVATE KEY-----'): ${e.message}`
    );
  }
}

async function unwrapAesKey(privateKey, wrappedKeyB64) {
  const normalized = normalizeBase64Payload(wrappedKeyB64);
  let wrapped;
  try {
    wrapped = base64ToBytes(normalized);
  } catch (e) {
    throw new Error(`X-Payload-Key no es base64 valido: ${e.message}`);
  }

  let decrypted;
  try {
    decrypted = new Uint8Array(await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, wrapped));
  } catch (e) {
    throw new Error(
      "No se pudo desencriptar el X-Payload-Key con RSA-OAEP-SHA256. Verifica que la llave "
      + `privada sea la correcta para este backend (${e.message}).`
    );
  }

  if (decrypted.length === 32) {
    return { keyBytes: decrypted, scheme: "OAEP-SHA256" };
  }

  // El cliente cifra el base64-string de la AES key, no los 32 bytes crudos.
  let innerText;
  try {
    innerText = new TextDecoder("utf-8", { fatal: true }).decode(decrypted).trim();
  } catch (e) {
    throw new Error(
      `El resultado del RSA-decrypt (${decrypted.length} bytes) no es texto valido; se esperaba `
      + "un base64-string de la AES key."
    );
  }

  let keyBytes;
  try {
    keyBytes = base64ToBytes(innerText);
  } catch (e) {
    throw new Error("El resultado del RSA-decrypt no es un base64-string valido de una AES key.");
  }

  if (keyBytes.length !== 32) {
    throw new Error(
      `Tras el doble base64-decode, el resultado mide ${keyBytes.length} bytes (se esperaban 32). `
      + "Verifica que la llave privada sea la correcta para este backend/ambiente."
    );
  }

  return { keyBytes, scheme: "OAEP-SHA256 (doble base64)" };
}

async function decryptApiPayload(aesKeyBytes, payloadB64) {
  const normalized = normalizeBase64Payload(payloadB64);
  let raw;
  try {
    raw = base64ToBytes(normalized);
  } catch (e) {
    throw new Error(`El payload no es base64 valido: ${e.message}`);
  }

  if (raw.length < NONCE_SIZE_EXPECTED + TAG_SIZE_EXPECTED) {
    throw new Error(`El payload es demasiado corto (${raw.length} bytes) para contener nonce+tag.`);
  }

  const nonce = raw.slice(0, NONCE_SIZE_EXPECTED);
  const ciphertextAndTag = raw.slice(NONCE_SIZE_EXPECTED);

  const key = await crypto.subtle.importKey("raw", aesKeyBytes, "AES-GCM", false, ["decrypt"]);
  try {
    const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, ciphertextAndTag);
    return new TextDecoder("utf-8", { fatal: true }).decode(plainBuf);
  } catch (e) {
    throw new Error("Tag invalido: la AES key desenvuelta no corresponde a este payload (o esta corrupto).");
  }
}

async function decryptApiPayloadFull(pemText, wrappedKeyB64, payloadB64) {
  const privateKey = await importRsaPrivateKeyFromPem(pemText);
  const { keyBytes, scheme } = await unwrapAesKey(privateKey, wrappedKeyB64);
  const plaintext = await decryptApiPayload(keyBytes, payloadB64);
  return { plaintext, scheme };
}

// ---------------------------------------------------------------------------
// Exports (para poder testear la logica pura con Node, sin DOM)
// ---------------------------------------------------------------------------

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    parseEnvelope,
    decryptEnvelope,
    walk,
    findAllEntriesByKeySubstring,
    environmentForPath,
    decryptJsonText,
    normalizeBase64Payload,
    importRsaPrivateKeyFromPem,
    unwrapAesKey,
    decryptApiPayload,
    decryptApiPayloadFull,
    base64ToBytes,
    bytesToBase64,
  };
}

// ---------------------------------------------------------------------------
// UI (solo corre en el navegador)
// ---------------------------------------------------------------------------

if (typeof document !== "undefined") {
  document.addEventListener("DOMContentLoaded", () => {
    const $ = (id) => document.getElementById(id);

    // --- Navegacion (sidebar) ---
    const navItems = document.querySelectorAll(".nav-item");
    const tabPanels = document.querySelectorAll(".tab-panel");
    navItems.forEach((btn) => {
      btn.addEventListener("click", () => {
        navItems.forEach((b) => b.classList.remove("active"));
        tabPanels.forEach((p) => p.classList.remove("active"));
        btn.classList.add("active");
        $(btn.dataset.tab).classList.add("active");
        closeSidebar();
      });
    });

    // --- Menu hamburguesa (sidebar off-canvas en mobile) ---
    const hamburgerBtn = $("hamburger-btn");
    const sidebar = $("sidebar");
    const sidebarOverlay = $("sidebar-overlay");

    function openSidebar() {
      sidebar.classList.add("open");
      sidebarOverlay.classList.add("open");
      hamburgerBtn.setAttribute("aria-expanded", "true");
    }
    function closeSidebar() {
      sidebar.classList.remove("open");
      sidebarOverlay.classList.remove("open");
      hamburgerBtn.setAttribute("aria-expanded", "false");
    }
    hamburgerBtn.addEventListener("click", () => {
      if (sidebar.classList.contains("open")) closeSidebar();
      else openSidebar();
    });
    sidebarOverlay.addEventListener("click", closeSidebar);

    // --- Tab 1: data.json ---
    const jsonInput = $("json-input");
    const phraseInput = $("phrase-input");
    const showPhraseToggle = $("show-phrase-toggle");
    const logBox = $("log-box");
    const resultBox = $("result-box");
    const decryptBtn = $("decrypt-btn");
    const loadFileInput = $("load-file-input");
    const loadFileBtn = $("load-file-btn");
    const exportJsonToggle = $("export-json-toggle");
    const copyResultBtn = $("copy-result-btn");
    const downloadResultBtn = $("download-result-btn");
    const expandResultBtn = $("expand-result-btn");

    let lastDecrypted = null;
    let lastSourceLabel = "pegado manualmente en la app";

    showPhraseToggle.addEventListener("change", () => {
      phraseInput.type = showPhraseToggle.checked ? "text" : "password";
    });

    jsonInput.addEventListener("input", () => {
      lastSourceLabel = "pegado/editado manualmente en la app";
    });

    loadFileBtn.addEventListener("click", () => loadFileInput.click());
    loadFileInput.addEventListener("change", async () => {
      const file = loadFileInput.files[0];
      if (!file) return;
      jsonInput.value = await file.text();
      lastSourceLabel = file.name;
      loadFileInput.value = "";
    });

    function log(message) {
      logBox.textContent += (logBox.textContent ? "\n" : "") + message;
      logBox.scrollTop = 0;
    }
    function clearLog() {
      logBox.textContent = "";
    }

    decryptBtn.addEventListener("click", async () => {
      const jsonText = jsonInput.value.trim();
      const passphrase = phraseInput.value;

      if (!jsonText) {
        alert("Pega el JSON de entrada o cargalo desde un archivo.");
        return;
      }
      if (!passphrase) {
        alert("Ingresa la frase de 32 caracteres.");
        return;
      }

      decryptBtn.disabled = true;
      clearLog();
      log("Procesando...");

      try {
        const { decrypted, stats } = await decryptJsonText(jsonText, passphrase);
        lastDecrypted = decrypted;

        const resultText = JSON.stringify(decrypted, null, 2);
        resultBox.value = resultText;
        resultBox.scrollTop = 0;

        const failed = stats.failed;
        const okCount = stats.candidates - failed.length;

        clearLog();
        log(`Valores candidatos a cifrado encontrados: ${stats.candidates}`);
        log(`Desencriptados correctamente: ${okCount}`);
        log(`Fallidos: ${failed.length}`);

        if (exportJsonToggle.checked) {
          downloadText(`decrypted_data_${Date.now()}.json`, resultText);
          log("JSON en claro descargado. Contiene credenciales: protegelo y borralo cuando termines.");
        }

        if (failed.length) {
          log("\nCampos que no se pudieron desencriptar:");
          failed.forEach(([path, error]) => log(`  - ${path}: ${error}`));
          log("\nSi todos fallaron, lo mas probable es que la frase sea incorrecta.");
          alert(`${failed.length} valor(es) no se pudieron desencriptar. Revisa el detalle abajo.`);
        } else if (stats.candidates === 0) {
          log("\nNo se encontro ningun valor con el formato cifrado esperado (nonceSize=12 al inicio del base64).");
          alert("No se encontro ningun valor con el formato cifrado esperado. El JSON quedo igual al de entrada.");
        } else {
          alert(`Los ${stats.candidates} valor(es) cifrados se desencriptaron correctamente.`);
        }
      } catch (e) {
        clearLog();
        log(`ERROR: ${e.message}`);
        alert(e.message);
      } finally {
        decryptBtn.disabled = false;
      }
    });

    copyResultBtn.addEventListener("click", () => copyToClipboard(resultBox.value));
    downloadResultBtn.addEventListener("click", () => {
      if (!resultBox.value.trim()) return;
      downloadText(`decrypted_data_${Date.now()}.json`, resultBox.value);
    });

    // --- Tab 2: Payload de API ---
    const pemInput = $("pem-input");
    const autofillPemBtn = $("autofill-pem-btn");
    const payloadKeyInput = $("payload-key-input");
    const apiPayloadInput = $("api-payload-input");
    const decryptPayloadBtn = $("decrypt-payload-btn");
    const payloadResultBox = $("payload-result-box");
    const copyPayloadResultBtn = $("copy-payload-result-btn");
    const expandPayloadResultBtn = $("expand-payload-result-btn");

    autofillPemBtn.addEventListener("click", () => {
      let data;
      try {
        data = JSON.parse(resultBox.value);
      } catch (e) {
        alert(
          "El resultado de la pestana data.json no es JSON valido. Desencripta primero el "
          + "data.json ahi, o pega la llave manualmente."
        );
        return;
      }

      const matches = findAllEntriesByKeySubstring(data, "private");
      if (!matches.length) {
        alert(
          "No se encontro ningun campo con 'private' en el nombre dentro del resultado de la "
          + "pestana data.json. Desencripta primero el data.json ahi, o pega la llave manualmente."
        );
        return;
      }

      if (matches.length === 1) {
        pemInput.value = matches[0][2].trim();
        pemInput.scrollTop = 0;
        return;
      }

      const labels = matches.map(([path, key]) => {
        const env = environmentForPath(data, path);
        const label = `${key} — ${path}`;
        return env ? `${env} — ${label}` : label;
      });
      showChoiceDialog(
        "Elegir llave privada RSA",
        "Se encontro mas de un campo con 'private' en el nombre. Elegi el que corresponda a "
        + "este request (mira el nombre del campo y el 'Environment' si no estas seguro).",
        labels,
        (index) => {
          if (index === null) return;
          pemInput.value = matches[index][2].trim();
          pemInput.scrollTop = 0;
        }
      );
    });

    decryptPayloadBtn.addEventListener("click", async () => {
      const pemText = pemInput.value.trim();
      const wrappedKeyB64 = payloadKeyInput.value.trim();
      const payloadB64 = apiPayloadInput.value.trim();

      if (!pemText) {
        alert("Pega la llave privada RSA (PEM).");
        return;
      }
      if (!wrappedKeyB64) {
        alert("Pega el valor del header X-Payload-Key.");
        return;
      }
      if (!payloadB64) {
        alert('Pega el payload cifrado (campo "encrypted").');
        return;
      }

      decryptPayloadBtn.disabled = true;
      payloadResultBox.value = "";

      try {
        const { plaintext, scheme } = await decryptApiPayloadFull(pemText, wrappedKeyB64, payloadB64);
        payloadResultBox.value = plaintext;
        payloadResultBox.scrollTop = 0;
        alert(`Payload desencriptado correctamente (esquema: ${scheme}).`);
      } catch (e) {
        payloadResultBox.value = `ERROR\n\n${e.message}`;
        payloadResultBox.scrollTop = 0;
        alert("No se pudo desencriptar el payload. El detalle quedo en el cuadro de Resultado.");
      } finally {
        decryptPayloadBtn.disabled = false;
      }
    });

    copyPayloadResultBtn.addEventListener("click", () => copyToClipboard(payloadResultBox.value));

    expandResultBtn.addEventListener("click", () => {
      openFullscreenViewer("JSON desencriptado", resultBox.value);
    });
    expandPayloadResultBtn.addEventListener("click", () => {
      openFullscreenViewer("Resultado", payloadResultBox.value);
    });

    // --- Helpers de UI compartidos ---

    function copyToClipboard(text) {
      text = text.trim();
      if (!text) return;
      navigator.clipboard.writeText(text).catch(() => {
        // Fallback para contextos sin permiso de clipboard API (p.ej. abierto como file://)
        const ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
      });
    }

    function downloadText(filename, text) {
      const blob = new Blob([text], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }

    function escapeHtml(str) {
      return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }

    // Resalta todas las apariciones de term en text (case-insensitive) envolviendolas en
    // <mark data-match="i">, escapando el resto. Devuelve {html, count}.
    function highlightMatches(text, term) {
      if (!term) return { html: escapeHtml(text), count: 0 };
      const lowerText = text.toLowerCase();
      const lowerTerm = term.toLowerCase();
      let html = "";
      let count = 0;
      let i = 0;
      while (i < text.length) {
        const idx = lowerText.indexOf(lowerTerm, i);
        if (idx === -1) {
          html += escapeHtml(text.slice(i));
          break;
        }
        html += escapeHtml(text.slice(i, idx));
        html += `<mark data-match="${count}">${escapeHtml(text.slice(idx, idx + term.length))}</mark>`;
        count++;
        i = idx + term.length;
      }
      return { html, count };
    }

    // Aplana un objeto/array anidado en filas [path, valor] para la vista de tabla. Objetos
    // y arrays vacios se muestran como "{}"/"[]"; todo lo demas se estringifica tal cual.
    function flattenForTable(obj, path = "") {
      if (Array.isArray(obj)) {
        if (obj.length === 0) return [[path || "(raiz)", "[]"]];
        return obj.flatMap((item, i) => flattenForTable(item, `${path}[${i}]`));
      }
      if (obj !== null && typeof obj === "object") {
        const keys = Object.keys(obj);
        if (keys.length === 0) return [[path || "(raiz)", "{}"]];
        return keys.flatMap((k) => flattenForTable(obj[k], path ? `${path}.${k}` : k));
      }
      return [[path || "(raiz)", obj === null ? "null" : String(obj)]];
    }

    function openFullscreenViewer(title, text) {
      if (!text.trim()) {
        alert("No hay nada para mostrar todavia.");
        return;
      }

      let parsedData = null;
      try {
        parsedData = JSON.parse(text);
        if (parsedData === null || typeof parsedData !== "object") parsedData = null;
      } catch (e) {
        parsedData = null;
      }

      const state = { mode: "json", search: "", currentMatch: 0 };

      const overlay = document.createElement("div");
      overlay.className = "dialog-overlay";

      const card = document.createElement("div");
      card.className = "fullscreen-card";

      // --- Header: titulo + copiar + cerrar ---
      const header = document.createElement("div");
      header.className = "fullscreen-header";

      const h = document.createElement("h3");
      h.textContent = title;
      header.appendChild(h);

      const actions = document.createElement("div");
      actions.className = "btn-group";

      const copyBtn = document.createElement("button");
      copyBtn.type = "button";
      copyBtn.className = "btn btn-secondary";
      copyBtn.textContent = "Copiar";
      copyBtn.addEventListener("click", () => copyToClipboard(text));
      actions.appendChild(copyBtn);

      const closeBtn = document.createElement("button");
      closeBtn.type = "button";
      closeBtn.className = "btn btn-primary";
      closeBtn.textContent = "Cerrar";
      const close = () => {
        document.body.removeChild(overlay);
        document.removeEventListener("keydown", onEsc);
      };
      closeBtn.addEventListener("click", close);
      actions.appendChild(closeBtn);

      header.appendChild(actions);
      card.appendChild(header);

      // --- Toolbar: JSON/Tabla + buscador ---
      const toolbar = document.createElement("div");
      toolbar.className = "fullscreen-toolbar";

      if (parsedData !== null) {
        const viewToggle = document.createElement("div");
        viewToggle.className = "view-toggle";

        const jsonModeBtn = document.createElement("button");
        jsonModeBtn.type = "button";
        jsonModeBtn.textContent = "JSON";
        jsonModeBtn.className = "active";

        const tableModeBtn = document.createElement("button");
        tableModeBtn.type = "button";
        tableModeBtn.textContent = "Tabla";

        jsonModeBtn.addEventListener("click", () => {
          state.mode = "json";
          jsonModeBtn.classList.add("active");
          tableModeBtn.classList.remove("active");
          render();
        });
        tableModeBtn.addEventListener("click", () => {
          state.mode = "table";
          tableModeBtn.classList.add("active");
          jsonModeBtn.classList.remove("active");
          render();
        });

        viewToggle.appendChild(jsonModeBtn);
        viewToggle.appendChild(tableModeBtn);
        toolbar.appendChild(viewToggle);
      }

      const searchBox = document.createElement("div");
      searchBox.className = "search-box";

      const searchInput = document.createElement("input");
      searchInput.type = "text";
      searchInput.placeholder = "Buscar...";

      const prevBtn = document.createElement("button");
      prevBtn.type = "button";
      prevBtn.className = "search-nav-btn";
      prevBtn.textContent = "↑";
      prevBtn.title = "Coincidencia anterior";

      const nextBtn = document.createElement("button");
      nextBtn.type = "button";
      nextBtn.className = "search-nav-btn";
      nextBtn.textContent = "↓";
      nextBtn.title = "Siguiente coincidencia";

      const status = document.createElement("span");
      status.className = "search-status";

      searchInput.addEventListener("input", () => {
        state.search = searchInput.value;
        state.currentMatch = 0;
        render();
      });

      prevBtn.addEventListener("click", () => {
        if (totalMatches <= 0) return;
        state.currentMatch = (state.currentMatch - 1 + totalMatches) % totalMatches;
        applyCurrentMatch();
      });
      nextBtn.addEventListener("click", () => {
        if (totalMatches <= 0) return;
        state.currentMatch = (state.currentMatch + 1) % totalMatches;
        applyCurrentMatch();
      });

      searchBox.appendChild(searchInput);
      searchBox.appendChild(prevBtn);
      searchBox.appendChild(nextBtn);
      searchBox.appendChild(status);
      toolbar.appendChild(searchBox);

      card.appendChild(toolbar);

      // --- Contenido (JSON resaltado o tabla) ---
      const content = document.createElement("div");
      content.className = "fullscreen-content";
      card.appendChild(content);

      let totalMatches = 0;

      function applyCurrentMatch() {
        const marks = content.querySelectorAll("mark");
        marks.forEach((m) => m.classList.remove("current-match"));
        if (marks.length) {
          const target = marks[state.currentMatch] || marks[0];
          target.classList.add("current-match");
          target.scrollIntoView({ block: "center" });
        }
        status.textContent = totalMatches
          ? `${state.currentMatch + 1} de ${totalMatches}`
          : (state.search ? "0 resultados" : "");
        prevBtn.disabled = totalMatches === 0;
        nextBtn.disabled = totalMatches === 0;
      }

      function render() {
        content.innerHTML = "";

        if (state.mode === "table" && parsedData !== null) {
          const rows = flattenForTable(parsedData);
          const term = state.search.toLowerCase();
          const filtered = term
            ? rows.filter(([p, v]) => p.toLowerCase().includes(term) || String(v).toLowerCase().includes(term))
            : rows;

          const table = document.createElement("table");
          table.className = "data-table";
          const thead = document.createElement("thead");
          thead.innerHTML = "<tr><th>Campo</th><th>Valor</th></tr>";
          table.appendChild(thead);

          const tbody = document.createElement("tbody");
          filtered.forEach(([p, v]) => {
            const tr = document.createElement("tr");
            const tdPath = document.createElement("td");
            tdPath.innerHTML = state.search ? highlightMatches(p, state.search).html : escapeHtml(p);
            const tdVal = document.createElement("td");
            tdVal.innerHTML = state.search ? highlightMatches(String(v), state.search).html : escapeHtml(String(v));
            tr.appendChild(tdPath);
            tr.appendChild(tdVal);
            tbody.appendChild(tr);
          });
          table.appendChild(tbody);
          content.appendChild(table);

          totalMatches = 0;
          status.textContent = term ? `${filtered.length} de ${rows.length} filas` : "";
          prevBtn.disabled = true;
          nextBtn.disabled = true;
          return;
        }

        const pre = document.createElement("pre");
        pre.className = "json-view";
        const { html, count } = highlightMatches(text, state.search);
        pre.innerHTML = html;
        content.appendChild(pre);

        totalMatches = count;
        applyCurrentMatch();
      }

      render();

      overlay.appendChild(card);
      overlay.addEventListener("click", (e) => {
        if (e.target === overlay) close();
      });
      function onEsc(e) {
        if (e.key === "Escape") close();
      }
      document.addEventListener("keydown", onEsc);

      document.body.appendChild(overlay);
      searchInput.focus();
    }

    function showChoiceDialog(title, message, options, onChoose) {
      const overlay = document.createElement("div");
      overlay.className = "dialog-overlay";

      const dialog = document.createElement("div");
      dialog.className = "dialog-card";

      const h = document.createElement("h3");
      h.textContent = title;
      dialog.appendChild(h);

      const p = document.createElement("p");
      p.textContent = message;
      dialog.appendChild(p);

      const list = document.createElement("div");
      list.className = "dialog-list";
      let selected = 0;
      const rows = options.map((label, i) => {
        const row = document.createElement("button");
        row.type = "button";
        row.className = "dialog-option" + (i === 0 ? " selected" : "");
        row.textContent = label;
        row.addEventListener("click", () => {
          selected = i;
          rows.forEach((r) => r.classList.remove("selected"));
          row.classList.add("selected");
        });
        list.appendChild(row);
        return row;
      });
      dialog.appendChild(list);

      const actions = document.createElement("div");
      actions.className = "dialog-actions";

      const cancelBtn = document.createElement("button");
      cancelBtn.type = "button";
      cancelBtn.className = "btn btn-secondary";
      cancelBtn.textContent = "Cancelar";
      cancelBtn.addEventListener("click", () => {
        document.body.removeChild(overlay);
        onChoose(null);
      });

      const okBtn = document.createElement("button");
      okBtn.type = "button";
      okBtn.className = "btn btn-primary";
      okBtn.textContent = "Usar esta";
      okBtn.addEventListener("click", () => {
        document.body.removeChild(overlay);
        onChoose(selected);
      });

      actions.appendChild(cancelBtn);
      actions.appendChild(okBtn);
      dialog.appendChild(actions);

      overlay.appendChild(dialog);
      document.body.appendChild(overlay);
    }
  });
}
