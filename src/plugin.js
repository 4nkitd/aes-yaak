/*
 * Yaak AES-128 Plugin
 * Provides template functions: encryptAes128, decryptAes128
 *
 * Usage inside Yaak templates/examples:
 *   {{ encryptAes128("hello", env.AES_KEY, env.AES_IV) }}
 *   {{ decryptAes128(last.response.body.data, env.AES_KEY, env.AES_IV) }}
 *
 * Key & IV:
 *   - Accepts raw UTF-8 strings, hex, or base64.
 *   - Must resolve to exactly 16 bytes (128 bits).
 *
 * Options (optional 4th param):
 * {
 *    mode: "CBC" | "GCM" | "CTR" | "ECB" (default "CBC"),
 *    padding: "PKCS7" | "None" (CBC/ECB only; default "PKCS7"),
 *
 *    // --- Encoding for Keys & IV ---
 *    keyEncoding: "auto" | "hex" | "base64" | "utf8" (default "auto"),
 *    ivEncoding: "auto" | "hex" | "base64" | "utf8" (default "auto"),
 *
 *    // --- ENCRYPTION options ---
 *    plaintextEncoding: "utf8" | "hex" | "base64" (default "utf8"),
 *    output: "base64" | "hex" (default "base64"; 'binary' intentionally removed — use hex for raw-safe form),
 *
 *    // --- DECRYPTION options ---
 *    inputEncoding: "auto" | "base64" | "hex" (default "auto"),
 *    decryptedOutputEncoding: "utf8" | "hex" | "base64" (default "utf8"),
 *    tag: <auth tag base64/hex> (GCM only),
 * }
 *
 * NEW (v0.2.1):
 * - The `options` argument can now be supplied as a JSON STRING as well as an object.
 *   Examples (all equivalent):
 *     {{ encryptAes128("hello", env.AES_KEY, env.AES_IV, { "mode": "ECB", "output": "hex" }) }}
 *     {{ encryptAes128("hello", env.AES_KEY, env.AES_IV, "{\"mode\":\"ECB\",\"output\":\"hex\"}") }}
 *   If a string starts with '{' or '[', the plugin attempts JSON.parse() and throws a descriptive
 *   error if parsing fails.
 *
 * For AES-GCM encryption the return format is "<ciphertext>[.|:]<tag>" when output is base64/hex.
 * NOTE: If you pass an unsupported output format the plugin will now throw (was previously silently base64).
 *
 * SECURITY NOTE: Never hardcode keys; use environment vars or Yaak secret storage.
 */
"use strict";

const VERSION = "0.2.2";

/**
 * Attempt to obtain a crypto implementation.
 */
function getCrypto() {
  const impl = {};
  if (typeof crypto !== "undefined" && crypto.subtle) {
    impl.web = true;
    impl.subtle = crypto.subtle;
  }
  try {
    const nodeCrypto = require("crypto");
    impl.node = nodeCrypto;
  } catch (_) {
    // Node crypto not available (likely pure browser environment)
  }
  if (!impl.subtle && !impl.node) {
    throw new Error("No crypto implementation available in this environment.");
  }
  return impl;
}

const CRYPTO_IMPL = getCrypto();

function isHex(str) {
  return /^[0-9a-fA-F]+$/.test(str);
}
function isBase64(str) {
  // A simplified check; Buffer/atob will do the real validation.
  return /^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/.test(
    str,
  );
}

/**
 * Normalize an input string into a Buffer of length `expectedLength` if provided.
 * encoding:
 *   - "auto": try hex (if exact length*2), then base64 pattern, else utf8
 *   - "hex" | "base64" | "utf8": forced decode
 */
function normalizeBytes(input, label, expectedLength, encoding = "auto") {
  if (input == null) throw new Error(`${label} is required`);
  if (typeof input !== "string") {
    throw new Error(`${label} must be a string`);
  }

  let raw = input.trim();
  let bytes;

  try {
    if (encoding && encoding !== "auto") {
      bytes = Buffer.from(raw, encoding);
    } else {
      // Auto-detection for backward compatibility
      if (expectedLength && raw.length === expectedLength * 2 && isHex(raw)) {
        bytes = Buffer.from(raw, "hex");
      } else if (isBase64(raw)) {
        try {
          bytes = Buffer.from(raw, "base64");
        } catch {}
      }
      // Fallback for non-hex/base64 or failed base64
      if (!bytes) {
        bytes = Buffer.from(raw, "utf8");
      }
    }
  } catch (e) {
    throw new Error(
      `Failed to decode ${label} with encoding '${encoding}': ${e.message}`,
    );
  }

  if (expectedLength && bytes.length !== expectedLength) {
    throw new Error(
      `${label} must be exactly ${expectedLength} bytes after decoding (encoding: ${encoding}); got ${bytes.length}`,
    );
  }
  return bytes;
}

/**
 * Coerce the raw options parameter.
 * - If already an object -> returned directly.
 * - If a string beginning with '{' or '[' -> JSON.parse()
 * - Otherwise returned unchanged (caller may treat as undefined).
 */
function coerceOptions(raw) {
  if (raw == null) return raw;
  if (typeof raw === "string") {
    const trimmed = raw.trim();
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
      try {
        return JSON.parse(trimmed);
      } catch (e) {
        throw new Error("options JSON parse error: " + e.message);
      }
    }
    // Non-JSONish string -> treat as error for clarity (helps catch accidental quotes)
    throw new Error(
      "options provided as a string must be valid JSON starting with '{' or '['",
    );
  }
  if (typeof raw !== "object") {
    throw new Error("options must be an object or JSON string");
  }
  return raw;
}

function parseOptions(opts, forDecrypt) {
  const o = Object.assign({}, opts || {});
  const validEncodings = ["auto", "hex", "base64", "utf8"];
  const validDataEncodings = ["hex", "base64", "utf8"];

  o.mode = (o.mode || "CBC").toUpperCase();
  if (!["CBC", "GCM", "CTR", "ECB"].includes(o.mode))
    throw new Error("Unsupported mode " + o.mode);

  o.padding = (o.padding || "PKCS7").toUpperCase();
  if (
    (o.mode === "CBC" || o.mode === "ECB") &&
    !["PKCS7", "NONE"].includes(o.padding)
  ) {
    throw new Error("Unsupported padding " + o.padding);
  }
  if (!(o.mode === "CBC" || o.mode === "ECB")) {
    o.padding = "NONE"; // Node handles implicitly for stream/AEAD modes
  }

  // Key/IV encodings
  o.keyEncoding = (o.keyEncoding || "auto").toLowerCase();
  o.ivEncoding = (o.ivEncoding || "auto").toLowerCase();
  if (!validEncodings.includes(o.keyEncoding))
    throw new Error("Invalid keyEncoding");
  if (!validEncodings.includes(o.ivEncoding))
    throw new Error("Invalid ivEncoding");

  if (!forDecrypt) {
    o.output = (o.output || "base64").toLowerCase();
    if (!["base64", "hex"].includes(o.output))
      throw new Error("Invalid output format");
    o.plaintextEncoding = (o.plaintextEncoding || "utf8").toLowerCase();
    if (!validDataEncodings.includes(o.plaintextEncoding))
      throw new Error("Invalid plaintextEncoding");
  } else {
    o.inputEncoding = (o.inputEncoding || "auto").toLowerCase();
    if (!["auto", "base64", "hex"].includes(o.inputEncoding))
      throw new Error("Invalid inputEncoding");
    o.decryptedOutputEncoding = (
      o.decryptedOutputEncoding || "utf8"
    ).toLowerCase();
    if (!validDataEncodings.includes(o.decryptedOutputEncoding))
      throw new Error("Invalid decryptedOutputEncoding");
  }
  return o;
}

function nodeAlgorithm(mode) {
  switch (mode) {
    case "CBC":
      return "aes-128-cbc";
    case "GCM":
      return "aes-128-gcm";
    case "CTR":
      return "aes-128-ctr";
    case "ECB":
      return "aes-128-ecb";
  }
  throw new Error("Unsupported mode " + mode);
}

function encodeOutput(buf, format) {
  if (format === "hex") return buf.toString("hex");
  if (format === "base64" || format == null) return buf.toString("base64");
  throw new Error("Unsupported output format (expected 'hex' or 'base64')");
}

function decodeInput(str, encoding) {
  if (encoding === "hex") return Buffer.from(str, "hex");
  if (encoding === "base64") return Buffer.from(str, "base64");
  // auto: try base64 then hex else utf8
  try {
    return Buffer.from(str, "base64");
  } catch {}
  if (isHex(str)) return Buffer.from(str, "hex");
  return Buffer.from(str, "utf8");
}

async function encryptAes128(plaintext, key, iv, rawOptions) {
  const coerced = coerceOptions(rawOptions);
  const opts = parseOptions(coerced, false);
  const keyBytes = normalizeBytes(key, "key", 16, opts.keyEncoding);
  const ivBytes =
    opts.mode === "ECB" ? null : normalizeBytes(iv, "iv", 16, opts.ivEncoding);
  if (opts.mode !== "ECB" && !ivBytes) {
    throw new Error("iv required for mode " + opts.mode);
  }
  if (plaintext == null) throw new Error("plaintext required");

  const ptBuf = normalizeBytes(
    String(plaintext),
    "plaintext",
    null,
    opts.plaintextEncoding,
  );

  // Decide backend:
  // Use Node crypto if:
  //  - Node crypto is available AND
  //  - (WebCrypto not available) OR (mode requires features WebCrypto backend doesn't support: ECB or CTR)
  const useNode =
    (CRYPTO_IMPL.node &&
      (!CRYPTO_IMPL.subtle || opts.mode === "ECB" || opts.mode === "CTR")) ||
    !CRYPTO_IMPL.subtle;

  if (useNode) {
    const algo = nodeAlgorithm(opts.mode);
    const cipher = CRYPTO_IMPL.node.createCipheriv(
      algo,
      keyBytes,
      opts.mode === "ECB" ? null : ivBytes,
      { authTagLength: opts.mode === "GCM" ? 16 : undefined },
    );
    if (
      (opts.mode === "CBC" || opts.mode === "ECB") &&
      opts.padding === "NONE"
    ) {
      cipher.setAutoPadding(false);
      const block = 16;
      let padded = ptBuf;
      if (ptBuf.length % block !== 0) {
        const padLen = block - (ptBuf.length % block);
        padded = Buffer.concat([ptBuf, Buffer.alloc(padLen)]);
      }
      const out = Buffer.concat([cipher.update(padded), cipher.final()]);
      return encodeOutput(out, opts.output);
    }
    const out = Buffer.concat([cipher.update(ptBuf), cipher.final()]);
    if (opts.mode === "GCM") {
      const tag = cipher.getAuthTag();
      return (
        encodeOutput(out, opts.output) + "." + encodeOutput(tag, opts.output)
      );
    }
    return encodeOutput(out, opts.output);
  } else {
    // WebCrypto path (CBC & GCM)
    if (opts.mode === "CTR" || opts.mode === "ECB") {
      throw new Error(
        opts.mode +
          " mode forced to WebCrypto path unexpectedly (no Node fallback)",
      );
    }
    const algo = {
      name: opts.mode === "CBC" ? "AES-CBC" : "AES-GCM",
      iv: ivBytes,
      length: 128,
    };
    const keyObj = await CRYPTO_IMPL.subtle.importKey(
      "raw",
      keyBytes,
      algo.name,
      false,
      ["encrypt"],
    );
    const ctBuf = Buffer.from(
      await CRYPTO_IMPL.subtle.encrypt(algo, keyObj, ptBuf),
    );
    if (opts.mode === "GCM") {
      const tag = ctBuf.slice(ctBuf.length - 16);
      const body = ctBuf.slice(0, ctBuf.length - 16);
      return (
        encodeOutput(body, opts.output) + "." + encodeOutput(tag, opts.output)
      );
    }
    return encodeOutput(ctBuf, opts.output);
  }
}

async function decryptAes128(ciphertext, key, iv, rawOptions) {
  const coerced = coerceOptions(rawOptions);
  const opts = parseOptions(coerced, true);
  const keyBytes = normalizeBytes(key, "key", 16, opts.keyEncoding);
  const ivBytes =
    opts.mode === "ECB" ? null : normalizeBytes(iv, "iv", 16, opts.ivEncoding);
  if (opts.mode !== "ECB" && !ivBytes) {
    throw new Error("iv required for mode " + opts.mode);
  }
  if (ciphertext == null) throw new Error("ciphertext required");
  let ctStr = String(ciphertext).trim();
  let tagBuf = null;
  if (opts.mode === "GCM") {
    if (opts.tag) {
      tagBuf = decodeInput(
        opts.tag,
        opts.inputEncoding === "auto" ? "base64" : opts.inputEncoding,
      );
    } else {
      const parts = ctStr.split(/[.:]/);
      if (parts.length < 2)
        throw new Error(
          "GCM ciphertext must include auth tag separated by . or : or specify options.tag",
        );
      ctStr = parts.slice(0, -1).join(".");
      tagBuf = decodeInput(parts[parts.length - 1], "auto");
    }
    if (tagBuf.length !== 16) throw new Error("GCM auth tag must be 16 bytes");
  }
  const ctBuf = decodeInput(ctStr, opts.inputEncoding);

  const useNode =
    (CRYPTO_IMPL.node &&
      (!CRYPTO_IMPL.subtle || opts.mode === "ECB" || opts.mode === "CTR")) ||
    !CRYPTO_IMPL.subtle;

  if (useNode) {
    const algo = nodeAlgorithm(opts.mode);
    const decipher = CRYPTO_IMPL.node.createDecipheriv(
      algo,
      keyBytes,
      opts.mode === "ECB" ? null : ivBytes,
      { authTagLength: opts.mode === "GCM" ? 16 : undefined },
    );
    if (opts.mode === "GCM") {
      decipher.setAuthTag(tagBuf);
    }
    if (
      (opts.mode === "CBC" || opts.mode === "ECB") &&
      opts.padding === "NONE"
    ) {
      decipher.setAutoPadding(false);
      const out = Buffer.concat([decipher.update(ctBuf), decipher.final()]);
      const result = out.toString("utf8").replace(/\x00+$/, "");
      return encodeOutput(
        Buffer.from(result, "utf8"),
        opts.decryptedOutputEncoding,
      );
    }
    const out = Buffer.concat([decipher.update(ctBuf), decipher.final()]);
    return encodeOutput(out, opts.decryptedOutputEncoding);
  } else {
    if (opts.mode === "CTR" || opts.mode === "ECB") {
      throw new Error(
        opts.mode +
          " mode forced to WebCrypto path unexpectedly (no Node fallback)",
      );
    }
    const algoName = opts.mode === "CBC" ? "AES-CBC" : "AES-GCM";
    let data = ctBuf;
    if (opts.mode === "GCM") {
      data = Buffer.concat([ctBuf, tagBuf]);
    }
    const keyObj = await CRYPTO_IMPL.subtle.importKey(
      "raw",
      keyBytes,
      algoName,
      false,
      ["decrypt"],
    );
    const ptBuf = Buffer.from(
      await CRYPTO_IMPL.subtle.decrypt(
        { name: algoName, iv: ivBytes },
        keyObj,
        data,
      ),
    );
    return encodeOutput(ptBuf, opts.decryptedOutputEncoding);
  }
}

function makeTemplate(fn, name, description) {
  return {
    name,
    description,
    args: ["text", "key", "iv", "options"],
    async run(context, ...args) {
      try {
        return await fn(...args);
      } catch (e) {
        return "[aes-error] " + e.message;
      }
    },
  };
}

const plugin = {
  name: "AES-128 Tools",
  version: VERSION,
  description:
    "Adds AES-128 encryptAes128 / decryptAes128 template helpers supporting CBC, GCM, CTR, ECB.",
  templates: [
    makeTemplate(
      encryptAes128,
      "encryptAes128",
      "Encrypt plaintext with AES-128 (CBC/GCM/CTR/ECB).",
    ),
    makeTemplate(
      decryptAes128,
      "decryptAes128",
      "Decrypt ciphertext with AES-128 (CBC/GCM/CTR/ECB).",
    ),
  ],
};

module.exports = plugin;

// Expose templateFunctions explicitly (some loaders look for this)
module.exports.templateFunctions = plugin.templates;

// Optional debug banner (enable with YAAK_AES_DEBUG=1)
if (
  typeof process !== "undefined" &&
  process.env &&
  process.env.YAAK_AES_DEBUG
) {
  try {
    const names = (plugin.templates || []).map((t) => t.name).join(", ");
    console.log("[yaak-aes-plugin] Loaded templates:", names);
  } catch (_) {}
}

// For ESM default export compatibility
module.exports.default = plugin;
