"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  default: () => src_default,
  plugin: () => plugin2
});
module.exports = __toCommonJS(src_exports);

// src/aesPlugin.ts
var VERSION = "0.4.0-ts";
var isBase64 = (s) => /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s);
var isHex = (s) => /^[0-9a-fA-F]+$/.test(s);
function coerceOptions(raw) {
  if (raw == null) return {};
  if (typeof raw === "string") {
    const t = raw.trim();
    if (t.startsWith("{") || t.startsWith("[")) {
      try {
        return JSON.parse(t);
      } catch (e) {
        throw new Error("options JSON parse error: " + e.message);
      }
    }
    throw new Error("options string must be JSON (start with { or [)");
  }
  if (typeof raw !== "object") throw new Error("options must be object/JSON");
  return raw;
}
function parseOptions(raw, forDecrypt) {
  const o = coerceOptions(raw);
  const mode = (o.mode || "CBC").toUpperCase();
  if (!["CBC", "GCM", "CTR", "ECB"].includes(mode))
    throw new Error("Unsupported mode " + mode);
  let padding = (o.padding || "PKCS7").toUpperCase();
  if ((mode === "CBC" || mode === "ECB") && !["PKCS7", "NONE"].includes(padding))
    throw new Error("Unsupported padding " + padding);
  if (!(mode === "CBC" || mode === "ECB")) {
    padding = "NONE";
  }
  let keySize;
  if (o.keySize != null) {
    const n = typeof o.keySize === "string" ? parseInt(o.keySize, 10) : o.keySize;
    if (n !== 128 && n !== 256) throw new Error("keySize must be 128 or 256");
    keySize = n;
  }
  const keyEncoding = (o.keyEncoding || "auto").toLowerCase();
  const ivEncoding = (o.ivEncoding || "auto").toLowerCase();
  ["keyEncoding", "ivEncoding"].forEach((k) => {
    const v = k === "keyEncoding" ? keyEncoding : ivEncoding;
    if (!["auto", "hex", "base64", "utf8"].includes(v))
      throw new Error(`Invalid ${k}`);
  });
  let plaintextEncoding = (o.plaintextEncoding || "utf8").toLowerCase();
  if (!["utf8", "hex", "base64"].includes(plaintextEncoding))
    throw new Error("Invalid plaintextEncoding");
  let inputEncoding = (o.inputEncoding || "auto").toLowerCase();
  if (!["auto", "hex", "base64"].includes(inputEncoding))
    throw new Error("Invalid inputEncoding");
  let decryptedOutputEncoding = (o.decryptedOutputEncoding || "utf8").toLowerCase();
  if (!["utf8", "hex", "base64"].includes(decryptedOutputEncoding))
    throw new Error("Invalid decryptedOutputEncoding");
  let output = (o.output || "base64").toLowerCase();
  if (!["base64", "hex"].includes(output))
    throw new Error("Invalid output (expected base64|hex)");
  let backend = (o.backend || "auto").toLowerCase();
  if (!["auto", "node", "web"].includes(backend))
    throw new Error("Invalid backend (auto|node|web)");
  return {
    mode,
    padding,
    keySize,
    keyEncoding,
    ivEncoding,
    plaintextEncoding,
    inputEncoding,
    decryptedOutputEncoding,
    output,
    tag: o.tag,
    backend,
    forDecrypt
  };
}
function decodeWithEncoding(value, encoding, acceptableLengths) {
  if (value == null) throw new Error("value required");
  if (typeof value !== "string") throw new Error("value must be string");
  const trimmed = value.trim();
  let buf;
  try {
    if (encoding !== "auto") {
      buf = Buffer.from(trimmed, encoding === "utf8" ? "utf8" : encoding);
    } else {
      if (acceptableLengths && acceptableLengths.some(
        (l) => trimmed.length === l * 2 && isHex(trimmed)
      )) {
        buf = Buffer.from(trimmed, "hex");
      } else if (isBase64(trimmed)) {
        try {
          buf = Buffer.from(trimmed, "base64");
        } catch {
        }
      }
      if (!buf) buf = Buffer.from(trimmed, "utf8");
    }
  } catch (e) {
    throw new Error(
      `decode error (${encoding}): ${e.message || String(e)}`
    );
  }
  if (acceptableLengths && acceptableLengths.length) {
    if (!acceptableLengths.includes(buf.length)) {
      throw new Error(
        `decoded length ${buf.length} not in [${acceptableLengths.join(" or ")}]`
      );
    }
  }
  return buf;
}
function normalizeKey(key, encoding, keySize) {
  const keyBytes = decodeWithEncoding(key, encoding, [16, 32]);
  const bits = keyBytes.length === 32 ? 256 : 128;
  if (keySize && keySize !== bits)
    throw new Error(
      `key size mismatch: key is ${bits}-bit but keySize=${keySize}`
    );
  return { keyBytes, keyBits: bits };
}
function normalizeIv(iv, encoding, mode) {
  if (mode === "ECB") return null;
  return decodeWithEncoding(iv, encoding, [16]);
}
function encodeBuffer(buf, format) {
  return buf.toString(format);
}
function encodePlainOutput(buf, encoding) {
  if (encoding === "utf8") return buf.toString("utf8");
  if (encoding === "hex") return buf.toString("hex");
  return buf.toString("base64");
}
function decodeCipherInput(str, encoding) {
  if (encoding === "hex") return Buffer.from(str, "hex");
  if (encoding === "base64") return Buffer.from(str, "base64");
  if (isBase64(str)) {
    try {
      return Buffer.from(str, "base64");
    } catch {
    }
  }
  if (isHex(str)) return Buffer.from(str, "hex");
  return Buffer.from(str, "utf8");
}
function detectBackends() {
  const b = {};
  if (typeof crypto !== "undefined" && crypto.subtle) b.subtle = crypto.subtle;
  try {
    b.node = require("crypto");
  } catch {
  }
  return b;
}
var BACKENDS = detectBackends();
function selectBackend(opts, mode) {
  if (opts.backend === "node") {
    if (!BACKENDS.node) throw new Error("Node backend requested but unavailable");
    return { type: "node" };
  }
  if (opts.backend === "web") {
    if (!BACKENDS.subtle)
      throw new Error("Web backend requested but unavailable");
    if (mode === "CTR" || mode === "ECB")
      throw new Error(mode + " unsupported in WebCrypto backend");
    return { type: "web" };
  }
  if (BACKENDS.node) return { type: "node" };
  if (mode === "CTR" || mode === "ECB")
    throw new Error(mode + " requires Node backend (unavailable)");
  if (BACKENDS.subtle) return { type: "web" };
  throw new Error("No cryptographic backend available");
}
function nodeAlgorithm(mode, bits) {
  return `aes-${bits}-${mode.toLowerCase()}`;
}
async function encryptCore(plaintext, key, iv, rawOptions) {
  const opts = parseOptions(rawOptions, false);
  if (plaintext == null) throw new Error("plaintext required");
  const { keyBytes, keyBits } = normalizeKey(
    key,
    opts.keyEncoding,
    opts.keySize
  );
  const ivBytes = normalizeIv(iv, opts.ivEncoding, opts.mode);
  if (opts.mode !== "ECB" && !ivBytes)
    throw new Error("iv required for mode " + opts.mode);
  const ptBuf = decodeWithEncoding(plaintext, opts.plaintextEncoding);
  const backend = selectBackend(opts, opts.mode);
  if (backend.type === "node") {
    const crypto2 = BACKENDS.node;
    const algo = nodeAlgorithm(opts.mode, keyBits);
    const cipher = crypto2.createCipheriv(
      algo,
      keyBytes,
      opts.mode === "ECB" ? null : ivBytes,
      { authTagLength: opts.mode === "GCM" ? 16 : void 0 }
    );
    if ((opts.mode === "CBC" || opts.mode === "ECB") && opts.padding === "NONE") {
      cipher.setAutoPadding(false);
      const block = 16;
      let padded = ptBuf;
      if (ptBuf.length % block !== 0) {
        padded = Buffer.concat([
          ptBuf,
          Buffer.alloc(block - ptBuf.length % block)
        ]);
      }
      const out2 = Buffer.concat([cipher.update(padded), cipher.final()]);
      return encodeBuffer(out2, opts.output);
    }
    const out = Buffer.concat([cipher.update(ptBuf), cipher.final()]);
    if (opts.mode === "GCM") {
      const tag = cipher.getAuthTag();
      return encodeBuffer(out, opts.output) + "." + encodeBuffer(tag, opts.output);
    }
    return encodeBuffer(out, opts.output);
  }
  if (opts.mode === "CTR" || opts.mode === "ECB")
    throw new Error(opts.mode + " unsupported in WebCrypto path");
  const subtle = BACKENDS.subtle;
  const algoName = opts.mode === "CBC" ? "AES-CBC" : "AES-GCM";
  const keyObj = await subtle.importKey(
    "raw",
    keyBytes,
    { name: algoName, length: keyBits },
    false,
    ["encrypt"]
  );
  const params = opts.mode === "CBC" ? { name: "AES-CBC", iv: ivBytes } : { name: "AES-GCM", iv: ivBytes };
  const encrypted = Buffer.from(await subtle.encrypt(params, keyObj, ptBuf));
  if (opts.mode === "GCM") {
    const tag = encrypted.slice(encrypted.length - 16);
    const body = encrypted.slice(0, encrypted.length - 16);
    return encodeBuffer(body, opts.output) + "." + encodeBuffer(tag, opts.output);
  }
  return encodeBuffer(encrypted, opts.output);
}
async function decryptCore(ciphertext, key, iv, rawOptions) {
  const opts = parseOptions(rawOptions, true);
  const { keyBytes, keyBits } = normalizeKey(
    key,
    opts.keyEncoding,
    opts.keySize
  );
  const ivBytes = normalizeIv(iv, opts.ivEncoding, opts.mode);
  if (opts.mode !== "ECB" && !ivBytes)
    throw new Error("iv required for mode " + opts.mode);
  if (ciphertext == null) throw new Error("ciphertext required");
  let ct = ciphertext.trim();
  let tagBuf = null;
  if (opts.mode === "GCM") {
    if (opts.tag) {
      tagBuf = decodeCipherInput(
        opts.tag,
        opts.inputEncoding === "auto" ? "base64" : opts.inputEncoding
      );
    } else {
      const parts = ct.split(/[.:]/);
      if (parts.length < 2)
        throw new Error(
          "GCM ciphertext must include auth tag (. or :) or specify options.tag"
        );
      ct = parts.slice(0, -1).join(".");
      tagBuf = decodeCipherInput(parts[parts.length - 1], "auto");
    }
    if (tagBuf.length !== 16) throw new Error("GCM auth tag must be 16 bytes");
  }
  const ctBuf = decodeCipherInput(ct, opts.inputEncoding);
  const backend = selectBackend(opts, opts.mode);
  if (backend.type === "node") {
    const crypto2 = BACKENDS.node;
    const algo = nodeAlgorithm(opts.mode, keyBits);
    const decipher = crypto2.createDecipheriv(
      algo,
      keyBytes,
      opts.mode === "ECB" ? null : ivBytes,
      { authTagLength: opts.mode === "GCM" ? 16 : void 0 }
    );
    if (opts.mode === "GCM") decipher.setAuthTag(tagBuf);
    if ((opts.mode === "CBC" || opts.mode === "ECB") && opts.padding === "NONE") {
      decipher.setAutoPadding(false);
      const out2 = Buffer.concat([decipher.update(ctBuf), decipher.final()]);
      const unpadded = out2.toString("utf8").replace(/\x00+$/, "");
      return encodePlainOutput(
        Buffer.from(unpadded, "utf8"),
        opts.decryptedOutputEncoding
      );
    }
    const out = Buffer.concat([decipher.update(ctBuf), decipher.final()]);
    return encodePlainOutput(out, opts.decryptedOutputEncoding);
  }
  if (opts.mode === "CTR" || opts.mode === "ECB")
    throw new Error(opts.mode + " unsupported in WebCrypto path");
  const subtle = BACKENDS.subtle;
  const algoName = opts.mode === "CBC" ? "AES-CBC" : "AES-GCM";
  const keyObj = await subtle.importKey(
    "raw",
    keyBytes,
    { name: algoName, length: keyBits },
    false,
    ["decrypt"]
  );
  let data = ctBuf;
  if (opts.mode === "GCM") {
    data = Buffer.concat([ctBuf, tagBuf]);
  }
  const params = opts.mode === "CBC" ? { name: "AES-CBC", iv: ivBytes } : { name: "AES-GCM", iv: ivBytes };
  const ptBuf = Buffer.from(await subtle.decrypt(params, keyObj, data));
  return encodePlainOutput(ptBuf, opts.decryptedOutputEncoding);
}
function makeTemplate(fn, name, description) {
  return {
    name,
    description,
    args: ["text", "key", "iv", "options"],
    async run(_ctx, ...args) {
      try {
        return await fn(...args);
      } catch (e) {
        return "[aes-error] " + (e?.message || String(e));
      }
    }
  };
}
async function encryptAes(plaintext, key, iv, options) {
  return encryptCore(plaintext, key, iv, options);
}
async function decryptAes(ciphertext, key, iv, options) {
  return decryptCore(ciphertext, key, iv, options);
}
async function encryptAes128(plaintext, key, iv, options) {
  return encryptCore(plaintext, key, iv, options);
}
async function decryptAes128(ciphertext, key, iv, options) {
  return decryptCore(ciphertext, key, iv, options);
}
var plugin = {
  name: "AES Tools (128/256) TS",
  version: VERSION,
  description: "AES encryption/decryption helpers supporting AES-128 & AES-256 (CBC/GCM/CTR/ECB).",
  templates: [
    makeTemplate(
      encryptAes,
      "encryptAes",
      "Encrypt (AES-128/256 auto; modes CBC/GCM/CTR/ECB)."
    ),
    makeTemplate(
      decryptAes,
      "decryptAes",
      "Decrypt (AES-128/256 auto; modes CBC/GCM/CTR/ECB)."
    ),
    makeTemplate(
      encryptAes128,
      "encryptAes128",
      "Encrypt (legacy alias \u2013 key length decides 128 vs 256)."
    ),
    makeTemplate(
      decryptAes128,
      "decryptAes128",
      "Decrypt (legacy alias \u2013 key length decides 128 vs 256)."
    )
  ]
};
plugin.templateFunctions = plugin.templates;
var aesPlugin_default = plugin;
try {
  if (typeof module !== "undefined" && module.exports) {
    module.exports = plugin;
    module.exports.default = plugin;
    module.exports.templateFunctions = plugin.templates;
  }
} catch {
}
try {
  if (typeof process !== "undefined" && process?.env?.YAAK_AES_DEBUG) {
    const names = plugin.templates.map((t) => t.name).join(", ");
    console.log(
      "[yaak-aes-plugin-ts]",
      VERSION,
      "templates:",
      names,
      "nodeBackend=",
      !!BACKENDS.node,
      "webBackend=",
      !!BACKENDS.subtle
    );
  }
} catch {
}

// src/index.ts
var aesTemplates = aesPlugin_default?.templates || [];
var templateFunctions = aesTemplates.map((t) => ({
  name: t.name,
  description: t.description,
  // Minimal arg metadata; Yaak expects objects derived from FormInput.
  args: t.args.map((arg) => ({
    name: arg,
    label: arg,
    type: "text",
    required: false
  })),
  async onRender(ctx, callArgs) {
    const values = callArgs?.values || {};
    const ordered = t.args.map((argName) => values[argName] ?? "");
    return await t.run(ctx, ...ordered);
  }
}));
var plugin2 = {
  httpRequestActions: [
    {
      label: "Hello, From Plugin",
      icon: "info",
      async onSelect(ctx, args) {
        await ctx.toast.show({
          color: "success",
          message: `You clicked the request ${args.httpRequest.id}`
        });
      }
    },
    {
      label: "List AES Templates",
      icon: "info",
      async onSelect(ctx) {
        const names = (templateFunctions || []).map((t) => t.name).join(", ") || "(none)";
        await ctx.toast.show({
          color: names && names !== "(none)" ? "info" : "warning",
          message: `AES templates: ${names}`
        });
      }
    }
  ],
  templateFunctions
};
var src_default = plugin2;
if (typeof module !== "undefined") {
  module.exports = plugin2;
  module.exports.plugin = plugin2;
  module.exports.templateFunctions = plugin2.templateFunctions;
  module.exports.default = plugin2;
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  plugin
});
