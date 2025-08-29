"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
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

// src/plugin.js
var require_plugin = __commonJS({
  "src/plugin.js"(exports2, module2) {
    "use strict";
    var VERSION = "0.2.1";
    function getCrypto() {
      if (typeof crypto !== "undefined" && crypto.subtle) {
        return { web: true, subtle: crypto.subtle };
      }
      try {
        const nodeCrypto = require("crypto");
        return { web: false, node: nodeCrypto };
      } catch (e) {
        throw new Error("No crypto implementation available in this environment.");
      }
    }
    var CRYPTO_IMPL = getCrypto();
    function isHex(str) {
      return /^[0-9a-fA-F]+$/.test(str);
    }
    function isBase64(str) {
      return /^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/.test(
        str
      );
    }
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
          if (expectedLength && raw.length === expectedLength * 2 && isHex(raw)) {
            bytes = Buffer.from(raw, "hex");
          } else if (isBase64(raw)) {
            try {
              bytes = Buffer.from(raw, "base64");
            } catch {
            }
          }
          if (!bytes) {
            bytes = Buffer.from(raw, "utf8");
          }
        }
      } catch (e) {
        throw new Error(
          `Failed to decode ${label} with encoding '${encoding}': ${e.message}`
        );
      }
      if (expectedLength && bytes.length !== expectedLength) {
        throw new Error(
          `${label} must be exactly ${expectedLength} bytes after decoding (encoding: ${encoding}); got ${bytes.length}`
        );
      }
      return bytes;
    }
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
        throw new Error(
          "options provided as a string must be valid JSON starting with '{' or '['"
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
      if ((o.mode === "CBC" || o.mode === "ECB") && !["PKCS7", "NONE"].includes(o.padding)) {
        throw new Error("Unsupported padding " + o.padding);
      }
      if (!(o.mode === "CBC" || o.mode === "ECB")) {
        o.padding = "NONE";
      }
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
        o.decryptedOutputEncoding = (o.decryptedOutputEncoding || "utf8").toLowerCase();
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
      try {
        return Buffer.from(str, "base64");
      } catch {
      }
      if (isHex(str)) return Buffer.from(str, "hex");
      return Buffer.from(str, "utf8");
    }
    async function encryptAes128(plaintext, key, iv, rawOptions) {
      const coerced = coerceOptions(rawOptions);
      const opts = parseOptions(coerced, false);
      const keyBytes = normalizeBytes(key, "key", 16, opts.keyEncoding);
      const ivBytes = opts.mode === "ECB" ? null : normalizeBytes(iv, "iv", 16, opts.ivEncoding);
      if (opts.mode !== "ECB" && !ivBytes) {
        throw new Error("iv required for mode " + opts.mode);
      }
      if (plaintext == null) throw new Error("plaintext required");
      const ptBuf = normalizeBytes(
        String(plaintext),
        "plaintext",
        null,
        opts.plaintextEncoding
      );
      if (!CRYPTO_IMPL.web) {
        const algo = nodeAlgorithm(opts.mode);
        const cipher = CRYPTO_IMPL.node.createCipheriv(
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
            const padLen = block - ptBuf.length % block;
            padded = Buffer.concat([ptBuf, Buffer.alloc(padLen)]);
          }
          const out2 = Buffer.concat([cipher.update(padded), cipher.final()]);
          return encodeOutput(out2, opts.output);
        }
        const out = Buffer.concat([cipher.update(ptBuf), cipher.final()]);
        if (opts.mode === "GCM") {
          const tag = cipher.getAuthTag();
          const main = encodeOutput(out, opts.output);
          const tagStr = encodeOutput(tag, opts.output);
          return main + "." + tagStr;
        }
        return encodeOutput(out, opts.output);
      } else {
        if (opts.mode === "CTR")
          throw new Error("CTR mode not supported in WebCrypto path");
        if (opts.mode === "ECB")
          throw new Error("ECB mode not supported in WebCrypto path");
        const algo = {
          name: opts.mode === "CBC" ? "AES-CBC" : "AES-GCM",
          iv: ivBytes,
          length: 128
        };
        const keyObj = await CRYPTO_IMPL.subtle.importKey(
          "raw",
          keyBytes,
          algo.name,
          false,
          ["encrypt"]
        );
        const ctBuf = Buffer.from(
          await CRYPTO_IMPL.subtle.encrypt(algo, keyObj, ptBuf)
        );
        if (opts.mode === "GCM") {
          const tag = ctBuf.slice(ctBuf.length - 16);
          const body = ctBuf.slice(0, ctBuf.length - 16);
          return encodeOutput(body, opts.output) + "." + encodeOutput(tag, opts.output);
        }
        return encodeOutput(ctBuf, opts.output);
      }
    }
    async function decryptAes128(ciphertext, key, iv, rawOptions) {
      const coerced = coerceOptions(rawOptions);
      const opts = parseOptions(coerced, true);
      const keyBytes = normalizeBytes(key, "key", 16, opts.keyEncoding);
      const ivBytes = opts.mode === "ECB" ? null : normalizeBytes(iv, "iv", 16, opts.ivEncoding);
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
            opts.inputEncoding === "auto" ? "base64" : opts.inputEncoding
          );
        } else {
          const parts = ctStr.split(/[.:]/);
          if (parts.length < 2)
            throw new Error(
              "GCM ciphertext must include auth tag separated by . or : or specify options.tag"
            );
          ctStr = parts.slice(0, -1).join(".");
          tagBuf = decodeInput(parts[parts.length - 1], "auto");
        }
        if (tagBuf.length !== 16) throw new Error("GCM auth tag must be 16 bytes");
      }
      const ctBuf = decodeInput(ctStr, opts.inputEncoding);
      if (!CRYPTO_IMPL.web) {
        const algo = nodeAlgorithm(opts.mode);
        const decipher = CRYPTO_IMPL.node.createDecipheriv(
          algo,
          keyBytes,
          opts.mode === "ECB" ? null : ivBytes,
          { authTagLength: opts.mode === "GCM" ? 16 : void 0 }
        );
        if (opts.mode === "GCM") {
          decipher.setAuthTag(tagBuf);
        }
        if ((opts.mode === "CBC" || opts.mode === "ECB") && opts.padding === "NONE") {
          decipher.setAutoPadding(false);
          const out2 = Buffer.concat([decipher.update(ctBuf), decipher.final()]);
          const result = out2.toString("utf8").replace(/\x00+$/, "");
          return encodeOutput(
            Buffer.from(result, "utf8"),
            opts.decryptedOutputEncoding
          );
        }
        const out = Buffer.concat([decipher.update(ctBuf), decipher.final()]);
        return encodeOutput(out, opts.decryptedOutputEncoding);
      } else {
        if (opts.mode === "CTR")
          throw new Error("CTR mode not supported in WebCrypto path");
        if (opts.mode === "ECB")
          throw new Error("ECB mode not supported in WebCrypto path");
        let algoName = opts.mode === "CBC" ? "AES-CBC" : "AES-GCM";
        let data = ctBuf;
        if (opts.mode === "GCM") {
          data = Buffer.concat([ctBuf, tagBuf]);
        }
        const keyObj = await CRYPTO_IMPL.subtle.importKey(
          "raw",
          keyBytes,
          algoName,
          false,
          ["decrypt"]
        );
        const ptBuf = Buffer.from(
          await CRYPTO_IMPL.subtle.decrypt(
            { name: algoName, iv: ivBytes },
            keyObj,
            data
          )
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
        }
      };
    }
    var plugin2 = {
      name: "AES-128 Tools",
      version: VERSION,
      description: "Adds AES-128 encryptAes128 / decryptAes128 template helpers supporting CBC, GCM, CTR, ECB.",
      templates: [
        makeTemplate(
          encryptAes128,
          "encryptAes128",
          "Encrypt plaintext with AES-128 (CBC/GCM/CTR/ECB)."
        ),
        makeTemplate(
          decryptAes128,
          "decryptAes128",
          "Decrypt ciphertext with AES-128 (CBC/GCM/CTR/ECB)."
        )
      ]
    };
    module2.exports = plugin2;
    module2.exports.templateFunctions = plugin2.templates;
    if (typeof process !== "undefined" && process.env && process.env.YAAK_AES_DEBUG) {
      try {
        const names = (plugin2.templates || []).map((t) => t.name).join(", ");
        console.log("[yaak-aes-plugin] Loaded templates:", names);
      } catch (_) {
      }
    }
    module2.exports.default = plugin2;
  }
});

// src/index.ts
var src_exports = {};
__export(src_exports, {
  default: () => src_default,
  plugin: () => plugin
});
module.exports = __toCommonJS(src_exports);
var aesCjsPlugin = require_plugin();
var aesTemplates = aesCjsPlugin?.templates || [];
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
var plugin = {
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
var src_default = plugin;
if (typeof module !== "undefined") {
  module.exports = plugin;
  module.exports.plugin = plugin;
  module.exports.templateFunctions = plugin.templateFunctions;
  module.exports.default = plugin;
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  plugin
});
