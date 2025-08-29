/**
 * AES Plugin (TypeScript) – Supports AES-128 & AES-256 (CBC / GCM / CTR / ECB)
 *
 * Exposed template helper function specs (expected by Yaak index bridge):
 *   - encryptAes
 *   - decryptAes
 *   - encryptAes128 (alias; will also accept 256-bit key)
 *   - decryptAes128 (alias; will also accept 256-bit key)
 *
 * NOTE: Your existing `index.ts` currently requires `./plugin.js`.
 *       To use this TypeScript implementation directly you should:
 *          1. Update `index.ts` to import: `import * as aesPlugin from "./aesPlugin";`
 *          2. Map `aesPlugin.templates` similarly to how the previous JS plugin was mapped.
 *
 * SECURITY RECOMMENDATIONS:
 *   - Prefer GCM (authenticated) over CBC / CTR / ECB.
 *   - Avoid ECB unless required for legacy interoperability.
 *   - Do not reuse (key, IV) pairs with GCM or CTR.
 *   - Keep keys in secure secrets; do not hardcode in source.
 *
 * GCM Output Format:
 *   <ciphertext>.<tag>   (both encoded according to `output` option: base64 or hex)
 *
 * OPTIONS (4th arg; may be object or JSON string):
 * {
 *   mode: "CBC" | "GCM" | "CTR" | "ECB"                      (default "CBC")
 *   padding: "PKCS7" | "None"                                (CBC / ECB only; default "PKCS7")
 *   keySize: 128 | 256 (optional – inferred from key bytes if omitted)
 *
 *   keyEncoding: "auto" | "hex" | "base64" | "utf8"          (default "auto")
 *   ivEncoding:  "auto" | "hex" | "base64" | "utf8"          (default "auto")
 *   plaintextEncoding: "utf8" | "hex" | "base64"             (default "utf8")
 *   inputEncoding: "auto" | "hex" | "base64"                 (decrypt only; default "auto")
 *   decryptedOutputEncoding: "utf8" | "hex" | "base64"       (decrypt only; default "utf8")
 *   output: "base64" | "hex"                                 (encrypt only; default "base64")
 *   tag: (auth tag in base64/hex if ciphertext not combined) (GCM decrypt)
 *   backend: "auto" | "node" | "web"                         (default "auto")
 * }
 *
 * BACKEND BEHAVIOR:
 *   - Node backend (crypto module) supports CBC / GCM / CTR / ECB (128 & 256)
 *   - WebCrypto backend supports only CBC / GCM (not CTR / ECB)
 *   - auto preference: Node if available (for broader mode coverage), else WebCrypto
 *
 * RETURN VALUE:
 *   On success: encrypted / decrypted string (encoded per options).
 *   On failure: string starting with `[aes-error] <message>`
 *
 * VERSION: 0.4.0 (TypeScript port)
 */

type AesMode = "CBC" | "GCM" | "CTR" | "ECB";

interface EncryptDecryptOptions {
  mode?: AesMode;
  padding?: "PKCS7" | "None";
  keySize?: 128 | 256 | "128" | "256";

  keyEncoding?: "auto" | "hex" | "base64" | "utf8";
  ivEncoding?: "auto" | "hex" | "base64" | "utf8";
  plaintextEncoding?: "utf8" | "hex" | "base64";
  inputEncoding?: "auto" | "hex" | "base64";
  decryptedOutputEncoding?: "utf8" | "hex" | "base64";
  output?: "base64" | "hex";
  tag?: string;
  backend?: "auto" | "node" | "web";
}

interface ParsedOptions {
  mode: AesMode;
  padding: "PKCS7" | "NONE";
  keySize?: 128 | 256;
  keyEncoding: "auto" | "hex" | "base64" | "utf8";
  ivEncoding: "auto" | "hex" | "base64" | "utf8";
  plaintextEncoding: "utf8" | "hex" | "base64";
  inputEncoding: "auto" | "hex" | "base64";
  decryptedOutputEncoding: "utf8" | "hex" | "base64";
  output: "base64" | "hex";
  tag?: string;
  backend: "auto" | "node" | "web";
  forDecrypt: boolean;
}

interface TemplateDef {
  name: string;
  description: string;
  args: string[];
  run: (ctx: unknown, ...args: any[]) => Promise<string> | string;
}

interface PluginExport {
  name: string;
  version: string;
  description: string;
  templates: TemplateDef[];
  templateFunctions?: TemplateDef[];
}

const VERSION = "0.4.0-ts";

const isBase64 = (s: string) =>
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s);

const isHex = (s: string) => /^[0-9a-fA-F]+$/.test(s);

function coerceOptions(raw: unknown): EncryptDecryptOptions {
  if (raw == null) return {};
  if (typeof raw === "string") {
    const t = raw.trim();
    if (t.startsWith("{") || t.startsWith("[")) {
      try {
        return JSON.parse(t);
      } catch (e: any) {
        throw new Error("options JSON parse error: " + e.message);
      }
    }
    throw new Error("options string must be JSON (start with { or [)");
  }
  if (typeof raw !== "object") throw new Error("options must be object/JSON");
  return raw as EncryptDecryptOptions;
}

function parseOptions(raw: unknown, forDecrypt: boolean): ParsedOptions {
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

  let keySize: 128 | 256 | undefined;
  if (o.keySize != null) {
    const n =
      typeof o.keySize === "string" ? parseInt(o.keySize, 10) : o.keySize;
    if (n !== 128 && n !== 256) throw new Error("keySize must be 128 or 256");
    keySize = n;
  }

  const keyEncoding = (o.keyEncoding || "auto").toLowerCase() as ParsedOptions["keyEncoding"];
  const ivEncoding = (o.ivEncoding || "auto").toLowerCase() as ParsedOptions["ivEncoding"];
  ["keyEncoding", "ivEncoding"].forEach((k) => {
    const v = (k === "keyEncoding" ? keyEncoding : ivEncoding) as string;
    if (!["auto", "hex", "base64", "utf8"].includes(v))
      throw new Error(`Invalid ${k}`);
  });

  let plaintextEncoding = (o.plaintextEncoding || "utf8").toLowerCase() as ParsedOptions["plaintextEncoding"];
  if (!["utf8", "hex", "base64"].includes(plaintextEncoding))
    throw new Error("Invalid plaintextEncoding");

  let inputEncoding = (o.inputEncoding || "auto").toLowerCase() as ParsedOptions["inputEncoding"];
  if (!["auto", "hex", "base64"].includes(inputEncoding))
    throw new Error("Invalid inputEncoding");

  let decryptedOutputEncoding = (o.decryptedOutputEncoding || "utf8").toLowerCase() as ParsedOptions["decryptedOutputEncoding"];
  if (!["utf8", "hex", "base64"].includes(decryptedOutputEncoding))
    throw new Error("Invalid decryptedOutputEncoding");

  let output = (o.output || "base64").toLowerCase() as ParsedOptions["output"];
  if (!["base64", "hex"].includes(output))
    throw new Error("Invalid output (expected base64|hex)");

  let backend = (o.backend || "auto").toLowerCase() as ParsedOptions["backend"];
  if (!["auto", "node", "web"].includes(backend))
    throw new Error("Invalid backend (auto|node|web)");

  return {
    mode: mode as AesMode,
    padding: padding as ParsedOptions["padding"],
    keySize,
    keyEncoding,
    ivEncoding,
    plaintextEncoding,
    inputEncoding,
    decryptedOutputEncoding,
    output,
    tag: o.tag,
    backend,
    forDecrypt,
  };
}

function decodeWithEncoding(
  value: string,
  encoding: "auto" | "hex" | "base64" | "utf8",
  acceptableLengths?: number[],
): Buffer {
  if (value == null) throw new Error("value required");
  if (typeof value !== "string") throw new Error("value must be string");
  const trimmed = value.trim();
  let buf: Buffer | undefined;

  try {
    if (encoding !== "auto") {
      buf = Buffer.from(trimmed, encoding === "utf8" ? "utf8" : encoding);
    } else {
      // auto
      // Try hex when an acceptable length*2 matches
      if (
        acceptableLengths &&
        acceptableLengths.some(
          (l) => trimmed.length === l * 2 && isHex(trimmed),
        )
      ) {
        buf = Buffer.from(trimmed, "hex");
      } else if (isBase64(trimmed)) {
        try {
          buf = Buffer.from(trimmed, "base64");
        } catch {
          // fall through
        }
      }
      if (!buf) buf = Buffer.from(trimmed, "utf8");
    }
  } catch (e: any) {
    throw new Error(
      `decode error (${encoding}): ${e.message || String(e)}`,
    );
  }

  if (acceptableLengths && acceptableLengths.length) {
    if (!acceptableLengths.includes(buf.length)) {
      throw new Error(
        `decoded length ${buf.length} not in [${acceptableLengths.join(" or ")}]`,
      );
    }
  }
  return buf;
}

function normalizeKey(
  key: string,
  encoding: ParsedOptions["keyEncoding"],
  keySize?: number,
): { keyBytes: Buffer; keyBits: 128 | 256 } {
  // Accept 16 or 32
  const keyBytes = decodeWithEncoding(key, encoding, [16, 32]);
  const bits = keyBytes.length === 32 ? 256 : 128;
  if (keySize && keySize !== bits)
    throw new Error(
      `key size mismatch: key is ${bits}-bit but keySize=${keySize}`,
    );
  return { keyBytes, keyBits: bits };
}

function normalizeIv(
  iv: string,
  encoding: ParsedOptions["ivEncoding"],
  mode: AesMode,
): Buffer | null {
  if (mode === "ECB") return null;
  return decodeWithEncoding(iv, encoding, [16]);
}

function encodeBuffer(buf: Buffer, format: "base64" | "hex"): string {
  return buf.toString(format);
}

function encodePlainOutput(
  buf: Buffer,
  encoding: "utf8" | "hex" | "base64",
): string {
  if (encoding === "utf8") return buf.toString("utf8");
  if (encoding === "hex") return buf.toString("hex");
  return buf.toString("base64");
}

function decodeCipherInput(
  str: string,
  encoding: "auto" | "hex" | "base64",
): Buffer {
  if (encoding === "hex") return Buffer.from(str, "hex");
  if (encoding === "base64") return Buffer.from(str, "base64");
  // auto
  if (isBase64(str)) {
    try {
      return Buffer.from(str, "base64");
    } catch {
      /* ignore */
    }
  }
  if (isHex(str)) return Buffer.from(str, "hex");
  return Buffer.from(str, "utf8");
}

/* ------------------------------- Backends ---------------------------------- */

interface Backends {
  node?: typeof import("crypto");
  subtle?: SubtleCrypto;
}

function detectBackends(): Backends {
  const b: Backends = {};
  if (typeof crypto !== "undefined" && crypto.subtle) b.subtle = crypto.subtle;
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    b.node = require("crypto");
  } catch {
    /* ignore */
  }
  return b;
}

const BACKENDS = detectBackends();

function selectBackend(
  opts: ParsedOptions,
  mode: AesMode,
): { type: "node" | "web" } {
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
  // auto
  if (BACKENDS.node) return { type: "node" };
  if (mode === "CTR" || mode === "ECB")
    throw new Error(mode + " requires Node backend (unavailable)");
  if (BACKENDS.subtle) return { type: "web" };
  throw new Error("No cryptographic backend available");
}

function nodeAlgorithm(mode: AesMode, bits: 128 | 256): string {
  return `aes-${bits}-${mode.toLowerCase()}`;
}

/* ------------------------------- Encryption -------------------------------- */

async function encryptCore(
  plaintext: string,
  key: string,
  iv: string,
  rawOptions: unknown,
): Promise<string> {
  const opts = parseOptions(rawOptions, false);
  if (plaintext == null) throw new Error("plaintext required");

  const { keyBytes, keyBits } = normalizeKey(
    key,
    opts.keyEncoding,
    opts.keySize,
  );
  const ivBytes = normalizeIv(iv, opts.ivEncoding, opts.mode);
  if (opts.mode !== "ECB" && !ivBytes)
    throw new Error("iv required for mode " + opts.mode);

  const ptBuf = decodeWithEncoding(plaintext, opts.plaintextEncoding);

  const backend = selectBackend(opts, opts.mode);

  if (backend.type === "node") {
    const crypto = BACKENDS.node!;
    const algo = nodeAlgorithm(opts.mode, keyBits);
    const cipher = crypto.createCipheriv(
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
        padded = Buffer.concat([
          ptBuf,
            Buffer.alloc(block - (ptBuf.length % block)),
        ]);
      }
      const out = Buffer.concat([cipher.update(padded), cipher.final()]);
      return encodeBuffer(out, opts.output);
    }

    const out = Buffer.concat([cipher.update(ptBuf), cipher.final()]);
    if (opts.mode === "GCM") {
      const tag = cipher.getAuthTag();
      return (
        encodeBuffer(out, opts.output) + "." + encodeBuffer(tag, opts.output)
      );
    }
    return encodeBuffer(out, opts.output);
  }

  // WebCrypto (CBC & GCM only)
  if (opts.mode === "CTR" || opts.mode === "ECB")
    throw new Error(opts.mode + " unsupported in WebCrypto path");

  const subtle = BACKENDS.subtle!;
  const algoName = opts.mode === "CBC" ? "AES-CBC" : "AES-GCM";

  const keyObj = await subtle.importKey(
    "raw",
    keyBytes,
    { name: algoName, length: keyBits },
    false,
    ["encrypt"],
  );
  const params =
    opts.mode === "CBC"
      ? { name: "AES-CBC", iv: ivBytes! }
      : { name: "AES-GCM", iv: ivBytes! };
  const encrypted = Buffer.from(await subtle.encrypt(params, keyObj, ptBuf));

  if (opts.mode === "GCM") {
    const tag = encrypted.slice(encrypted.length - 16);
    const body = encrypted.slice(0, encrypted.length - 16);
    return (
      encodeBuffer(body, opts.output) + "." + encodeBuffer(tag, opts.output)
    );
  }
  return encodeBuffer(encrypted, opts.output);
}

/* ------------------------------- Decryption -------------------------------- */

async function decryptCore(
  ciphertext: string,
  key: string,
  iv: string,
  rawOptions: unknown,
): Promise<string> {
  const opts = parseOptions(rawOptions, true);

  const { keyBytes, keyBits } = normalizeKey(
    key,
    opts.keyEncoding,
    opts.keySize,
  );
  const ivBytes = normalizeIv(iv, opts.ivEncoding, opts.mode);
  if (opts.mode !== "ECB" && !ivBytes)
    throw new Error("iv required for mode " + opts.mode);
  if (ciphertext == null) throw new Error("ciphertext required");

  let ct = ciphertext.trim();
  let tagBuf: Buffer | null = null;
  if (opts.mode === "GCM") {
    if (opts.tag) {
      tagBuf = decodeCipherInput(
        opts.tag,
        opts.inputEncoding === "auto" ? "base64" : opts.inputEncoding,
      );
    } else {
      const parts = ct.split(/[.:]/);
      if (parts.length < 2)
        throw new Error(
          "GCM ciphertext must include auth tag (. or :) or specify options.tag",
        );
      ct = parts.slice(0, -1).join(".");
      tagBuf = decodeCipherInput(parts[parts.length - 1], "auto");
    }
    if (tagBuf.length !== 16) throw new Error("GCM auth tag must be 16 bytes");
  }

  const ctBuf = decodeCipherInput(ct, opts.inputEncoding);

  const backend = selectBackend(opts, opts.mode);

  if (backend.type === "node") {
    const crypto = BACKENDS.node!;
    const algo = nodeAlgorithm(opts.mode, keyBits);
    const decipher = crypto.createDecipheriv(
      algo,
      keyBytes,
      opts.mode === "ECB" ? null : ivBytes,
      { authTagLength: opts.mode === "GCM" ? 16 : undefined },
    );
    if (opts.mode === "GCM") decipher.setAuthTag(tagBuf!);

    if (
      (opts.mode === "CBC" || opts.mode === "ECB") &&
      opts.padding === "NONE"
    ) {
      decipher.setAutoPadding(false);
      const out = Buffer.concat([decipher.update(ctBuf), decipher.final()]);
      const unpadded = out.toString("utf8").replace(/\x00+$/, "");
      return encodePlainOutput(
        Buffer.from(unpadded, "utf8"),
        opts.decryptedOutputEncoding,
      );
    }
    const out = Buffer.concat([decipher.update(ctBuf), decipher.final()]);
    return encodePlainOutput(out, opts.decryptedOutputEncoding);
  }

  // WebCrypto
  if (opts.mode === "CTR" || opts.mode === "ECB")
    throw new Error(opts.mode + " unsupported in WebCrypto path");

  const subtle = BACKENDS.subtle!;
  const algoName = opts.mode === "CBC" ? "AES-CBC" : "AES-GCM";
  const keyObj = await subtle.importKey(
    "raw",
    keyBytes,
    { name: algoName, length: keyBits },
    false,
    ["decrypt"],
  );
  let data = ctBuf;
  if (opts.mode === "GCM") {
    data = Buffer.concat([ctBuf, tagBuf!]); // append tag
  }
  const params =
    opts.mode === "CBC"
      ? { name: "AES-CBC", iv: ivBytes! }
      : { name: "AES-GCM", iv: ivBytes! };
  const ptBuf = Buffer.from(await subtle.decrypt(params, keyObj, data));
  return encodePlainOutput(ptBuf, opts.decryptedOutputEncoding);
}

/* ------------------------------- Template Wrappers ------------------------- */

function makeTemplate(
  fn: (...args: any[]) => Promise<string>,
  name: string,
  description: string,
): TemplateDef {
  return {
    name,
    description,
    args: ["text", "key", "iv", "options"],
    async run(_ctx, ...args) {
      try {
        return await fn(...args);
      } catch (e: any) {
        return "[aes-error] " + (e?.message || String(e));
      }
    },
  };
}

/* Public (generic) names – neutral (128 or 256) */
async function encryptAes(
  plaintext: string,
  key: string,
  iv: string,
  options?: unknown,
) {
  return encryptCore(plaintext, key, iv, options);
}

async function decryptAes(
  ciphertext: string,
  key: string,
  iv: string,
  options?: unknown,
) {
  return decryptCore(ciphertext, key, iv, options);
}

/* Legacy alias names */
async function encryptAes128(
  plaintext: string,
  key: string,
  iv: string,
  options?: unknown,
) {
  return encryptCore(plaintext, key, iv, options);
}

async function decryptAes128(
  ciphertext: string,
  key: string,
  iv: string,
  options?: unknown,
) {
  return decryptCore(ciphertext, key, iv, options);
}

export const plugin: PluginExport = {
  name: "AES Tools (128/256) TS",
  version: VERSION,
  description:
    "AES encryption/decryption helpers supporting AES-128 & AES-256 (CBC/GCM/CTR/ECB).",
  templates: [
    makeTemplate(
      encryptAes,
      "encryptAes",
      "Encrypt (AES-128/256 auto; modes CBC/GCM/CTR/ECB).",
    ),
    makeTemplate(
      decryptAes,
      "decryptAes",
      "Decrypt (AES-128/256 auto; modes CBC/GCM/CTR/ECB).",
    ),
    makeTemplate(
      encryptAes128,
      "encryptAes128",
      "Encrypt (legacy alias – key length decides 128 vs 256).",
    ),
    makeTemplate(
      decryptAes128,
      "decryptAes128",
      "Decrypt (legacy alias – key length decides 128 vs 256).",
    ),
  ],
};

plugin.templateFunctions = plugin.templates;

export default plugin;

// CommonJS compatibility if required.
declare const module: any; // silent for TS build contexts lacking Node types
try {
  if (typeof module !== "undefined" && module.exports) {
    module.exports = plugin;
    module.exports.default = plugin;
    module.exports.templateFunctions = plugin.templates;
  }
} catch {
  /* ignore */
}

// Optional debug logging
try {
  if (typeof process !== "undefined" && process?.env?.YAAK_AES_DEBUG) {
    const names = plugin.templates.map((t) => t.name).join(", ");
    // eslint-disable-next-line no-console
    console.log(
      "[yaak-aes-plugin-ts]",
      VERSION,
      "templates:",
      names,
      "nodeBackend=",
      !!BACKENDS.node,
      "webBackend=",
      !!BACKENDS.subtle,
    );
  }
} catch {
  /* ignore */
}
