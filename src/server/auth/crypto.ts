import { createCipheriv, createDecipheriv, createHash, randomBytes, timingSafeEqual } from "node:crypto";

export const sha256Hex = (value: string) => createHash("sha256").update(value, "utf8").digest("hex");

/** URL-safe random token (default 256 bits). */
export const randomToken = (bytes = 32) => randomBytes(bytes).toString("base64url");

/** PKCE S256 challenge for a verifier. */
export const pkceChallenge = (verifier: string) => createHash("sha256").update(verifier).digest("base64url");

export function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

/**
 * Parses the operator's 32-byte token-encryption key (base64, base64url or hex). Returns null for
 * anything else so a malformed key disables the feature instead of weakening encryption.
 */
export function parseEncryptionKey(raw: string | undefined): Buffer | null {
  const v = raw?.trim();
  if (!v) return null;
  const candidates = [/^[0-9a-f]{64}$/i.test(v) ? Buffer.from(v, "hex") : null, Buffer.from(v, "base64")];
  return candidates.find((b) => b?.length === 32) ?? null;
}

/** AES-256-GCM. Output: "v1.<iv>.<tag>.<ciphertext>", base64url parts. */
export function encryptSecret(plain: string, key: Buffer): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  return ["v1", iv.toString("base64url"), cipher.getAuthTag().toString("base64url"), ct.toString("base64url")].join(".");
}

export function decryptSecret(enc: string, key: Buffer): string {
  const [v, iv, tag, ct] = enc.split(".");
  if (v !== "v1" || !iv || !tag || ct === undefined) throw new Error("Unsupported ciphertext.");
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "base64url"), { authTagLength: 16 });
  decipher.setAuthTag(Buffer.from(tag, "base64url"));
  return Buffer.concat([decipher.update(Buffer.from(ct, "base64url")), decipher.final()]).toString("utf8");
}
