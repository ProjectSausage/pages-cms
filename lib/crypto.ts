/**
 * Utility functions to encrypt and decrypt text using AES-GCM. Used to secure
 * info in the DB (e.g. GitHub tokens).
 *
 * Requires a CRYPTO_KEY environment variable to be set.
 * CRYPTO_KEY must be a 32-byte key encoded as standard or URL-safe base64.
 */

const decodeBase64 = (value: string) => {
  let normalized = value.trim();
  if (
    (normalized.startsWith('"') && normalized.endsWith('"'))
    || (normalized.startsWith("'") && normalized.endsWith("'"))
  ) {
    normalized = normalized.slice(1, -1).trim();
  }

  normalized = normalized.replace(/\s+/g, "");
  normalized = normalized.replace(/-/g, "+").replace(/_/g, "/");
  while (normalized.length % 4 !== 0) normalized += "=";

  return Uint8Array.from(atob(normalized), (c) => c.charCodeAt(0));
};

const importKey = async (base64Key: string) => {
  const rawKey = decodeBase64(base64Key);
  if (rawKey.length !== 32) {
    throw new Error(
      `CRYPTO_KEY must decode to 32 bytes for AES-256-GCM (got ${rawKey.length}). Check Vercel env: no extra quotes, and keep trailing "=" if present.`,
    );
  }

  return crypto.subtle.importKey(
    "raw",
    rawKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );
};

const encrypt = async (text: string) => {
  if (process.env.CRYPTO_KEY === undefined) throw new Error("Crypto key is not set.");
  const key = await importKey(process.env.CRYPTO_KEY);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encodedText = new TextEncoder().encode(text);

  const encryptedData = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encodedText,
  );

  return {
    ciphertext: btoa(String.fromCharCode(...Array.from(new Uint8Array(encryptedData)))),
    iv: btoa(String.fromCharCode(...Array.from(iv))),
  };
};

const decrypt = async (ciphertext: string, iv: string) => {
  if (process.env.CRYPTO_KEY === undefined) throw new Error("Crypto key is not set.");
  const key = await importKey(process.env.CRYPTO_KEY);
  const ivArray = decodeBase64(iv);
  const encryptedDataArray = decodeBase64(ciphertext);

  const decryptedData = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: ivArray },
    key,
    encryptedDataArray,
  );

  return new TextDecoder().decode(decryptedData);
};

export { encrypt, decrypt };
