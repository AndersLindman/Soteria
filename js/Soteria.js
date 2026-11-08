/**
 * Soteria: HHK-Rabin KEM ES Module
 * High-performance browser-native Rabin Key Encapsulation Mechanism
 */
export class SoteriaKEM {
  constructor(seedBytes = 32) {
    this.seedBytes = seedBytes;
    this.enc = new TextEncoder();
    this.params = null;
  }

  /**
   * Initializes or loads the key parameters. 
   * Uses browser-native RSA-4096 generation as a fast prime extraction engine.
   */
  async init() {
    if (this.params) return this.params;

    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 4096,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: "SHA-256"
      },
      true,
      ["sign", "verify"]
    );

    const jwk = await window.crypto.subtle.exportKey("jwk", keyPair.privateKey);

    const p = this._base64UrlToBigInt(jwk.p);
    const q = this._base64UrlToBigInt(jwk.q);
    const N = p * q;

    const [qInvRaw] = this._extGcd(q, p);
    const qInv = ((qInvRaw % p) + p) % p;

    const sigmaSecret = window.crypto.getRandomValues(new Uint8Array(this.seedBytes));

    this.params = { p, q, N, qInv, sigmaSecret };
    return this.params;
  }

  /**
   * Encapsulates a random session seed for a given public modulus N.
   * @param {bigint} N - The public Rabin modulus
   * @returns {Promise<{seed: Uint8Array, ciphertext: bigint, sessionKey: string}>}
   */
  async encapsulate(N) {
    const seed = window.crypto.getRandomValues(new Uint8Array(this.seedBytes));
    const M = await this._encodeMessage(seed, N);
    const ciphertext = (M * M) % N;
    const sessionKey = await this._deriveSessionKey(seed, ciphertext, N);

    return { seed, ciphertext, sessionKey };
  }

  /**
   * Decapsulates a received ciphertext using private parameters and implicit rejection.
   * @param {bigint} ciphertext - The received ciphertext
   * @returns {Promise<{sessionKey: string, isValid: boolean}>}
   */
  async decapsulate(ciphertext) {
    if (!this.params) throw new Error("SoteriaKEM not initialized. Call await kem.init() first.");
    const { p, q, N, qInv, sigmaSecret } = this.params;

    const decResult = await this._decrypt(ciphertext, p, q, N, qInv);

    let sessionKey;
    if (decResult.isValid) {
      sessionKey = await this._deriveSessionKey(decResult.seed, ciphertext, N);
    } else {
      // HHK implicit rejection fallback
      sessionKey = await this._deriveSessionKey(sigmaSecret, ciphertext, N);
    }

    return { sessionKey, isValid: decResult.isValid };
  }

  // ============================================================
  // INTERNAL CRYPTOGRAPHIC UTILITIES
  // ============================================================

  async _encodeMessage(seedBytes, N) {
    const bitLen = N.toString(2).length;
    const byteLen = Math.ceil(bitLen / 8);
    const padLen = byteLen - 1 - this.seedBytes;

    const salt = this.enc.encode("RabinKEM-Salt-Native");
    const info = this.enc.encode("RabinKEM-Pad-Native");
    const padBytes = await this._hkdfSha256(seedBytes, salt, info, padLen);

    const mBytes = new Uint8Array(byteLen);
    mBytes[0] = 0x00;
    mBytes.set(seedBytes, 1);
    mBytes.set(padBytes, 1 + this.seedBytes);

    return this._bytesToBigIntBE(mBytes, 0, byteLen);
  }

  async _decodeMessage(M, N) {
    const bitLen = N.toString(2).length;
    const byteLen = Math.ceil(bitLen / 8);
    const mBytes = this._bigIntToBytesBE(M, byteLen);

    if (mBytes[0] !== 0x00) return null;

    const seed = mBytes.slice(1, 1 + this.seedBytes);
    const padBytes = mBytes.slice(1 + this.seedBytes);
    const padLen = byteLen - 1 - this.seedBytes;

    const salt = this.enc.encode("RabinKEM-Salt-Native");
    const info = this.enc.encode("RabinKEM-Pad-Native");
    const expectedPad = await this._hkdfSha256(seed, salt, info, padLen);

    for (let i = 0; i < padLen; i++) {
      if (padBytes[i] !== expectedPad[i]) return null;
    }
    return seed;
  }

  async _decrypt(c, p, q, N, qInv) {
    c = ((c % N) + N) % N;

    const mp = this._tonelliShanks(c % p, p);
    const mq = this._tonelliShanks(c % q, q);

    if (mp === null || mq === null) return { seed: null, isValid: false };

    const rps = [mp, p - mp];
    const rqs = [mq, q - mq];

    for (const rp of rps) {
      for (const rq of rqs) {
        let diff = ((rp - rq) % p + p) % p;
        let h = (qInv * diff) % p;
        let root = rq + h * q;

        if ((root * root) % N !== c) continue;

        const seed = await this._decodeMessage(root, N);
        if (seed !== null) {
          return { seed, isValid: true };
        }
      }
    }
    return { seed: null, isValid: false };
  }

  _tonelliShanks(n, p) {
    if (n === 0n) return 0n;
    if (this._modPow(n, (p - 1n) / 2n, p) !== 1n) return null;

    let Q = p - 1n;
    let S = 0n;
    while (Q % 2n === 0n) { Q /= 2n; S += 1n; }

    if (S === 1n) return this._modPow(n, (p + 1n) / 4n, p);

    let z = 2n;
    while (this._modPow(z, (p - 1n) / 2n, p) !== p - 1n) z += 1n;

    let M = S;
    let c = this._modPow(z, Q, p);
    let t = this._modPow(n, Q, p);
    let R = this._modPow(n, (Q + 1n) / 2n, p);

    while (true) {
      if (t === 0n) return 0n;
      if (t === 1n) return R;

      let i = 0n;
      let temp = t;
      while (temp !== 1n) {
        temp = (temp * temp) % p;
        i += 1n;
      }

      let b = c;
      for (let j = 0n; j < M - i - 1n; j++) b = (b * b) % p;

      M = i;
      c = (b * b) % p;
      t = (t * c) % p;
      R = (R * b) % p;
    }
  }

  async _deriveSessionKey(secretBytes, c, N) {
    const bitLen = N.toString(2).length;
    const byteLen = Math.ceil(bitLen / 8);
    const nBytes = this._bigIntToBytesBE(N, byteLen);
    const cBytes = this._bigIntToBytesBE(c, byteLen);

    const transcript = new Uint8Array(nBytes.length + cBytes.length);
    transcript.set(nBytes, 0);
    transcript.set(cBytes, nBytes.length);

    const transcriptHash = new Uint8Array(await window.crypto.subtle.digest("SHA-256", transcript));
    const salt = new Uint8Array(32);
    const key = await window.crypto.subtle.importKey("raw", secretBytes, "HKDF", false, ["deriveBits"]);
    const prkBits = await window.crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: salt, info: new Uint8Array(0) }, key, 256);

    const prkKey = await window.crypto.subtle.importKey("raw", prkBits, "HKDF", false, ["deriveBits"]);
    const okmBits = await window.crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: transcriptHash }, prkKey, 256);

    return this._bytesToHex(new Uint8Array(okmBits));
  }

  async _hkdfSha256(ikmBytes, saltBytes, infoBytes, lengthBytes) {
    const key = await window.crypto.subtle.importKey("raw", ikmBytes, "HKDF", false, ["deriveBits"]);
    const bits = await window.crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: saltBytes, info: infoBytes }, key, lengthBytes * 8
    );
    return new Uint8Array(bits);
  }

  _modPow(base, exp, mod) {
    let res = 1n; base = base % mod;
    while (exp > 0n) {
      if (exp & 1n) res = (res * base) % mod;
      base = (base * base) % mod; exp >>= 1n;
    }
    return res;
  }

  _cryptoRandomBigInt(bits) {
    const bytes = new Uint8Array(Math.ceil(bits / 8));
    window.crypto.getRandomValues(bytes);
    let value = 0n;
    for (const byte of bytes) value = (value << 8n) | BigInt(byte);
    return value;
  }

  _bytesToBigIntBE(bytes, start, length) {
    let value = 0n; const end = start + length;
    for (let i = start; i < end; i++) value = (value << 8n) | BigInt(bytes[i]);
    return value;
  }

  _bigIntToBytesBE(val, byteLen) {
    const out = new Uint8Array(byteLen); let temp = val;
    for (let i = byteLen - 1; i >= 0; i--) { out[i] = Number(temp & 0xffn); temp >>= 8n; }
    return out;
  }

  _bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
  }

  _extGcd(a, b) {
    let x0 = 1n, x1 = 0n, y0 = 0n, y1 = 1n;
    while (b !== 0n) {
      const q = a / b; const r = a % b; a = b; b = r;
      const nx = x0 - q * x1; x0 = x1; x1 = nx;
      const ny = y0 - q * y1; y0 = y1; y1 = ny;
    }
    return [x0, y0, a];
  }

  _base64UrlToBigInt(b64url) {
    let b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) { b64 += "="; }
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return this._bytesToBigIntBE(bytes, 0, bytes.length);
  }
}
