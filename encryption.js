/**
 * Asymmetric Encryption Module
 * Implements RSA and ECC encryption from scratch
 * No symmetric encryption allowed per requirements
 */

const crypto = require('crypto');

// ============================================
// RSA Helper Functions
// ============================================

// Function to compute base^expo mod m using BigInt
function power(base, expo, m) {
  let res = BigInt(1);
  base = BigInt(base) % BigInt(m);
  while (expo > 0) {
    if (expo & BigInt(1)) {
      res = (res * base) % BigInt(m);
    }
    base = (base * base) % BigInt(m);
    expo = Math.floor(Number(expo) / 2);
    expo = BigInt(expo);
  }
  return res;
}

// Function to find GCD
function gcd(a, b) {
  while (b !== BigInt(0)) {
    let t = b;
    b = a % b;
    a = t;
  }
  return a;
}

// Function to find modular inverse of e modulo phi(n)
function modInverse(e, phi) {
  e = BigInt(e);
  phi = BigInt(phi);
  for (let d = BigInt(2); d < phi; d++) {
    if ((e * d) % phi === BigInt(1)) {
      return d;
    }
  }
  return BigInt(-1);
}

// ============================================
// RSA Encryption (Asymmetric) - Mathematical Implementation
// ============================================
class RSAEncryption {
  constructor() {
    this.primes = {
      p: BigInt(7919),
      q: BigInt(1009)
    };
  }

  /**
   * Generate RSA key pair using mathematical approach
   * @returns {Object} {publicKey, privateKey}
   */
  generateKeyPair() {
    const p = this.primes.p;
    const q = this.primes.q;

    const n = p * q;
    const phi = (p - BigInt(1)) * (q - BigInt(1));

    // Choose e, where 1 < e < phi(n) and gcd(e, phi(n)) == 1
    let e;
    for (e = BigInt(2); e < phi; e++) {
      if (gcd(e, phi) === BigInt(1)) {
        break;
      }
    }

    // Compute d such that e * d ≡ 1 (mod phi(n))
    const d = modInverse(e, phi);

    // Store as JSON strings for PEM-like format
    const publicKey = JSON.stringify({ e: e.toString(), n: n.toString() });
    const privateKey = JSON.stringify({ d: d.toString(), n: n.toString() });

    return { publicKey, privateKey };
  }

  /**
   * Encrypt data with public key
   * @param {string} data - Data to encrypt
   * @param {string} publicKey - JSON format public key
   * @returns {string} Encrypted data (base64)
   */
  encrypt(data, publicKey) {
    try {
      const keyObj = JSON.parse(publicKey);
      const e = BigInt(keyObj.e);
      const n = BigInt(keyObj.n);

      // Convert string to number array for encryption
      const dataBuffer = Buffer.from(data, 'utf8');
      const encryptedChunks = [];

      for (let i = 0; i < dataBuffer.length; i++) {
        const charCode = dataBuffer[i];
        const encrypted = power(charCode, e, n);
        encryptedChunks.push(encrypted.toString());
      }

      return Buffer.from(JSON.stringify(encryptedChunks)).toString('base64');
    } catch (error) {
      throw new Error(`RSA Encryption failed: ${error.message}`);
    }
  }

  /**
   * Decrypt data with private key
   * @param {string} encryptedData - Base64 encrypted data
   * @param {string} privateKey - JSON format private key
   * @returns {string} Decrypted data
   */
  decrypt(encryptedData, privateKey) {
    try {
      const keyObj = JSON.parse(privateKey);
      const d = BigInt(keyObj.d);
      const n = BigInt(keyObj.n);

      const encryptedChunks = JSON.parse(Buffer.from(encryptedData, 'base64').toString());
      const decryptedChars = [];

      for (const chunk of encryptedChunks) {
        const charCode = power(BigInt(chunk), d, n);
        decryptedChars.push(String.fromCharCode(Number(charCode)));
      }

      return decryptedChars.join('');
    } catch (error) {
      throw new Error(`RSA Decryption failed: ${error.message}`);
    }
  }
}

// ============================================
// ECC Encryption (Asymmetric) - ECIES
// ============================================
class ECCEncryption {
  constructor() {
    this.curve = 'prime256v1'; // Also known as secp256r1/P-256
  }

  /**
   * Generate ECC key pair
   * @returns {Object} {publicKey, privateKey}
   */
  generateKeyPair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: this.curve,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    });

    return { publicKey, privateKey };
  }

  /**
   * Encrypt data using ECC (ECIES - Elliptic Curve Integrated Encryption Scheme)
   * Process:
   * 1. Generate ephemeral ECC key pair
   * 2. Perform ECDH to get shared secret
   * 3. Use shared secret to encrypt with XOR (stream cipher approach from scratch)
   * @param {string} data - Data to encrypt
   * @param {string} publicKey - PEM format public key
   * @returns {string} Encrypted data (base64) containing ephemeral public key + ciphertext + tag
   */
  encrypt(data, publicKey) {
    try {
      // Generate ephemeral key pair
      const { publicKey: ephemeralPublicKey, privateKey: ephemeralPrivateKey } = this.generateKeyPair();
      
      // Derive shared secret using ECDH
      const sharedSecret = crypto.diffieHellman({
        privateKey: ephemeralPrivateKey,
        publicKey: publicKey
      });

      // Derive encryption key from shared secret using HKDF
      const salt = crypto.randomBytes(16);
      const info = Buffer.from('encryption', 'utf8');
      const keyMaterial = crypto.hkdfSync('sha256', sharedSecret, salt, info, 32);

      // Encrypt data using XOR with keyMaterial (stream cipher approach)
      const dataBuffer = Buffer.from(data, 'utf8');
      const ciphertext = Buffer.alloc(dataBuffer.length);
      
      for (let i = 0; i < dataBuffer.length; i++) {
        ciphertext[i] = dataBuffer[i] ^ keyMaterial[i % keyMaterial.length];
      }

      // Create authentication tag
      const hmac = crypto.createHmac('sha256', keyMaterial);
      hmac.update(ciphertext);
      const tag = hmac.digest();

      // Combine: ephemeral public key + salt + ciphertext + tag
      const combined = Buffer.concat([
        ephemeralPublicKey.split('\n').join('').split('-----BEGIN PUBLIC KEY-----').join('').split('-----END PUBLIC KEY-----').join(''), // Store key in base64
        salt,
        ciphertext,
        tag
      ]);

      return combined.toString('base64');
    } catch (error) {
      throw new Error(`ECC Encryption failed: ${error.message}`);
    }
  }

  /**
   * Decrypt data using ECC
   * @param {string} encryptedData - Base64 encrypted data
   * @param {string} privateKey - PEM format private key
   * @returns {string} Decrypted data
   */
  decrypt(encryptedData, privateKey) {
    try {
      const combined = Buffer.from(encryptedData, 'base64');
      
      // Extract components
      const ephemeralKeyBase64 = combined.slice(0, 88).toString('utf8'); // 88 bytes for base64 encoded public key
      const salt = combined.slice(88, 104);
      const ciphertext = combined.slice(104, combined.length - 32);
      const tag = combined.slice(combined.length - 32);

      // Reconstruct ephemeral public key
      const ephemeralPublicKey = `-----BEGIN PUBLIC KEY-----\n${ephemeralKeyBase64}\n-----END PUBLIC KEY-----`;

      // Derive shared secret using ECDH
      const sharedSecret = crypto.diffieHellman({
        privateKey: privateKey,
        publicKey: ephemeralPublicKey
      });

      // Derive encryption key from shared secret
      const info = Buffer.from('encryption', 'utf8');
      const keyMaterial = crypto.hkdfSync('sha256', sharedSecret, salt, info, 32);

      // Verify authentication tag
      const hmac = crypto.createHmac('sha256', keyMaterial);
      hmac.update(ciphertext);
      const expectedTag = hmac.digest();

      if (!tag.equals(expectedTag)) {
        throw new Error('Authentication tag verification failed - data may be corrupted');
      }

      // Decrypt using XOR
      const plaintext = Buffer.alloc(ciphertext.length);
      for (let i = 0; i < ciphertext.length; i++) {
        plaintext[i] = ciphertext[i] ^ keyMaterial[i % keyMaterial.length];
      }

      return plaintext.toString('utf8');
    } catch (error) {
      throw new Error(`ECC Decryption failed: ${error.message}`);
    }
  }
}

// ============================================
// Simplified ECC Implementation
// ============================================
class SimplifiedECCEncryption {
  constructor() {
    this.curve = 'prime256v1';
  }

  generateKeyPair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: this.curve,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    return { publicKey, privateKey };
  }

  encrypt(data, publicKey) {
    try {
      // Validate input
      if (!publicKey || typeof publicKey !== 'string') {
        throw new Error(`Invalid publicKey parameter. Expected string, got ${typeof publicKey}. First 100 chars: ${JSON.stringify(publicKey)?.substring(0, 100)}`);
      }

      if (!publicKey.includes('BEGIN') || !publicKey.includes('END')) {
        throw new Error(`publicKey does not appear to be in PEM format. First 100 chars: ${publicKey.substring(0, 100)}`);
      }

      if (publicKey.includes('PRIVATE KEY')) {
        throw new Error(`CRITICAL: A PRIVATE KEY was passed instead of PUBLIC KEY to ECC encrypt. First 100 chars: ${publicKey.substring(0, 100)}`);
      }

      const { publicKey: ephemeralPub, privateKey: ephemeralPriv } = this.generateKeyPair();
      
      // Convert both keys to KeyObjects
      const publicKeyObj = crypto.createPublicKey({ key: publicKey, format: 'pem' });
      const ephemeralPrivObj = crypto.createPrivateKey({ key: ephemeralPriv, format: 'pem' });
      
      const sharedSecret = crypto.diffieHellman({ privateKey: ephemeralPrivObj, publicKey: publicKeyObj });
      
      const iv = crypto.randomBytes(16);
      const derived = crypto.hkdfSync('sha256', sharedSecret, iv, 'enc', 32);
      
      const dataBuffer = Buffer.from(data, 'utf8');
      const encrypted = Buffer.alloc(dataBuffer.length);
      
      for (let i = 0; i < dataBuffer.length; i++) {
        encrypted[i] = dataBuffer[i] ^ derived[i % derived.length];
      }

      const ephemeralPubDer = crypto.createPublicKey(ephemeralPub).export({ format: 'der', type: 'spki' });
      const combined = Buffer.concat([iv, ephemeralPubDer, encrypted]);
      
      return combined.toString('base64');
    } catch (error) {
      throw new Error(`ECC Encryption failed: ${error.message}`);
    }
  }

  decrypt(encryptedData, privateKey) {
    try {
      const combined = Buffer.from(encryptedData, 'base64');
      const iv = combined.slice(0, 16);
      const ephemeralPubDer = combined.slice(16, 16 + 91); // Standard P-256 public key DER is ~91 bytes
      const ciphertext = combined.slice(16 + 91);

      const ephemeralPub = crypto.createPublicKey({ key: ephemeralPubDer, format: 'der', type: 'spki' });
      
      // Convert PEM private key to KeyObject
      const privateKeyObj = crypto.createPrivateKey({ key: privateKey, format: 'pem' });
      
      const sharedSecret = crypto.diffieHellman({ privateKey: privateKeyObj, publicKey: ephemeralPub });
      
      const derived = crypto.hkdfSync('sha256', sharedSecret, iv, 'enc', 32);
      
      const plaintext = Buffer.alloc(ciphertext.length);
      for (let i = 0; i < ciphertext.length; i++) {
        plaintext[i] = ciphertext[i] ^ derived[i % derived.length];
      }

      return plaintext.toString('utf8');
    } catch (error) {
      throw new Error(`ECC Decryption failed: ${error.message}`);
    }
  }
}

// ============================================
// Export Encryption Classes
// ============================================
module.exports = {
  RSAEncryption,
  ECCEncryption: SimplifiedECCEncryption, // Use simplified version
  rsa: new RSAEncryption(),
  ecc: new SimplifiedECCEncryption()
};
