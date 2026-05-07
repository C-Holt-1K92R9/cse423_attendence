/**
 * Message Authentication Code (MAC) Module
 * Implements HMAC for data integrity verification
 * Detects unauthorized modifications and ensures data authenticity
 */

const crypto = require('crypto');

class HMACValidator {
  /**
   * Generate HMAC for data integrity
   * Uses SHA-256 as the hash algorithm
   * @param {string} data - Data to authenticate
   * @param {string} secret - Secret key (from key management system)
   * @returns {string} HMAC in hex format
   */
  static generateHMAC(data, secret) {
    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(JSON.stringify(data)); // Ensure consistent JSON serialization
    return hmac.digest('hex');
  }

  /**
   * Verify HMAC and detect tampering
   * @param {string} data - Original data
   * @param {string} providedHmac - HMAC to verify against
   * @param {string} secret - Secret key
   * @returns {boolean} True if HMAC matches, false if data was tampered
   */
  static verifyHMAC(data, providedHmac, secret) {
    const expectedHmac = this.generateHMAC(data, secret);
    // Use constant-time comparison to prevent timing attacks
    return crypto.timingSafeEqual(
      Buffer.from(expectedHmac),
      Buffer.from(providedHmac)
    );
  }

  /**
   * Generate HMAC-based authentication code for encrypted data
   * Combines both confidentiality and authenticity
   * @param {string} encryptedData - Already encrypted data
   * @param {string} secret - Secret key
   * @returns {string} Authentication code
   */
  static generateAuthCode(encryptedData, secret) {
    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(encryptedData);
    return hmac.digest('hex');
  }

  /**
   * Verify authentication code for encrypted data
   * @param {string} encryptedData - Encrypted data
   * @param {string} providedAuthCode - Auth code to verify
   * @param {string} secret - Secret key
   * @returns {boolean} True if authentic
   */
  static verifyAuthCode(encryptedData, providedAuthCode, secret) {
    const expectedAuthCode = this.generateAuthCode(encryptedData, secret);
    return crypto.timingSafeEqual(
      Buffer.from(expectedAuthCode),
      Buffer.from(providedAuthCode)
    );
  }

  /**
   * Generate CBC-MAC style authentication (simplified version)
   * @param {string} data - Data to authenticate
   * @param {string} secret - Secret key
   * @returns {string} CBC-MAC equivalent using HMAC
   */
  static generateCBCMAC(data, secret) {
    // In modern practice, HMAC is preferred over CBC-MAC for security
    // This implements HMAC which provides better security properties
    return this.generateHMAC(data, secret);
  }

  /**
   * Create authenticated encryption output
   * Returns both encrypted data and its authentication tag
   * @param {string} encryptedData - Data that's already encrypted
   * @param {string} secret - Authentication secret
   * @returns {Object} {encryptedData, authTag}
   */
  static createAuthenticatedOutput(encryptedData, secret) {
    return {
      encryptedData,
      authTag: this.generateAuthCode(encryptedData, secret),
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Verify authenticated output
   * @param {Object} output - Object with encryptedData and authTag
   * @param {string} secret - Authentication secret
   * @returns {boolean} True if output is authentic and unmodified
   */
  static verifyAuthenticatedOutput(output, secret) {
    try {
      return this.verifyAuthCode(output.encryptedData, output.authTag, secret);
    } catch (error) {
      return false;
    }
  }
}

module.exports = HMACValidator;
