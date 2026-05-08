/**
 * Key Management Module
 * Handles generation, storage, distribution, and rotation of encryption keys
 * Manages both RSA and ECC key pairs
 */

const { RSAEncryption, ECCEncryption } = require('./encryption');
const crypto = require('crypto');

class KeyManager {
  constructor(db) {
    this.db = db;
    this.rsa = new RSAEncryption();
    this.ecc = new ECCEncryption();
    this.keyRotationInterval = 30 * 24 * 60 * 60 * 1000; // 30 days in milliseconds
  }

  /**
   * Initialize key management system
   * Creates encryption_keys table if it doesn't exist
   */
  async initialize() {
    try {
      const queries = [
        `CREATE TABLE IF NOT EXISTS encryption_keys (
          id INT AUTO_INCREMENT PRIMARY KEY,
          user_id INT NOT NULL,
          key_type ENUM('RSA', 'ECC') NOT NULL,
          public_key LONGTEXT NOT NULL,
          private_key LONGTEXT NOT NULL,
          algorithm_version INT DEFAULT 1,
          is_active BOOLEAN DEFAULT TRUE,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          rotation_date TIMESTAMP,
          status ENUM('active', 'retired', 'compromised') DEFAULT 'active',
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
          INDEX idx_user_id (user_id),
          INDEX idx_status (status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
        
        `CREATE TABLE IF NOT EXISTS hmac_secrets (
          id INT AUTO_INCREMENT PRIMARY KEY,
          user_id INT NOT NULL,
          secret_key VARCHAR(255) NOT NULL UNIQUE,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          is_active BOOLEAN DEFAULT TRUE,
          status ENUM('active', 'rotated') DEFAULT 'active',
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
          INDEX idx_user_id (user_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
        
        `CREATE TABLE IF NOT EXISTS key_audit_log (
          id INT AUTO_INCREMENT PRIMARY KEY,
          user_id INT NOT NULL,
          action VARCHAR(100) NOT NULL,
          key_type ENUM('RSA', 'ECC') NOT NULL,
          details TEXT,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
          INDEX idx_user_id (user_id),
          INDEX idx_action (action)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`
      ];

      for (const query of queries) {
        try {
          await this.db.execute(query);
        } catch (error) {
          // Table might already exist, continue
          if (!error.message.includes('already exists')) {
            console.warn('Table creation warning:', error.message);
          }
        }
      }
      console.log('✅ Key management tables initialized');
    } catch (error) {
      console.error('❌ Error initializing key management:', error.message);
    }
  }

  /**
   * Generate RSA and ECC keys for a user
   * @param {number} userId - User ID
   * @returns {Promise<Object>} Generated key pair information
   */
  async generateKeysForUser(userId) {
    try {
      // Generate RSA keys
      const rsaKeys = this.rsa.generateKeyPair();
      
      // Generate ECC keys
      const eccKeys = this.ecc.generateKeyPair();

      // Generate HMAC secret (random 32 bytes)
      const hmacSecret = crypto.randomBytes(32).toString('hex');

      // Store RSA keys
      await this.storeKey(userId, 'RSA', rsaKeys.publicKey, rsaKeys.privateKey);

      // Store ECC keys
      await this.storeKey(userId, 'ECC', eccKeys.publicKey, eccKeys.privateKey);

      // Store HMAC secret
      await this.storeHMACSecret(userId, hmacSecret);

      // Log the key generation
      await this.logKeyAction(userId, 'KEY_GENERATION', 'RSA', 'Initial RSA key pair generated');
      await this.logKeyAction(userId, 'KEY_GENERATION', 'ECC', 'Initial ECC key pair generated');

      return {
        success: true,
        message: 'Keys generated successfully',
        keyTypes: ['RSA', 'ECC'],
        hmacSecretGenerated: true
      };
    } catch (error) {
      console.error('Error generating keys:', error);
      throw error;
    }
  }

  /**
   * Store encryption key in database
   * @param {number} userId - User ID
   * @param {string} keyType - 'RSA' or 'ECC'
   * @param {string} publicKey - Public key in PEM format
   * @param {string} privateKey - Private key in PEM format
   */
  async storeKey(userId, keyType, publicKey, privateKey) {
    try {
      const query = `
        INSERT INTO encryption_keys (user_id, key_type, public_key, private_key, is_active)
        VALUES (?, ?, ?, ?, TRUE)
      `;
      await this.db.execute(query, [userId, keyType, publicKey, privateKey]);
    } catch (error) {
      console.error('Error storing key:', error);
      throw error;
    }
  }

  /**
   * Store HMAC secret for user
   * @param {number} userId - User ID
   * @param {string} hmacSecret - HMAC secret key
   */
  async storeHMACSecret(userId, hmacSecret) {
    try {
      const query = `
        INSERT INTO hmac_secrets (user_id, secret_key, is_active)
        VALUES (?, ?, TRUE)
      `;
      await this.db.execute(query, [userId, hmacSecret]);
    } catch (error) {
      console.error('Error storing HMAC secret:', error);
      throw error;
    }
  }

  /**
   * Get active keys for user
   * @param {number} userId - User ID
   * @param {string} keyType - 'RSA', 'ECC', or 'ALL'
   * @returns {Promise<Array>} Array of active keys
   */
  async getActiveKeys(userId, keyType = 'ALL') {
    try {
      let query = `
        SELECT id, key_type, public_key, private_key, created_at
        FROM encryption_keys
        WHERE user_id = ? AND status = 'active'
      `;
      
      const params = [userId];
      
      if (keyType !== 'ALL') {
        query += ' AND key_type = ?';
        params.push(keyType);
      }

      const [results] = await this.db.execute(query, params);
      return results || [];
    } catch (error) {
      console.error('Error getting active keys:', error);
      throw error;
    }
  }

  /**
   * Get public key for a user
   * @param {number} userId - User ID
   * @param {string} keyType - 'RSA' or 'ECC'
   * @returns {Promise<string>} Public key in PEM format
   */
  async getPublicKey(userId, keyType) {
    try {
      const query = `
        SELECT public_key FROM encryption_keys
        WHERE user_id = ? AND key_type = ? AND status = 'active'
        ORDER BY created_at DESC LIMIT 1
      `;
      
      const [results] = await this.db.execute(query, [userId, keyType]);
      console.log(`[KeyManager] getPublicKey query results for user ${userId}, type ${keyType}:`, {
        rowCount: results?.length || 0,
        firstRowKeyPrefix: results?.[0]?.public_key?.substring(0, 50) || 'NO_KEY'
      });
      
      if (results && results.length > 0) {
        const publicKey = results[0].public_key;
        
        // Validation
        if (!publicKey.includes('BEGIN PUBLIC KEY') && !publicKey.includes('BEGIN EC PRIVATE KEY') && !publicKey.includes('BEGIN RSA PRIVATE KEY')) {
          console.warn(`[KeyManager] WARNING: Retrieved key doesn't look like PEM format for ${keyType}`);
        }
        
        if (publicKey.includes('PRIVATE KEY')) {
          console.error(`[KeyManager] CRITICAL ERROR: Retrieved PRIVATE KEY instead of public key for user ${userId}, type ${keyType}`);
        }
        
        return publicKey;
      } else {
        throw new Error(`No active ${keyType} key found for user ${userId}`);
      }
    } catch (error) {
      console.error('Error getting public key:', error);
      throw error;
    }
  }

  /**
   * Get private key for a user (requires verification)
   * @param {number} userId - User ID
   * @param {string} keyType - 'RSA' or 'ECC'
   * @returns {Promise<string>} Private key in PEM format
   */
  async getPrivateKey(userId, keyType) {
    try {
      const query = `
        SELECT private_key FROM encryption_keys
        WHERE user_id = ? AND key_type = ? AND status = 'active'
        ORDER BY created_at DESC LIMIT 1
      `;
      
      const [results] = await this.db.execute(query, [userId, keyType]);
      if (results && results.length > 0) {
        return results[0].private_key;
      } else {
        throw new Error(`No active ${keyType} key found for user ${userId}`);
      }
    } catch (error) {
      console.error('Error getting private key:', error);
      throw error;
    }
  }

  /**
   * Get HMAC secret for user
   * @param {number} userId - User ID
   * @returns {Promise<string>} HMAC secret
   */
  async getHMACSecret(userId) {
    try {
      const query = `
        SELECT secret_key FROM hmac_secrets
        WHERE user_id = ? AND is_active = TRUE
        ORDER BY created_at DESC LIMIT 1
      `;
      
      const [results] = await this.db.execute(query, [userId]);
      if (results && results.length > 0) {
        return results[0].secret_key;
      } else {
        throw new Error(`No HMAC secret found for user ${userId}`);
      }
    } catch (error) {
      console.error('Error getting HMAC secret:', error);
      throw error;
    }
  }

  /**
   * Rotate keys for a user (deprecate old, generate new)
   * @param {number} userId - User ID
   * @returns {Promise<Object>} Rotation status
   */
  async rotateKeys(userId) {
    try {
      // Deactivate old keys
      await this.deactivateOldKeys(userId);

      // Generate new keys
      const result = await this.generateKeysForUser(userId);

      // Log rotation
      await this.logKeyAction(userId, 'KEY_ROTATION', 'RSA', 'Keys rotated successfully');

      return {
        success: true,
        message: 'Keys rotated successfully',
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('Error rotating keys:', error);
      throw error;
    }
  }

  /**
   * Deactivate old keys
   * @param {number} userId - User ID
   */
  async deactivateOldKeys(userId) {
    try {
      const query = `
        UPDATE encryption_keys
        SET status = 'retired'
        WHERE user_id = ? AND status = 'active'
      `;
      
      await this.db.execute(query, [userId]);
    } catch (error) {
      console.error('Error deactivating keys:', error);
      throw error;
    }
  }

  /**
   * Log key management actions for audit
   * @param {number} userId - User ID
   * @param {string} action - Action name
   * @param {string} keyType - Key type involved
   * @param {string} details - Additional details
   */
  async logKeyAction(userId, action, keyType, details) {
    try {
      const query = `
        INSERT INTO key_audit_log (user_id, action, key_type, details)
        VALUES (?, ?, ?, ?)
      `;
      
      await this.db.execute(query, [userId, action, keyType, details]);
    } catch (error) {
      console.error('Error logging key action:', error);
    }
  }

  /**
   * Check if key rotation is needed
   * @param {number} userId - User ID
   * @returns {Promise<boolean>} True if rotation needed
   */
  async isKeyRotationNeeded(userId) {
    try {
      const query = `
        SELECT created_at FROM encryption_keys
        WHERE user_id = ? AND status = 'active'
        ORDER BY created_at DESC LIMIT 1
      `;
      
      const [results] = await this.db.execute(query, [userId]);
      if (results && results.length > 0) {
        const createdAt = new Date(results[0].created_at);
        const now = new Date();
        const diff = now - createdAt;
        return diff > this.keyRotationInterval;
      } else {
        return false;
      }
    } catch (error) {
      console.error('Error checking key rotation:', error);
      return false;
    }
  }

  /**
   * Get audit log for a user
   * @param {number} userId - User ID
   * @param {number} limit - Number of records to return
   * @returns {Promise<Array>} Audit log entries
   */
  async getAuditLog(userId, limit = 50) {
    try {
      const query = `
        SELECT * FROM key_audit_log
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT ?
      `;
      
      const [results] = await this.db.execute(query, [userId, limit]);
      return results || [];
    } catch (error) {
      console.error('Error getting audit log:', error);
      throw error;
    }
  }
}

module.exports = KeyManager;
