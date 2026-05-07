/**
 * Role-Based Access Control (RBAC) Module
 * Implements permission checking for both students and admins
 */

class RBACManager {
  constructor(db) {
    this.db = db;
  }

  /**
   * Check if user has permission for an action
   * @param {number} userId - User ID
   * @param {number} userType - User type (0=Student, 1=Admin)
   * @param {string} permission - Permission name
   * @returns {Promise<boolean>} True if user has permission
   */
  async hasPermission(userId, userType, permission) {
    try {
      const query = `
        SELECT * FROM role_permissions
        WHERE user_type = ? AND permission = ?
      `;
      
      const [results] = await this.db.execute(query, [userType, permission]);
      return results && results.length > 0;
    } catch (error) {
      console.error('Error checking permission:', error);
      return false;
    }
  }

  /**
   * Get all permissions for a user type
   * @param {number} userType - User type (0=Student, 1=Admin)
   * @returns {Promise<Array>} Array of permissions
   */
  async getPermissions(userType) {
    try {
      const query = `
        SELECT permission FROM role_permissions
        WHERE user_type = ?
      `;
      
      const [results] = await this.db.execute(query, [userType]);
      return results ? results.map(r => r.permission) : [];
    } catch (error) {
      console.error('Error getting permissions:', error);
      return [];
    }
  }

  /**
   * Verify user has permission before action (throws if denied)
   * @param {number} userId - User ID
   * @param {number} userType - User type
   * @param {string} permission - Required permission
   * @throws {Error} If permission denied
   */
  async requirePermission(userId, userType, permission) {
    const hasPermission = await this.hasPermission(userId, userType, permission);
    if (!hasPermission) {
      throw new Error(`Access Denied: User does not have '${permission}' permission`);
    }
  }

  /**
   * Log access control decision
   * @param {number} userId - User ID
   * @param {string} action - Action attempted
   * @param {string} resource - Resource accessed
   * @param {string} result - 'allowed' or 'denied'
   * @param {string} reason - Reason for decision
   * @param {string} ipAddress - Client IP address
   */
  async logAccess(userId, action, resource, result, reason, ipAddress) {
    try {
      const query = `
        INSERT INTO access_control_log (user_id, action, resource, result, reason, ip_address)
        VALUES (?, ?, ?, ?, ?, ?)
      `;
      
      await this.db.execute(query, [userId, action, resource, result, reason, ipAddress]);
    } catch (error) {
      console.error('Error logging access:', error);
    }
  }

  /**
   * Check if user can edit another user's profile
   * @param {number} editorId - User ID attempting to edit
   * @param {number} editorType - Editor user type
   * @param {number} targetUserId - User ID being edited
   * @returns {Promise<boolean>} True if allowed
   */
  async canEditUser(editorId, editorType, targetUserId) {
    // Students can only edit themselves
    if (editorType === 0) {
      return editorId === targetUserId;
    }
    
    // Admins can edit anyone
    if (editorType === 1) {
      return await this.hasPermission(editorId, editorType, 'edit_any_user');
    }
    
    return false;
  }

  /**
   * Check if user can delete a post
   * @param {number} userId - User ID attempting delete
   * @param {number} userType - User type
   * @param {number} postUserId - User ID who created post
   * @returns {Promise<boolean>} True if allowed
   */
  async canDeletePost(userId, userType, postUserId) {
    // Users can delete their own posts
    if (userId === postUserId) {
      return await this.hasPermission(userId, userType, 'delete_own_posts');
    }
    
    // Admins can delete any post
    if (userType === 1) {
      return await this.hasPermission(userId, userType, 'delete_any_post');
    }
    
    return false;
  }

  /**
   * Check if user can view post based on visibility
   * @param {number} userId - User ID viewing
   * @param {number} userType - User type
   * @param {number} postUserId - User ID who created post
   * @param {string} visibility - Post visibility level
   * @returns {Promise<boolean>} True if allowed
   */
  async canViewPost(userId, userType, postUserId, visibility) {
    // Own posts are always viewable
    if (userId === postUserId) return true;
    
    // Public posts visible to all
    if (visibility === 'public') return true;
    
    // Admin-only posts only for admins
    if (visibility === 'admin_only') {
      return userType === 1;
    }
    
    // Private posts only for owner
    if (visibility === 'private') {
      return false;
    }
    
    return false;
  }

  /**
   * Get user's effective permissions
   * @param {number} userType - User type
   * @returns {Promise<Object>} Object with permission flags
   */
  async getUserPermissions(userType) {
    const permissions = await this.getPermissions(userType);
    
    return {
      isStudent: userType === 0,
      isAdmin: userType === 1,
      permissions: permissions,
      can: {
        viewOwnProfile: permissions.includes('view_own_profile'),
        editOwnProfile: permissions.includes('edit_own_profile'),
        createPosts: permissions.includes('create_posts'),
        viewPublicPosts: permissions.includes('view_public_posts'),
        viewAllPosts: permissions.includes('view_all_posts'),
        deleteAnyPost: permissions.includes('delete_any_post'),
        manageUsers: permissions.includes('edit_any_user'),
        viewAuditLogs: permissions.includes('view_audit_logs'),
        manageKeys: permissions.includes('manage_keys'),
        exportData: permissions.includes('export_data')
      }
    };
  }

  /**
   * Get access control audit trail
   * @param {number} userId - User ID
   * @param {number} limit - Number of records
   * @returns {Promise<Array>} Audit trail
   */
  async getAccessLog(userId, limit = 50) {
    try {
      const query = `
        SELECT * FROM access_control_log
        WHERE user_id = ?
        ORDER BY accessed_at DESC
        LIMIT ?
      `;
      
      const [results] = await this.db.execute(query, [userId, limit]);
      return results || [];
    } catch (error) {
      console.error('Error getting access log:', error);
      return [];
    }
  }
}

module.exports = RBACManager;
