-- Updated Database Schema with Encryption Support
-- Run this to add encryption capabilities to existing database

USE `attendance`;

-- ============================================
-- ALTER TABLE: users (Add encrypted columns)
-- ============================================
ALTER TABLE users 
ADD COLUMN `name_encrypted` LONGTEXT COMMENT 'Encrypted using RSA' AFTER `Name`,
ADD COLUMN `email_encrypted` LONGTEXT COMMENT 'Encrypted using ECC' AFTER `Email`,
ADD COLUMN `phone_encrypted` LONGTEXT COMMENT 'Encrypted phone number' AFTER `Photo_url`,
ADD COLUMN `student_id_encrypted` LONGTEXT COMMENT 'Encrypted student ID' AFTER `StudentID`,
ADD COLUMN `encryption_version` INT DEFAULT 1 COMMENT 'Track encryption algorithm version',
ADD COLUMN `data_integrity_tag` VARCHAR(255) COMMENT 'HMAC for data integrity verification';

-- ============================================
-- Table: encryption_keys
-- ============================================
CREATE TABLE IF NOT EXISTS `encryption_keys` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `user_id` INT NOT NULL,
  `key_type` ENUM('RSA', 'ECC') NOT NULL,
  `public_key` LONGTEXT NOT NULL,
  `private_key` LONGTEXT NOT NULL,
  `algorithm_version` INT DEFAULT 1,
  `is_active` BOOLEAN DEFAULT TRUE,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `rotation_date` TIMESTAMP NULL,
  `status` ENUM('active', 'retired', 'compromised') DEFAULT 'active',
  FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
  INDEX `idx_user_id` (`user_id`),
  INDEX `idx_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- Table: hmac_secrets
-- ============================================
CREATE TABLE IF NOT EXISTS `hmac_secrets` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `user_id` INT NOT NULL,
  `secret_key` VARCHAR(255) NOT NULL UNIQUE,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `is_active` BOOLEAN DEFAULT TRUE,
  `status` ENUM('active', 'rotated') DEFAULT 'active',
  FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
  INDEX `idx_user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- Table: posts (User-generated content)
-- ============================================
CREATE TABLE IF NOT EXISTS `posts` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `user_id` INT NOT NULL,
  `title_encrypted` LONGTEXT NOT NULL COMMENT 'Encrypted using RSA',
  `content_encrypted` LONGTEXT NOT NULL COMMENT 'Encrypted using ECC',
  `original_title` VARCHAR(255) COMMENT 'Plaintext for searching/indexing only',
  `original_content` TEXT COMMENT 'Plaintext for searching/indexing only',
  `data_integrity_tag` VARCHAR(255) NOT NULL COMMENT 'HMAC for integrity verification',
  `is_published` BOOLEAN DEFAULT TRUE,
  `visibility` ENUM('public', 'private', 'admin_only') DEFAULT 'private',
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `deleted_at` TIMESTAMP NULL,
  FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
  INDEX `idx_user_id` (`user_id`),
  INDEX `idx_visibility` (`visibility`),
  INDEX `idx_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- Table: key_audit_log
-- ============================================
CREATE TABLE IF NOT EXISTS `key_audit_log` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `user_id` INT NOT NULL,
  `action` VARCHAR(100) NOT NULL COMMENT 'KEY_GENERATION, KEY_ROTATION, KEY_COMPROMISE, etc.',
  `key_type` ENUM('RSA', 'ECC') NOT NULL,
  `details` TEXT,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
  INDEX `idx_user_id` (`user_id`),
  INDEX `idx_action` (`action`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- Table: data_integrity_log
-- ============================================
CREATE TABLE IF NOT EXISTS `data_integrity_log` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `user_id` INT NOT NULL,
  `table_name` VARCHAR(100),
  `record_id` INT,
  `verification_status` ENUM('valid', 'tampered', 'unverified') DEFAULT 'valid',
  `expected_hmac` VARCHAR(255),
  `actual_hmac` VARCHAR(255),
  `checked_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
  INDEX `idx_user_id` (`user_id`),
  INDEX `idx_verification_status` (`verification_status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- Table: role_permissions (RBAC)
-- ============================================
CREATE TABLE IF NOT EXISTS `role_permissions` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `user_type` INT COMMENT '0 = Student, 1 = Admin/Faculty',
  `permission` VARCHAR(100) NOT NULL COMMENT 'e.g., view_posts, create_posts, manage_users, etc.',
  `description` TEXT,
  UNIQUE KEY `unique_role_permission` (`user_type`, `permission`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- Table: access_control_log
-- ============================================
CREATE TABLE IF NOT EXISTS `access_control_log` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `user_id` INT NOT NULL,
  `action` VARCHAR(100),
  `resource` VARCHAR(255),
  `result` ENUM('allowed', 'denied') DEFAULT 'denied',
  `reason` TEXT,
  `ip_address` VARCHAR(45),
  `accessed_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
  INDEX `idx_user_id` (`user_id`),
  INDEX `idx_accessed_at` (`accessed_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- Insert Default RBAC Permissions
-- ============================================
INSERT IGNORE INTO role_permissions (user_type, permission, description) VALUES
-- Student Permissions
(0, 'view_own_profile', 'View their own profile information'),
(0, 'edit_own_profile', 'Edit their own profile'),
(0, 'view_own_posts', 'View their own posts'),
(0, 'create_posts', 'Create new posts'),
(0, 'edit_own_posts', 'Edit their own posts'),
(0, 'delete_own_posts', 'Delete their own posts'),
(0, 'view_public_posts', 'View public posts from other users'),
(0, 'submit_attendance', 'Submit attendance'),
(0, 'view_attendance_records', 'View their own attendance records'),

-- Admin/Faculty Permissions
(1, 'view_all_users', 'View all user profiles'),
(1, 'edit_any_user', 'Edit any user profile'),
(1, 'delete_user', 'Delete user accounts'),
(1, 'view_all_posts', 'View all posts regardless of visibility'),
(1, 'delete_any_post', 'Delete any post'),
(1, 'manage_permissions', 'Manage user permissions'),
(1, 'view_audit_logs', 'View system audit logs'),
(1, 'manage_keys', 'Manage encryption keys'),
(1, 'manage_attendance', 'Manage attendance records'),
(1, 'export_data', 'Export system data'),
(1, 'rotate_keys', 'Rotate encryption keys for users');
