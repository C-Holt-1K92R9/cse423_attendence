-- Updated Database Schema with Encryption Support and Email Verification
-- Run this to add encryption capabilities and email verification to existing database

USE `attendance`;

-- ============================================
-- ALTER TABLE: users (Add encrypted columns & verification)
-- ============================================
ALTER TABLE users 
ADD COLUMN `name_encrypted` LONGTEXT COMMENT 'Encrypted using RSA' AFTER `Name`,
ADD COLUMN `email_encrypted` LONGTEXT COMMENT 'Encrypted using ECC' AFTER `Email`,
ADD COLUMN `phone_encrypted` LONGTEXT COMMENT 'Encrypted phone number' AFTER `Photo_url`,
ADD COLUMN `student_id_encrypted` LONGTEXT COMMENT 'Encrypted student ID' AFTER `StudentID`,
ADD COLUMN `encryption_version` INT DEFAULT 1 COMMENT 'Track encryption algorithm version',
ADD COLUMN `data_integrity_tag` VARCHAR(255) COMMENT 'HMAC for data integrity verification',
ADD COLUMN `verified` BOOLEAN DEFAULT 0 COMMENT '1 = verified, 0 = pending verification',
ADD COLUMN `verify_key` VARCHAR(255) UNIQUE COMMENT 'Email verification token',
ADD COLUMN `verify_key_expires` TIMESTAMP NULL COMMENT 'Verification token expiration time';

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
  `result` ENUM('allowed', 'denied') DEFAULT 'allowed',
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
  INDEX `idx_user_id` (`user_id`),
  INDEX `idx_result` (`result`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- Table: auth_tokens (Remember-Me)
-- ============================================
CREATE TABLE IF NOT EXISTS `auth_tokens` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `selector` VARCHAR(255) NOT NULL UNIQUE,
  `hashed_validator` VARCHAR(255) NOT NULL,
  `email` VARCHAR(255),
  `expires` TIMESTAMP NOT NULL,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_email` (`email`),
  INDEX `idx_expires` (`expires`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- Insert Initial RBAC Permissions
-- ============================================
INSERT IGNORE INTO `role_permissions` (`user_type`, `permission`, `description`) VALUES
-- Student Permissions (type 0)
(0, 'view_own_profile', 'View personal profile information'),
(0, 'edit_own_profile', 'Edit personal profile information'),
(0, 'submit_attendance', 'Submit attendance records'),
(0, 'view_attendance_records', 'View personal attendance history'),

-- Admin/Faculty Permissions (type 1)
(1, 'view_all_users', 'View all user accounts'),
(1, 'edit_any_user', 'Modify any user account'),
(1, 'delete_user', 'Delete user accounts'),
(1, 'manage_permissions', 'Configure access control permissions'),
(1, 'view_audit_logs', 'Access security and audit logs'),
(1, 'manage_keys', 'Handle encryption keys'),
(1, 'manage_attendance', 'Review and manage attendance data'),
(1, 'export_data', 'Generate reports and export data'),
(1, 'rotate_keys', 'Trigger key rotation events');
