-- Attendance Management System Database Schema
-- Import this file into phpMyAdmin to create the complete database

-- Create Database
CREATE DATABASE IF NOT EXISTS `attendance`;
USE `attendance`;

-- ============================================
-- Table: users
-- ============================================
CREATE TABLE IF NOT EXISTS `users` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `Email` VARCHAR(255) NOT NULL UNIQUE,
  `Password` VARCHAR(255),
  `Name` VARCHAR(255),
  `type` INT DEFAULT 0 COMMENT '0 = Student, 1 = Admin/Faculty',
  `google_id` VARCHAR(255) UNIQUE,
  `Photo_url` LONGTEXT,
  `StudentID` VARCHAR(50) UNIQUE,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- Table: auth_tokens
-- ============================================
CREATE TABLE IF NOT EXISTS `auth_tokens` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `selector` VARCHAR(255) NOT NULL UNIQUE,
  `hashed_validator` VARCHAR(255) NOT NULL,
  `email` VARCHAR(255) NOT NULL,
  `expires` DATETIME NOT NULL,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (`email`) REFERENCES `users`(`Email`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- Table: records
-- ============================================
CREATE TABLE IF NOT EXISTS `records` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `StudentID` VARCHAR(50) NOT NULL UNIQUE,
  `Name` VARCHAR(255),
  `Email` VARCHAR(255),
  `Course` VARCHAR(255),
  `Section` VARCHAR(50),
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX `idx_StudentID` (`StudentID`),
  INDEX `idx_Section` (`Section`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- Table: verification
-- ============================================
CREATE TABLE IF NOT EXISTS `verification` (
  `ID` INT AUTO_INCREMENT PRIMARY KEY,
  `token` VARCHAR(255),
  `date` VARCHAR(20) NOT NULL COMMENT 'Format: dd_mm_yyyy',
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_date` (`date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- Table: student_response
-- ============================================
CREATE TABLE IF NOT EXISTS `student_response` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `StudentID` VARCHAR(50),
  `ip` VARCHAR(50),
  `isp` VARCHAR(255),
  `attended_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (`StudentID`) REFERENCES `records`(`StudentID`) ON DELETE SET NULL,
  INDEX `idx_StudentID` (`StudentID`),
  INDEX `idx_attended_at` (`attended_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- Table: history
-- ============================================
CREATE TABLE IF NOT EXISTS `history` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `history_dates` VARCHAR(20) NOT NULL COMMENT 'Format: dd_mm_yyyy',
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY `unique_date` (`history_dates`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- Table: sessions (for express-session)
-- ============================================
CREATE TABLE IF NOT EXISTS `sessions` (
  `session_id` VARCHAR(128) NOT NULL PRIMARY KEY,
  `expires` INT UNSIGNED NOT NULL,
  `data` MEDIUMTEXT,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX `expires` (`expires`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Sample Data (Optional - Comment out if not needed)
-- INSERT INTO users (Email, Name, type) VALUES 
-- ('admin@bracu.ac.bd', 'Admin User', 1),
-- ('test@g.bracu.ac.bd', 'Test Student', 0);
