-- ====================================================================
-- RBA Login Database Setup Script (Simple Version)
-- File: create_database_simple.sql
-- Deskripsi: Script SQL sederhana untuk membuat database RBA Login
-- ====================================================================

-- Buat database
CREATE DATABASE IF NOT EXISTS rba_login_db;
USE rba_login_db;

-- ====================================================================
-- TABEL USERS
-- ====================================================================
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100) UNIQUE,
    security_question VARCHAR(255),
    security_answer VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ====================================================================
-- TABEL LOGIN_HISTORY (Tabel utama untuk menyimpan riwayat login)
-- ====================================================================
CREATE TABLE IF NOT EXISTS login_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    login_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(50),
    user_agent TEXT,
    browser VARCHAR(100),
    os_name VARCHAR(100),
    device_type VARCHAR(50),
    success BOOLEAN NOT NULL DEFAULT 0,
    risk_score FLOAT DEFAULT 0.0,
    risk_level INT DEFAULT 1,
    region VARCHAR(100),
    asn INT DEFAULT 0,
    -- Kolom untuk hybrid scores
    if_score DECIMAL(10,6) DEFAULT NULL COMMENT 'Isolation Forest score (0-1)',
    rule_score DECIMAL(10,6) DEFAULT NULL COMMENT 'Rule-based weighted score (0-1)',
    combined_score DECIMAL(10,6) DEFAULT NULL COMMENT 'Hybrid combined score (0-1)',
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- ====================================================================
-- TABEL USER_BEHAVIOR (Untuk menyimpan perilaku pengguna)
-- ====================================================================
CREATE TABLE IF NOT EXISTS user_behavior (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    last_login TIMESTAMP,
    login_count INT DEFAULT 0,
    failed_login_count INT DEFAULT 0,
    usual_browser TEXT,
    usual_os TEXT,
    usual_device_type TEXT,
    usual_ip_prefix VARCHAR(20),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- ====================================================================
-- INSERT DATA DEFAULT USERS
-- ====================================================================
-- Tambahkan user default jika belum ada
INSERT IGNORE INTO users (username, password, email, security_question, security_answer) VALUES 
('admin', 'pbkdf2:sha256:600000$salt123$hash123', 'admin@example.com', 'Siapa nama hewan peliharaan pertama Anda?', 'kucing'),
('user', 'pbkdf2:sha256:600000$salt456$hash456', 'user@example.com', 'Di kota mana Anda dilahirkan?', 'jakarta');

-- ====================================================================
-- TABEL OTP (Untuk menyimpan kode OTP yang dikirim via email)
-- ====================================================================
CREATE TABLE IF NOT EXISTS otp_codes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    email VARCHAR(100) NOT NULL,
    otp_code VARCHAR(255) NOT NULL,  -- Encrypted OTP code
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL,
    is_used BOOLEAN DEFAULT FALSE,
    attempt_count INT DEFAULT 0,
    ip_address VARCHAR(50),
    session_id VARCHAR(255),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Buat index untuk tabel OTP
CREATE INDEX idx_otp_user_id ON otp_codes(user_id);
CREATE INDEX idx_otp_expires ON otp_codes(expires_at);
CREATE INDEX idx_otp_session ON otp_codes(session_id);

-- ====================================================================
-- INDEXES UNTUK PERFORMA
-- ====================================================================
CREATE INDEX IF NOT EXISTS idx_login_history_user_timestamp ON login_history(user_id, login_timestamp);
CREATE INDEX IF NOT EXISTS idx_login_history_user_success ON login_history(user_id, success);
CREATE INDEX IF NOT EXISTS idx_login_history_ip ON login_history(ip_address);
-- Index untuk hybrid scores
CREATE INDEX IF NOT EXISTS idx_login_history_if_score ON login_history(if_score);
CREATE INDEX IF NOT EXISTS idx_login_history_rule_score ON login_history(rule_score);
CREATE INDEX IF NOT EXISTS idx_login_history_combined_score ON login_history(combined_score);

-- ====================================================================
-- VERIFIKASI SETUP
-- ====================================================================
SHOW TABLES;
DESCRIBE login_history;
SELECT COUNT(*) as total_users FROM users; 