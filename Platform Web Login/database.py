import pymysql
from werkzeug.security import generate_password_hash
import app_config
import json
import os
import uuid
from datetime import datetime
import pytz

def get_db_connection():
    """Mendapatkan koneksi database"""
    conn = pymysql.connect(
        host=app_config.MYSQL_HOST,
        user=app_config.MYSQL_USER,
        password=app_config.MYSQL_PASSWORD,
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor,
        init_command='SET time_zone = "+07:00"'  # Set timezone ke WIB
    )
    
    # Set session timezone
    cursor = conn.cursor()
    cursor.execute("SET time_zone = '+07:00'")
    cursor.close()
    
    return conn

def init_database():
    """Inisialisasi database dan tabel"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Buat database jika belum ada
    cursor.execute(f"CREATE DATABASE IF NOT EXISTS {app_config.DB_NAME}")
    cursor.execute(f"USE {app_config.DB_NAME}")
    
    # Buat tabel users
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        email VARCHAR(100) UNIQUE,
        security_question VARCHAR(255),
        security_answer VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Tambahkan kolom security question jika belum ada (untuk database yang sudah ada)
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN security_question VARCHAR(255)")
        print("✅ Kolom security_question berhasil ditambahkan")
    except:
        pass  # Kolom sudah ada
    
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN security_answer VARCHAR(255)")
        print("✅ Kolom security_answer berhasil ditambahkan")
    except:
        pass  # Kolom sudah ada
    
    # Buat tabel login_history dengan kolom hybrid scores
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS login_history (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        login_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ip_address VARCHAR(50),
        user_agent TEXT,
        browser VARCHAR(100),
        os_name VARCHAR(100),
        device_type VARCHAR(50),
        success BOOLEAN,
        risk_score FLOAT,
        risk_level INT,
        asn INT DEFAULT 0,
        region VARCHAR(100) DEFAULT 'Unknown',
        if_score DECIMAL(10,6) DEFAULT NULL COMMENT 'Isolation Forest score (0-1)',
        rule_score DECIMAL(10,6) DEFAULT NULL COMMENT 'Rule-based weighted score (0-1)',
        combined_score DECIMAL(10,6) DEFAULT NULL COMMENT 'Hybrid combined score (0-1)',
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    ''')
    
    # Buat tabel user_behavior
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS user_behavior (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        last_login TIMESTAMP,
        login_count INT DEFAULT 0,
        failed_login_count INT DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    ''')
    
    # Tambahkan kolom yang mungkin belum ada (untuk database yang sudah ada)
    try:
        cursor.execute("ALTER TABLE login_history ADD COLUMN asn INT DEFAULT 0")
        print("✅ Kolom ASN berhasil ditambahkan")
    except:
        pass  # Kolom sudah ada
    
    try:
        cursor.execute("ALTER TABLE login_history ADD COLUMN region VARCHAR(100) DEFAULT 'Unknown'")
        print("✅ Kolom region berhasil ditambahkan")
    except:
        pass  # Kolom sudah ada
    
    try:
        cursor.execute("ALTER TABLE login_history ADD COLUMN if_score DECIMAL(10,6) DEFAULT NULL")
        print("✅ Kolom if_score berhasil ditambahkan")
    except:
        pass  # Kolom sudah ada
    
    try:
        cursor.execute("ALTER TABLE login_history ADD COLUMN rule_score DECIMAL(10,6) DEFAULT NULL")
        print("✅ Kolom rule_score berhasil ditambahkan")
    except:
        pass  # Kolom sudah ada
    
    try:
        cursor.execute("ALTER TABLE login_history ADD COLUMN combined_score DECIMAL(10,6) DEFAULT NULL")
        print("✅ Kolom combined_score berhasil ditambahkan")
    except:
        pass  # Kolom sudah ada
    
    # Buat tabel OTP jika belum ada
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS otp_codes (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        email VARCHAR(100) NOT NULL,
        otp_code VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NULL,
        is_used BOOLEAN DEFAULT FALSE,
        attempt_count INT DEFAULT 0,
        ip_address VARCHAR(50),
        session_id VARCHAR(255),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    ''')
    
    # Buat index secara terpisah untuk menghindari error
    try:
        cursor.execute("CREATE INDEX idx_otp_user_id ON otp_codes(user_id)")
    except:
        pass  # Index sudah ada
    
    try:
        cursor.execute("CREATE INDEX idx_otp_expires ON otp_codes(expires_at)")
    except:
        pass  # Index sudah ada
    
    try:
        cursor.execute("CREATE INDEX idx_otp_session ON otp_codes(session_id)")
    except:
        pass  # Index sudah ada
    print("✅ Tabel otp_codes berhasil dibuat/diverifikasi")
    
    # Tambahkan user default jika tabel kosong
    cursor.execute("SELECT COUNT(*) as count FROM users")
    result = cursor.fetchone()
    if result['count'] == 0:
        default_password = generate_password_hash('password123')
        cursor.execute(
            "INSERT INTO users (username, password, email, security_question, security_answer) VALUES (%s, %s, %s, %s, %s)",
            ('admin', default_password, 'admin@example.com', 'Siapa nama hewan peliharaan pertama Anda?', 'kucing')
        )
        cursor.execute(
            "INSERT INTO users (username, password, email, security_question, security_answer) VALUES (%s, %s, %s, %s, %s)",
            ('user', default_password, 'user@example.com', 'Di kota mana Anda dilahirkan?', 'jakarta')
        )
        print("✅ User default berhasil dibuat")
    
    conn.commit()
    cursor.close()
    conn.close()
    print("Database berhasil diinisialisasi")



def save_login_history(user_id, ip_address, user_agent, browser, os_name, device_type, success, risk_score, risk_level, asn=0, region='Unknown', if_score=None, rule_score=None, combined_score=None):
    """Menyimpan riwayat login ke database dengan timestamp WIB eksplisit"""
    conn = get_db_connection()
    conn.select_db(app_config.DB_NAME)
    cursor = conn.cursor()
    
    # PERBAIKAN: Eksplisit timestamp WIB
    current_time = datetime.now(pytz.timezone('Asia/Jakarta'))
    
    cursor.execute(
        "INSERT INTO login_history (user_id, login_timestamp, ip_address, user_agent, browser, os_name, device_type, success, risk_score, risk_level, asn, region, if_score, rule_score, combined_score) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (user_id, current_time, ip_address, user_agent, browser, os_name, device_type, success, risk_score, risk_level, asn, region, if_score, rule_score, combined_score)
    )
    
    # Update user_behavior dengan timestamp WIB
    if success:
        cursor.execute(
            "UPDATE user_behavior SET last_login = %s, login_count = login_count + 1 WHERE user_id = %s",
            (current_time, user_id)
        )
    else:
        cursor.execute(
            "UPDATE user_behavior SET failed_login_count = failed_login_count + 1 WHERE user_id = %s",
            (user_id,)
        )
    
    conn.commit()
    cursor.close()
    conn.close()

def save_login_data(login_info):
    """Menyimpan data login ke file JSON dengan timestamp WIB"""
    try:
        # Pastikan direktori ada
        os.makedirs(app_config.DATA_DIR, exist_ok=True)
        
        # Generate nama file unik
        login_id = str(uuid.uuid4())
        filename = f"login_{login_id}.json"
        filepath = os.path.join(app_config.DATA_DIR, filename)
        
        # PERBAIKAN: Pastikan timestamp WIB konsisten
        login_info['login_id'] = login_id
        
        # Jika timestamp belum ada atau perlu diperbarui
        if 'timestamp' not in login_info or not login_info['timestamp']:
            login_info['timestamp'] = datetime.now(pytz.timezone('Asia/Jakarta')).isoformat()
        
        # Simpan ke file
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(login_info, f, indent=2, ensure_ascii=False)
            
        print(f"✅ Data login disimpan ke: {filepath} (WIB)")
        
    except Exception as e:
        print(f"❌ Error menyimpan data login: {str(e)}") 
