# Konfigurasi Database
MYSQL_HOST = 'localhost'
MYSQL_USER = 'root'
MYSQL_PASSWORD = ''
DB_NAME = 'rba_login_db'

# Konfigurasi Model
MODEL_PATH = 'rba_universal_isolation_0.9068.pkl'

# Konfigurasi Aplikasi
SECRET_KEY = 'rahasia123'
SESSION_LIFETIME_MINUTES = 30

# Import timedelta untuk session lifetime
from datetime import timedelta
SESSION_LIFETIME = timedelta(minutes=SESSION_LIFETIME_MINUTES)

# Konfigurasi Direktori
DATA_DIR = 'login_data'

# Konfigurasi Email SMTP
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587

# ⚠️ PENTING: Ini adalah kredensial untuk MENGIRIM email (SMTP Server)
# BUKAN email tujuan! Email tujuan diambil dari database user yang registrasi.
# 
# Untuk mendapatkan App Password:
# 1. Aktifkan 2-Step Verification di Google Account Anda
# 2. Buka Google Account Settings > Security > App Passwords  
# 3. Generate App Password untuk "Mail" application
# 4. Gunakan 16-character password yang dihasilkan (bukan password Gmail biasa)

SENDER_EMAIL = 'igharcita@gmail.com'      # Email Gmail Anda untuk MENGIRIM OTP
SENDER_PASSWORD = 'vjyb pisf vqcb oidh'      # App Password Gmail (16 karakter)
EMAIL_ENABLED = True  # Set False untuk disable email OTP

# ✅ Contoh konfigurasi yang benar:
# SENDER_EMAIL = 'admin@gmail.com'           # Email pengirim (admin/sistem)
# SENDER_PASSWORD = 'abcdefghijklmnop'       # App Password dari Gmail (tanpa spasi)
#
# 📧 Alur kerja:
# 1. User registrasi dengan email: user@gmail.com
# 2. User login dengan risiko tinggi/sedang
# 3. Sistem kirim OTP dari SENDER_EMAIL ke user@gmail.com
# 4. User cek email di user@gmail.com untuk mendapat kode OTP

# Konfigurasi OTP
OTP_LENGTH = 6
OTP_EXPIRY_MINUTES = 3  # Ubah dari 10 menjadi 3 menit
OTP_MAX_ATTEMPTS = 3
OTP_RATE_LIMIT_MINUTES = 5  # Cooldown period untuk request OTP baru

# Konfigurasi Enkripsi OTP
OTP_ENCRYPTION_KEY = 'owr1SZH6b3DhslPbd1695FEbXxlxFItL'  # 32 karakter untuk AES-256

# Label Risiko
RISK_LABELS = {
    0: "Rendah",
    1: "Sedang", 
    2: "Tinggi"
}

RISK_COLORS = {
    0: "success",
    1: "warning",
    2: "danger"
} 

# ========== WEIGHTED RULE CONFIGURATION ==========

# Toggle untuk weighted rule system
# DISABLED: Hanya menggunakan IF_score untuk testing
USE_WEIGHTED_RULE = False

# Alpha parameter untuk hybrid score (0.0 = rule only, 1.0 = IF only)
# Diubah menjadi 0.5 untuk 50:50 ML:Weight
WEIGHTED_RULE_ALPHA = 0.5

# Bobot fitur (akan dinormalisasi otomatis)
# DISABLED: Feature weights dinonaktifkan untuk testing IF_score saja
FEATURE_WEIGHTS = {
    'Browser Name_anomaly': 1,      # Browser - bobot terendah
    'OS Name_anomaly': 2,           # OS
    'TimeOfHour_anomaly': 3,        # Time of Hour
    'Device Type_anomaly': 4,       # Device Type
    'DailyLoginCount_anomaly': 5,   # Daily Login Count
    'TimeBetweenLogins_anomaly': 3, # Time Between Logins - diturunkan dari 6
    'Geolocation_Anomaly': 7,       # Geolocation (IP/ASN+Location)
    'FailedLogin_combined_anomaly': 8 # Failed Login Combined (24h) - bobot tertinggi
}

# Threshold untuk risk level determination
RISK_THRESHOLDS = {
    'lower_threshold': 0.2595,  # Threshold untuk Low Risk
    'upper_threshold': 0.5750   # Threshold untuk Medium Risk
} 

# ========== PAIRWISE TEST MODE (untuk pengujian saja) ==========
# Matikan pada produksi
ENABLE_PAIRWISE_TEST = False

# Daftar fitur yang tetap diaktifkan (fitur lain akan dinetralisasi ke 0.0)
# Contoh: ['OS Name_anomaly', 'Browser Name_anomaly']
PAIRWISE_FEATURE_MASK = ['DailyLoginCount_anomaly', 'TimeBetweenLogins_anomaly', "TimeOfHour_anomaly"]

# Opsi lock tambahan (opsional)
PAIRWISE_LOCKS = {
    # Jika menggunakan IP lokal dan ingin menormalkan geolokasi (agar tidak selalu anomali)
    # set ke None untuk menonaktifkan
    'geo_override_for_local': None  # Contoh: {'asn': 38496, 'region': 'ID', 'country': 'ID', 'org': 'CNI-ID'}
}