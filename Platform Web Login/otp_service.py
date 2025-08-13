import random
import string
import hashlib
import secrets
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import base64
import app_config
from database import get_db_connection
from email_service import EmailService
import pytz

# Set timezone untuk aplikasi
jakarta_tz = pytz.timezone('Asia/Jakarta')

class OTPService:
    def __init__(self):
        self.otp_length = app_config.OTP_LENGTH
        self.expiry_minutes = app_config.OTP_EXPIRY_MINUTES
        self.max_attempts = app_config.OTP_MAX_ATTEMPTS
        self.rate_limit_minutes = app_config.OTP_RATE_LIMIT_MINUTES
        self.encryption_key = self._get_encryption_key()
        self.email_service = EmailService()
    
    def _get_encryption_key(self):
        """
        Mendapatkan atau membuat kunci enkripsi yang aman
        """
        key_string = app_config.OTP_ENCRYPTION_KEY
        if len(key_string) < 32:
            # Jika kunci kurang dari 32 karakter, pad dengan hash
            key_string = hashlib.sha256(key_string.encode()).hexdigest()[:32]
        
        # Konversi ke format base64 untuk Fernet
        key_bytes = key_string.encode()[:32]
        key_b64 = base64.urlsafe_b64encode(key_bytes)
        return Fernet(key_b64)
    
    def generate_otp(self):
        """
        Generate OTP yang aman menggunakan secrets module
        """
        # Menggunakan secrets untuk keamanan kriptografi yang lebih baik
        digits = string.digits
        otp = ''.join(secrets.choice(digits) for _ in range(self.otp_length))
        return otp
    
    def encrypt_otp(self, otp_code):
        """
        Enkripsi kode OTP sebelum disimpan di database
        """
        try:
            encrypted_otp = self.encryption_key.encrypt(otp_code.encode())
            return encrypted_otp.decode()
        except Exception as e:
            print(f"❌ Error enkripsi OTP: {str(e)}")
            return None
    
    def decrypt_otp(self, encrypted_otp):
        """
        Dekripsi kode OTP dari database
        """
        try:
            decrypted_otp = self.encryption_key.decrypt(encrypted_otp.encode())
            return decrypted_otp.decode()
        except Exception as e:
            print(f"❌ Error dekripsi OTP: {str(e)}")
            return None
    
    def check_rate_limit(self, user_id, ip_address):
        """
        Cek apakah user sudah melewati rate limit untuk request OTP
        """
        conn = get_db_connection()
        conn.select_db(app_config.DB_NAME)
        cursor = conn.cursor()
        
        try:
            # Cek OTP request dalam periode rate limit
            rate_limit_time = datetime.now(jakarta_tz) - timedelta(minutes=self.rate_limit_minutes)
            
            cursor.execute("""
                SELECT COUNT(*) as count FROM otp_codes 
                WHERE (user_id = %s OR ip_address = %s) 
                AND created_at > %s
            """, (user_id, ip_address, rate_limit_time))
            
            result = cursor.fetchone()
            request_count = result['count'] if result else 0
            
            # Limit maksimal 3 request per periode
            max_requests = 3
            
            if request_count >= max_requests:
                return False, f"Terlalu banyak request OTP. Coba lagi dalam {self.rate_limit_minutes} menit."
            
            return True, f"Tersisa {max_requests - request_count} request OTP"
            
        except Exception as e:
            print(f"❌ Error cek rate limit: {str(e)}")
            return False, "Error sistem"
        finally:
            cursor.close()
            conn.close()
    
    def cleanup_expired_otps(self):
        """
        Membersihkan OTP yang sudah kedaluwarsa
        """
        conn = get_db_connection()
        conn.select_db(app_config.DB_NAME)
        cursor = conn.cursor()
        
        try:
            cursor.execute("DELETE FROM otp_codes WHERE expires_at < NOW()")
            deleted_count = cursor.rowcount
            conn.commit()
            
            if deleted_count > 0:
                print(f"✅ Berhasil menghapus {deleted_count} OTP yang kedaluwarsa")
            
        except Exception as e:
            print(f"❌ Error cleanup OTP: {str(e)}")
        finally:
            cursor.close()
            conn.close()
    
    def create_otp(self, user_id, email, ip_address, session_id):
        """
        Membuat dan menyimpan OTP baru
        """
        # Optimasi: Skip cleanup untuk mengurangi delay, akan dicleanup secara berkala
        # self.cleanup_expired_otps()
        
        # Cek rate limit
        can_request, message = self.check_rate_limit(user_id, ip_address)
        if not can_request:
            return False, message, None
        
        # Generate OTP
        otp_code = self.generate_otp()
        
        # Enkripsi OTP
        encrypted_otp = self.encrypt_otp(otp_code)
        if not encrypted_otp:
            return False, "Error enkripsi OTP", None
        
        # Hitung waktu kedaluwarsa dengan timezone yang benar
        current_time = datetime.now(jakarta_tz)
        expires_at = current_time + timedelta(minutes=self.expiry_minutes)
        
        conn = get_db_connection()
        conn.select_db(app_config.DB_NAME)
        cursor = conn.cursor()
        
        try:
            # Nonaktifkan OTP sebelumnya untuk user ini
            cursor.execute("""
                UPDATE otp_codes 
                SET is_used = TRUE 
                WHERE user_id = %s AND session_id = %s AND is_used = FALSE
            """, (user_id, session_id))
            
            # Simpan OTP baru dengan timezone yang benar
            cursor.execute("""
                INSERT INTO otp_codes 
                (user_id, email, otp_code, created_at, expires_at, ip_address, session_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (user_id, email, encrypted_otp, current_time, expires_at, ip_address, session_id))
            
            conn.commit()
            otp_id = cursor.lastrowid
            
            print(f"✅ OTP berhasil dibuat untuk user {user_id}")
            return True, "OTP berhasil dibuat", {
                'otp_id': otp_id,
                'otp_code': otp_code,
                'expires_at': expires_at
            }
            
        except Exception as e:
            print(f"❌ Error membuat OTP: {str(e)}")
            return False, "Error sistem", None
        finally:
            cursor.close()
            conn.close()
    
    def send_otp_email(self, user_id, username, email, ip_address, session_id):
        """
        Membuat dan mengirim OTP via email
        """
        # Buat OTP
        success, message, otp_data = self.create_otp(user_id, email, ip_address, session_id)
        
        if not success:
            return False, message
        
        # Kirim email (optimasi: return immediately, send in background if needed)
        try:
            email_sent = self.email_service.send_otp_email(
                recipient_email=email,
                otp_code=otp_data['otp_code'],
                username=username,
                expires_in_minutes=self.expiry_minutes
            )
            
            if email_sent:
                return True, f"Kode OTP telah dikirim ke {email}. Kode berlaku selama {self.expiry_minutes} menit."
            else:
                return False, "Gagal mengirim email OTP. Silakan coba lagi."
        except Exception as e:
            # Log error tapi tetap return success karena OTP sudah dibuat
            print(f"⚠️ Warning: OTP dibuat tapi email gagal dikirim: {str(e)}")
            return True, f"Kode OTP telah dibuat. Kode berlaku selama {self.expiry_minutes} menit."
    
    def verify_otp(self, user_id, otp_code, session_id):
        """
        Verifikasi kode OTP
        """
        conn = get_db_connection()
        conn.select_db(app_config.DB_NAME)
        cursor = conn.cursor()
        
        try:
            # Ambil OTP yang aktif untuk user dengan timezone yang benar
            cursor.execute("""
                SELECT id, otp_code, 
                       CONVERT_TZ(expires_at, '+00:00', '+07:00') as expires_at, 
                       attempt_count, is_used
                FROM otp_codes 
                WHERE user_id = %s AND session_id = %s AND is_used = FALSE
                ORDER BY created_at DESC 
                LIMIT 1
            """, (user_id, session_id))
            
            otp_record = cursor.fetchone()
            
            if not otp_record:
                return False, "Kode OTP tidak ditemukan atau sudah digunakan"
            
            # Cek apakah OTP sudah kedaluwarsa dengan timezone yang benar
            current_time = datetime.now(jakarta_tz)
            expires_at = otp_record['expires_at'].replace(tzinfo=jakarta_tz)
            
            if current_time > expires_at:
                cursor.execute("UPDATE otp_codes SET is_used = TRUE WHERE id = %s", (otp_record['id'],))
                conn.commit()
                return False, "Kode OTP sudah kedaluwarsa"
            
            # Cek jumlah percobaan
            if otp_record['attempt_count'] >= self.max_attempts:
                cursor.execute("UPDATE otp_codes SET is_used = TRUE WHERE id = %s", (otp_record['id'],))
                conn.commit()
                return False, "Terlalu banyak percobaan. Silakan minta kode OTP baru."
            
            # Dekripsi OTP dari database
            stored_otp = self.decrypt_otp(otp_record['otp_code'])
            if not stored_otp:
                return False, "Error verifikasi OTP"
            
            # Update attempt count
            cursor.execute("""
                UPDATE otp_codes 
                SET attempt_count = attempt_count + 1 
                WHERE id = %s
            """, (otp_record['id'],))
            
            # Verifikasi OTP
            if stored_otp == otp_code:
                # OTP benar, tandai sebagai digunakan
                cursor.execute("UPDATE otp_codes SET is_used = TRUE WHERE id = %s", (otp_record['id'],))
                conn.commit()
                return True, "Kode OTP valid"
            else:
                conn.commit()
                remaining_attempts = self.max_attempts - (otp_record['attempt_count'] + 1)
                if remaining_attempts > 0:
                    return False, f"Kode OTP salah. Tersisa {remaining_attempts} percobaan."
                else:
                    cursor.execute("UPDATE otp_codes SET is_used = TRUE WHERE id = %s", (otp_record['id'],))
                    conn.commit()
                    return False, "Kode OTP salah. Silakan minta kode baru."
            
        except Exception as e:
            print(f"❌ Error verifikasi OTP: {str(e)}")
            return False, "Error sistem"
        finally:
            cursor.close()
            conn.close()
    
    def get_otp_status(self, user_id, session_id):
        """
        Mendapatkan status OTP untuk user
        """
        conn = get_db_connection()
        conn.select_db(app_config.DB_NAME)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT id, created_at, expires_at, attempt_count, is_used
                FROM otp_codes 
                WHERE user_id = %s AND session_id = %s
                ORDER BY created_at DESC 
                LIMIT 1
            """, (user_id, session_id))
            
            otp_record = cursor.fetchone()
            
            if not otp_record:
                return None
            
            now = datetime.now(jakarta_tz)
            time_remaining = (otp_record['expires_at'] - now).total_seconds()
            
            return {
                'exists': True,
                'is_used': otp_record['is_used'],
                'is_expired': time_remaining <= 0,
                'time_remaining': max(0, int(time_remaining)),
                'attempts_remaining': max(0, self.max_attempts - otp_record['attempt_count']),
                'created_at': otp_record['created_at'],
                'expires_at': otp_record['expires_at']
            }
            
        except Exception as e:
            print(f"❌ Error mendapatkan status OTP: {str(e)}")
            return None
        finally:
            cursor.close()
            conn.close()
    
    def invalidate_user_otps(self, user_id):
        """
        Invalidasi semua OTP aktif untuk user (untuk logout/security)
        """
        conn = get_db_connection()
        conn.select_db(app_config.DB_NAME)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                UPDATE otp_codes 
                SET is_used = TRUE 
                WHERE user_id = %s AND is_used = FALSE
            """, (user_id,))
            
            conn.commit()
            affected_rows = cursor.rowcount
            
            if affected_rows > 0:
                print(f"✅ Berhasil invalidasi {affected_rows} OTP untuk user {user_id}")
            
        except Exception as e:
            print(f"❌ Error invalidasi OTP: {str(e)}")
        finally:
            cursor.close()
            conn.close() 
