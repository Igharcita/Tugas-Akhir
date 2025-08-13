#!/usr/bin/env python3
"""
Script untuk cleanup OTP yang kedaluwarsa secara berkala
Menjalankan cleanup setiap 5 menit untuk menjaga performa
"""

import time
import threading
from datetime import datetime
import pytz
from otp_service import OTPService

# Set timezone untuk aplikasi
jakarta_tz = pytz.timezone('Asia/Jakarta')

class OTPCleanupScheduler:
    def __init__(self, interval_minutes=5):
        self.interval_minutes = interval_minutes
        self.otp_service = OTPService()
        self.running = False
        self.cleanup_thread = None
    
    def start(self):
        """Mulai scheduler cleanup"""
        if self.running:
            print("⚠️ Cleanup scheduler sudah berjalan")
            return
        
        self.running = True
        self.cleanup_thread = threading.Thread(target=self._run_cleanup, daemon=True)
        self.cleanup_thread.start()
        print(f"✅ OTP Cleanup Scheduler dimulai (interval: {self.interval_minutes} menit)")
    
    def stop(self):
        """Hentikan scheduler cleanup"""
        self.running = False
        if self.cleanup_thread:
            self.cleanup_thread.join()
        print("🛑 OTP Cleanup Scheduler dihentikan")
    
    def _run_cleanup(self):
        """Jalankan cleanup secara berkala"""
        while self.running:
            try:
                current_time = datetime.now(jakarta_tz)
                print(f"🔄 Menjalankan cleanup OTP - {current_time.strftime('%Y-%m-%d %H:%M:%S WIB')}")
                self.otp_service.cleanup_expired_otps()
                
                # Tunggu interval berikutnya
                time.sleep(self.interval_minutes * 60)
                
            except Exception as e:
                print(f"❌ Error dalam cleanup scheduler: {str(e)}")
                time.sleep(30)  # Tunggu 30 detik sebelum retry
    
    def cleanup_now(self):
        """Jalankan cleanup sekarang juga"""
        try:
            print("🔄 Menjalankan cleanup manual...")
            self.otp_service.cleanup_expired_otps()
            print("✅ Cleanup manual selesai")
        except Exception as e:
            print(f"❌ Error cleanup manual: {str(e)}")

# Instance global untuk digunakan di aplikasi
cleanup_scheduler = OTPCleanupScheduler()

if __name__ == "__main__":
    # Jika dijalankan langsung, jalankan cleanup scheduler
    print("🚀 Memulai OTP Cleanup Scheduler...")
    
    try:
        cleanup_scheduler.start()
        
        # Jalankan cleanup manual pertama kali
        cleanup_scheduler.cleanup_now()
        
        # Biarkan scheduler berjalan
        while True:
            time.sleep(60)  # Check setiap menit
            
    except KeyboardInterrupt:
        print("\n🛑 Menghentikan scheduler...")
        cleanup_scheduler.stop()
        print("✅ Scheduler dihentikan") 
