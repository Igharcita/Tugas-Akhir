#!/usr/bin/env python3
"""
Script untuk membersihkan data sintetis yang salah timezone dari database
Hapus data sintetis lama sebelum membuat data sintetis baru yang benar
"""

import pymysql
import app_config
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
        init_command='SET time_zone = "+07:00"'
    )
    
    cursor = conn.cursor()
    cursor.execute("SET time_zone = '+07:00'")
    cursor.close()
    
    return conn

def cleanup_synthetic_data(username="ighar"):
    """Membersihkan data sintetis dari database"""
    print("🧹 CLEANUP DATA SINTETIS DARI DATABASE")
    print("=" * 50)
    
    conn = get_db_connection()
    conn.select_db(app_config.DB_NAME)
    cursor = conn.cursor()
    
    try:
        # 1. Dapatkan user_id
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        user_data = cursor.fetchone()
        
        if not user_data:
            print(f"❌ User '{username}' tidak ditemukan")
            return
        
        user_id = user_data['id']
        print(f"✅ User ID untuk '{username}': {user_id}")
        
        # 2. Cek data sintetis yang ada
        cursor.execute("""
            SELECT COUNT(*) as total_synthetic
            FROM login_history 
            WHERE user_id = %s AND ip_address = '127.0.0.1'
        """, (user_id,))
        
        synthetic_count = cursor.fetchone()['total_synthetic']
        print(f"📊 Data sintetis yang ditemukan: {synthetic_count}")
        
        if synthetic_count == 0:
            print("✅ Tidak ada data sintetis untuk dibersihkan")
            return
        
        # 3. Tampilkan contoh data sintetis
        cursor.execute("""
            SELECT 
                id,
                CONVERT_TZ(login_timestamp, '+00:00', '+07:00') as login_timestamp_wib,
                login_timestamp as login_timestamp_utc,
                ip_address,
                risk_score
            FROM login_history 
            WHERE user_id = %s AND ip_address = '127.0.0.1'
            ORDER BY login_timestamp DESC
            LIMIT 5
        """, (user_id,))
        
        sample_data = cursor.fetchall()
        print("\n📋 CONTOH DATA SINTETIS YANG AKAN DIHAPUS:")
        print("-" * 50)
        for record in sample_data:
            print(f"ID: {record['id']}")
            print(f"  WIB:  {record['login_timestamp_wib']}")
            print(f"  UTC:  {record['login_timestamp_utc']}")
            print(f"  IP:   {record['ip_address']}")
            print(f"  Risk: {record['risk_score']}")
            print()
        
        # 4. Konfirmasi penghapusan
        print("⚠️ PERINGATAN: Operasi ini akan menghapus data sintetis!")
        response = input("Apakah Anda yakin ingin menghapus data sintetis? (y/N): ")
        
        if response.lower() != 'y':
            print("❌ Operasi dibatalkan")
            return
        
        # 5. Hapus data sintetis
        cursor.execute("""
            DELETE FROM login_history 
            WHERE user_id = %s AND ip_address = '127.0.0.1'
        """, (user_id,))
        
        deleted_count = cursor.rowcount
        conn.commit()
        
        print(f"✅ Berhasil menghapus {deleted_count} data sintetis dari database")
        
        # 6. Verifikasi penghapusan
        cursor.execute("""
            SELECT COUNT(*) as remaining_synthetic
            FROM login_history 
            WHERE user_id = %s AND ip_address = '127.0.0.1'
        """, (user_id,))
        
        remaining = cursor.fetchone()['remaining_synthetic']
        print(f"📊 Data sintetis yang tersisa: {remaining}")
        
        if remaining == 0:
            print("✅ Semua data sintetis berhasil dihapus")
        else:
            print("⚠️ Masih ada data sintetis yang tersisa")
        
        # 7. Tampilkan data yang tersisa
        cursor.execute("""
            SELECT COUNT(*) as total_remaining
            FROM login_history 
            WHERE user_id = %s
        """, (user_id,))
        
        total_remaining = cursor.fetchone()['total_remaining']
        print(f"📊 Total data login yang tersisa: {total_remaining}")
        
    except Exception as e:
        conn.rollback()
        print(f"❌ Error membersihkan data: {str(e)}")
    finally:
        cursor.close()
        conn.close()

def verify_cleanup(username="ighar"):
    """Verifikasi hasil cleanup"""
    print("\n🔍 VERIFIKASI HASIL CLEANUP")
    print("=" * 30)
    
    conn = get_db_connection()
    conn.select_db(app_config.DB_NAME)
    cursor = conn.cursor()
    
    try:
        # Dapatkan user_id
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        user_data = cursor.fetchone()
        
        if not user_data:
            print(f"❌ User '{username}' tidak ditemukan")
            return
        
        user_id = user_data['id']
        
        # Cek data yang tersisa
        cursor.execute("""
            SELECT 
                COUNT(*) as total_logins,
                COUNT(CASE WHEN ip_address = '127.0.0.1' THEN 1 END) as synthetic_logins,
                COUNT(CASE WHEN ip_address != '127.0.0.1' THEN 1 END) as real_logins
            FROM login_history 
            WHERE user_id = %s
        """, (user_id,))
        
        stats = cursor.fetchone()
        print(f"📊 Total login: {stats['total_logins']}")
        print(f"📊 Data sintetis: {stats['synthetic_logins']}")
        print(f"📊 Data real: {stats['real_logins']}")
        
        if stats['synthetic_logins'] == 0:
            print("✅ Cleanup berhasil - tidak ada data sintetis tersisa")
        else:
            print("⚠️ Masih ada data sintetis tersisa")
        
    except Exception as e:
        print(f"❌ Error verifikasi: {str(e)}")
    finally:
        cursor.close()
        conn.close()

def main():
    """Fungsi utama"""
    print("🚀 CLEANUP DATA SINTETIS - PERBAIKAN TIMEZONE")
    print("=" * 60)
    
    username = "ighar"
    
    # Cleanup data sintetis
    cleanup_synthetic_data(username)
    
    # Verifikasi hasil
    verify_cleanup(username)
    
    print("\n✅ Proses cleanup selesai!")
    print("💡 Sekarang Anda bisa menjalankan sintetis.py yang sudah diperbaiki")

if __name__ == "__main__":
    main() 