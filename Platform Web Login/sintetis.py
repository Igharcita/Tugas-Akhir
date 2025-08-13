#!/usr/bin/env python3
"""
Script untuk membuat data sintetis user ighar dengan kriteria:
- Total 30 login sukses
- 1–2 login per hari, tanggal unik acak, seluruhnya sebelum 8 Agustus 2025
- Minimal 2-3 pola waktu login (pagi, siang, sore) dalam rentang 08:00–16:00 WIB
- 100% menggunakan perangkat/lokasi yang sama: Chrome, Windows, desktop, ASN 38496, Region ID, Org CNI-ID
- Jeda waktu realistis (30–90 menit) antar login pada hari yang sama, tetap dalam jam kerja
- Menyimpan timestamp dalam WIB untuk konsistensi dengan aplikasi utama
"""

import json
import random
import os
import uuid
from datetime import datetime, timedelta
import pytz
import pymysql
import sys

# Konfigurasi database
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'db': 'rba_login_db',
    'charset': 'utf8mb4',
    'cursorclass': pymysql.cursors.DictCursor
}

# Konfigurasi direktori untuk menyimpan file JSON
DATA_DIR = 'login_data'

# Set timezone untuk Jakarta (WIB)
jakarta_tz = pytz.timezone('Asia/Jakarta')

def get_db_connection():
    """Mendapatkan koneksi database"""
    try:
        conn = pymysql.connect(
            host=DB_CONFIG['host'],
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password'],
            db=DB_CONFIG['db'],
            charset=DB_CONFIG['charset'],
            cursorclass=DB_CONFIG['cursorclass'],
            init_command='SET time_zone = "+07:00"'
        )
        return conn
    except Exception as e:
        print(f"❌ Error koneksi database: {str(e)}")
        return None

def get_user_id(username):
    """Mendapatkan user_id dari username"""
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        
        if user:
            return user['id']
        else:
            print(f"⚠️ User '{username}' tidak ditemukan")
            return None
    except Exception as e:
        print(f"❌ Error mendapatkan user_id: {str(e)}")
        return None
    finally:
        conn.close()

def add_realistic_time_gaps(login_times_by_date):
    """
    Menambahkan jeda waktu yang realistis antara login pada hari yang sama
    
    Args:
        login_times_by_date: Dictionary dengan tanggal sebagai kunci dan list waktu login sebagai nilai
        
    Returns:
        Dictionary dengan tanggal sebagai kunci dan list waktu login yang sudah diatur dengan jeda
    """
    result = {}
    
    for date, times in login_times_by_date.items():
        # Urutkan waktu login
        times.sort()
        
        # Jika hanya ada 1 login pada hari ini, tidak perlu jeda
        if len(times) <= 1:
            result[date] = times
            continue
            
        # Untuk setiap hari dengan lebih dari 1 login, tambahkan jeda waktu
        adjusted_times = []
        
        # Tambahkan waktu login pertama
        adjusted_times.append(times[0])
        
        for i in range(1, len(times)):
            prev_time = adjusted_times[-1]
            current_time = times[i]
            
            # Pastikan ada minimal 30-90 menit jeda antara login
            min_gap_minutes = 30
            max_gap_minutes = 90
            
            # Hitung jeda waktu saat ini dalam menit
            current_gap = (current_time - prev_time).total_seconds() / 60
            
            # PERBAIKAN: Jika jeda terlalu pendek, tambahkan jeda
            if current_gap < min_gap_minutes:
                # Tambahkan jeda acak antara min_gap dan max_gap
                gap_minutes = random.randint(min_gap_minutes, max_gap_minutes)
                new_time = prev_time + timedelta(minutes=gap_minutes)
                
                # PERBAIKAN: Pastikan waktu baru masih dalam jam kerja (08:00 - 16:00)
                if (new_time.hour > 16) or (new_time.hour == 16 and (new_time.minute > 0 or new_time.second > 0)):
                    # Jika melebihi jam 16:00, coba dengan jeda minimal
                    new_time = prev_time + timedelta(minutes=min_gap_minutes)
                    # Jika masih melebihi jam 16:00, gunakan waktu asli tapi tambahkan warning
                    if (new_time.hour > 16) or (new_time.hour == 16 and (new_time.minute > 0 or new_time.second > 0)):
                        print(f"⚠️ Login {new_time} melebihi jam kerja (>=16:00), menggunakan waktu asli")
                        new_time = current_time
                
                # PERBAIKAN: Selalu tambahkan waktu, jangan skip
                adjusted_times.append(new_time)
            else:
                # Jeda sudah cukup, gunakan waktu asli
                adjusted_times.append(current_time)
        
        result[date] = adjusted_times
    
    return result

def generate_synthetic_data(username):
    """Membuat data sintetis untuk user"""
    user_id = get_user_id(username)
    if not user_id:
        print(f"❌ Tidak dapat membuat data sintetis untuk user '{username}', user tidak ditemukan")
        return
    
    print(f"🔍 Membuat data sintetis untuk user '{username}' (ID: {user_id})...")
    
    # Tetapkan parameter perangkat yang konsisten
    device_params = {
        'browser': 'Chrome',
        'platform': 'Windows',
        'device_type': 'desktop',
        'ip_address': '127.0.0.1',
        'asn': 38496,
        'region': 'ID',
        'org': 'CNI-ID',
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36'
    }
    
    # Definisikan pola waktu login
    time_patterns = {
        'pagi': {'hour_start': 8, 'hour_end': 10},
        'siang': {'hour_start': 12, 'hour_end': 14},
        'sore': {'hour_start': 15, 'hour_end': 16}
    }
    
    # Tentukan tanggal mulai dan selesai (sebelum 11 Agustus 2025)
    end_date = datetime(2025, 8, 10)  # 10 Agustus 2025 sebagai hari terakhir
    start_date = end_date - timedelta(days=30)  # jendela 30 hari ke belakang
    
    # Tentukan jumlah login yang akan dibuat (persyaratan: 30)
    total_logins = 30
    
    # Buat daftar tanggal yang akan digunakan (15–30 hari berbeda; 1–2 login/hari)
    num_days = random.randint(15, 30)
    all_dates = [start_date + timedelta(days=i) for i in range((end_date - start_date).days + 1)]
    selected_dates = sorted(random.sample(all_dates, num_days))
    
    # Distribusikan login: 1–2 per hari harus berjumlah total_logins
    login_distribution = distribute_logins_one_to_two(total_logins, num_days)
    
    # Kumpulkan waktu login berdasarkan tanggal
    login_times_by_date = {}
    
    used_patterns_global = set()
    for i, date in enumerate(selected_dates):
        num_logins_today = login_distribution[i]
        login_times_by_date[date] = []
        
        # Pilih pola waktu untuk hari ini
        available_patterns = list(time_patterns.keys())
        if num_logins_today == 1:
            today_patterns = [random.choice(available_patterns)]
        else:  # 2 login/hari -> gunakan 2 pola berbeda untuk variasi
            today_patterns = random.sample(available_patterns, 2)
        
        # Buat login untuk setiap pola waktu
        for pattern in today_patterns:
            time_range = time_patterns[pattern]
            
            # Tentukan jam dan menit secara acak dalam rentang pola
            hour = random.randint(time_range['hour_start'], time_range['hour_end'])
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            
            # Buat timestamp login
            login_time = date.replace(hour=hour, minute=minute, second=second)
            login_times_by_date[date].append(login_time)
            used_patterns_global.add(pattern)
    
    # Tambahkan jeda waktu yang realistis
    login_times_by_date = add_realistic_time_gaps(login_times_by_date)
    
    # Buat data login dari waktu yang sudah diatur
    login_data = []
    
    for date, times in login_times_by_date.items():
        for login_time in times:
            # PERBAIKAN: Gunakan WIB untuk semua timestamp (konsisten dengan aplikasi utama)
            login_time_wib = jakarta_tz.localize(login_time)
            
            # Buat data login dengan timestamp WIB
            login_entry = {
                'login_id': str(uuid.uuid4()),
                'timestamp': login_time_wib.isoformat(),  # Simpan dalam WIB
                'username': username,
                'ip_address': device_params['ip_address'],
                'user_agent': device_params['user_agent'],
                'browser': device_params['browser'],
                'platform': device_params['platform'],
                'device_type': device_params['device_type'],
                'success': True,
                'geolocation_info': {
                    'asn': device_params['asn'],
                    'country': 'ID',
                    'region': device_params['region'],
                    'org': device_params.get('org', 'CNI-ID')
                }
            }
            
            login_data.append(login_entry)
    
    # Urutkan login berdasarkan timestamp
    login_data.sort(key=lambda x: x['timestamp'])
    
    return login_data

def distribute_logins_one_to_two(total_logins, num_days):
    """Mendistribusikan login sehingga setiap hari 1–2 login dan total sesuai."""
    if num_days < 1:
        return []
    min_total = num_days
    max_total = num_days * 2
    if not (min_total <= total_logins <= max_total):
        # Sesuaikan num_days jika tak konsisten; fallback ke batas terdekat
        num_days = max(1, min(total_logins, total_logins // 1))
        min_total = num_days
        max_total = num_days * 2
        if not (min_total <= total_logins <= max_total):
            # fallback keras: paksa num_days agar valid
            num_days = max(1, min(total_logins, 30))
    distribution = [1] * num_days
    remaining = total_logins - num_days
    while remaining > 0:
        idx = random.randrange(num_days)
        if distribution[idx] < 2:
            distribution[idx] += 1
            remaining -= 1
    return distribution

def distribute_logins(total_logins, num_days):
    """Mendistribusikan jumlah login ke sejumlah hari"""
    # Pastikan setiap hari minimal mendapat 1 login
    distribution = [1] * num_days
    remaining = total_logins - num_days
    
    # Distribusikan login yang tersisa secara acak
    for _ in range(remaining):
        idx = random.randint(0, num_days - 1)
        distribution[idx] += 1
    
    return distribution

def distribute_logins_realistic(total_logins, num_days):
    """Mendistribusikan login dengan variasi yang lebih realistis"""
    distribution = []
    for i in range(num_days):
        # Variasi: 0-4 login per hari (bukan selalu 2-3)
        if i == 0:  # Hari pertama
            distribution.append(1)  # Mulai dengan 1 login
        else:
            # Random antara 0-4 login
            count = random.choice([0, 1, 2, 3, 4])
            distribution.append(count)
    
    # Pastikan total sesuai
    current_total = sum(distribution)
    while current_total < total_logins:
        idx = random.randint(0, num_days - 1)
        if distribution[idx] < 4:
            distribution[idx] += 1
            current_total += 1
    
    return distribution

def save_to_json_files(login_data):
    """Menyimpan data login ke file JSON"""
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
    
    saved_files = []
    
    for login in login_data:
        login_id = login['login_id']
        filename = os.path.join(DATA_DIR, f"login_{login_id}.json")
        
        # Gunakan timestamp WIB untuk JSON file (konsisten dengan aplikasi utama)
        json_data = login.copy()
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2)
        
        saved_files.append(filename)
    
    print(f"✅ {len(saved_files)} file JSON berhasil disimpan di folder '{DATA_DIR}'")
    return saved_files

def save_to_database(login_data, user_id):
    """Menyimpan data login ke database dengan timestamp WIB"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        
        for login in login_data:
            # Parse timestamp WIB
            timestamp = login['timestamp']  # Sudah dalam WIB
            if isinstance(timestamp, str):
                # Parse ISO format WIB
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                # Pastikan timezone WIB
                if not timestamp.tzinfo:
                    timestamp = jakarta_tz.localize(timestamp)
            
            # Insert ke database dengan timestamp WIB
            cursor.execute("""
                INSERT INTO login_history 
                (user_id, login_timestamp, ip_address, user_agent, browser, os_name, device_type, 
                success, risk_score, risk_level, asn, region)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                user_id,
                timestamp,  # Timestamp WIB
                login['ip_address'],
                login['user_agent'],
                login['browser'],
                login['platform'],
                login['device_type'],
                login['success'],
                0.1,  # risk_score default rendah
                0,    # risk_level default rendah
                login['geolocation_info']['asn'],
                login['geolocation_info']['region']
            ))
        
        conn.commit()
        print(f"✅ {len(login_data)} data login berhasil disimpan ke database (WIB)")
        return True
    except Exception as e:
        conn.rollback()
        print(f"❌ Error menyimpan ke database: {str(e)}")
        return False
    finally:
        conn.close()

def main():
    """Fungsi utama"""
    print("🚀 Membuat Data Sintetis Login (DIPERBAIKI - WIB)")
    print("📅 Periode: 30 hari sebelum 10 Agustus 2025")
    print("=" * 60)
    
    username = "igharcita"
    
    # Dapatkan user_id
    user_id = get_user_id(username)
    if not user_id:
        print(f"❌ User '{username}' tidak ditemukan. Pastikan user sudah terdaftar.")
        return
    
    # Generate data sintetis
    login_data = generate_synthetic_data(username)
    
    if not login_data:
        print("❌ Gagal membuat data sintetis")
        return
    
    print(f"✅ Berhasil membuat {len(login_data)} data login sintetis")
    
    # Tampilkan ringkasan dengan timezone yang benar
    dates = set()
    patterns = {}
    
    for login in login_data:
        # Parse timestamp WIB untuk analisis
        timestamp_wib = datetime.fromisoformat(login['timestamp'].replace('Z', '+00:00'))
        dates.add(timestamp_wib.date())
        
        hour = timestamp_wib.hour
        if hour < 12:
            pattern = "pagi"
        elif hour < 15:
            pattern = "siang"
        else:
            pattern = "sore"
        patterns[pattern] = patterns.get(pattern, 0) + 1
    
    print("\n📊 Ringkasan Data Sintetis (WIB):")
    print(f"- Total login: {len(login_data)}")
    print(f"- Jumlah hari: {len(dates)}")
    print(f"- Rentang tanggal: {min(dates)} sampai {max(dates)}")
    print(f"- Distribusi waktu: {patterns}")
    
    # Analisis jeda waktu antar login pada hari yang sama
    time_gaps = []
    prev_login = None
    prev_date = None
    
    for login in login_data:
        current_time = datetime.fromisoformat(login['timestamp'].replace('Z', '+00:00'))
        current_date = current_time.date()
        
        if prev_login and current_date == prev_date:
            gap_minutes = (current_time - prev_login).total_seconds() / 60
            time_gaps.append(gap_minutes)
        
        prev_login = current_time
        prev_date = current_date
    
    if time_gaps:
        avg_gap = sum(time_gaps) / len(time_gaps)
        min_gap = min(time_gaps)
        max_gap = max(time_gaps)
        print(f"- Jeda waktu antar login (pada hari yang sama):")
        print(f"  - Rata-rata: {avg_gap:.1f} menit")
        print(f"  - Minimum: {min_gap:.1f} menit")
        print(f"  - Maksimum: {max_gap:.1f} menit")
    
    # Tampilkan contoh timestamp
    print("\n🌍 CONTOH TIMESTAMP:")
    print("-" * 30)
    sample_login = login_data[0]
    timestamp_wib = datetime.fromisoformat(sample_login['timestamp'].replace('Z', '+00:00'))
    print(f"WIB:  {timestamp_wib.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Format: {sample_login['timestamp']}")
    
    # Simpan ke file JSON
    saved_files = save_to_json_files(login_data)
    
    # Simpan ke database
    if saved_files:
        save_to_database(login_data, user_id)
    
    print("\n✅ Proses pembuatan data sintetis selesai!")
    print("🔧 PERBAIKAN: Data sekarang disimpan dalam WIB di database (konsisten dengan aplikasi utama)")
    print("📝 CATATAN: Login terakhir pada 10 Agustus 2025, siap untuk testing pada 11 Agustus 2025")

if __name__ == "__main__":
    main() 