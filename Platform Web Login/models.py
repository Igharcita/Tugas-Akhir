import pickle
import numpy as np
import json
import warnings
from datetime import datetime, timedelta
import pytz
from user_agents import parse
from database import get_db_connection
import app_config
import joblib
import pandas as pd
import numpy as np
from collections import Counter
import os
import uuid

# Import library untuk geolokasi dan ASN
try:
    from ipwhois import IPWhois
    from cymruwhois import Client as CymruClient
    GEOLOCATION_AVAILABLE = True
except ImportError:
    GEOLOCATION_AVAILABLE = False
    print("⚠️ Warning: ipwhois atau cymruwhois tidak tersedia. Geolocation Anomaly akan menggunakan fallback.")

# Set timezone untuk aplikasi
jakarta_tz = pytz.timezone('Asia/Jakarta')

# ========== WEIGHTED RULE SYSTEM ==========

def normalize_weights(weights):
    """Menormalisasi bobot menjadi proporsi (Σ=1)"""
    total_weight = sum(weights.values())
    if total_weight == 0:
        return {k: 1.0/len(weights) for k in weights.keys()}
    
    return {k: v/total_weight for k, v in weights.items()}

def calculate_rule_weighted_score(anomaly_features):
    """Menghitung rule-based weighted score"""
    # Normalisasi bobot
    normalized_weights = normalize_weights(app_config.FEATURE_WEIGHTS)
    
    # Hitung weighted sum
    weighted_sum = 0.0
    total_weight = 0.0
    
    for feature, weight in normalized_weights.items():
        if feature in anomaly_features:
            score = anomaly_features[feature]
            weighted_sum += weight * score
            total_weight += weight
    
    # Normalisasi hasil akhir
    if total_weight > 0:
        return weighted_sum / total_weight
    else:
        return 0.0

def calculate_hybrid_score(if_score, rule_score, alpha=0.5):
    """Menghitung hybrid score dengan formula: combined = α * if_score + (1-α) * rule_score"""
    return alpha * if_score + (1 - alpha) * rule_score

def determine_risk_level_hybrid(combined_score: float, thresholds: dict) -> int:
    """Menentukan risk level berdasarkan combined score"""
    lower_threshold = thresholds.get('lower_threshold', 0.2595)
    upper_threshold = thresholds.get('upper_threshold', 0.5750)
    
    if combined_score <= lower_threshold:
        return 0  # Rendah
    elif combined_score <= upper_threshold:
        return 1  # Sedang
    else:
        return 2  # Tinggi

class RBAModel:
    def __init__(self):
        """Inisialisasi model RBA"""
        self.isolation_model = None
        self.model_features = []
        self.thresholds = {}
        self.cymru_client = None
        
        # Inisialisasi Cymru client untuk geolokasi
        if GEOLOCATION_AVAILABLE:
            try:
                self.cymru_client = CymruClient()
            except Exception as e:
                print(f"⚠️ Warning: Tidak dapat inisialisasi Cymru client: {str(e)}")
        
        # Load model
        self.load_model()
    
    def load_model(self):
        """Load model Isolation Forest"""
        try:
            with open(app_config.MODEL_PATH, 'rb') as f:
                model_data = pickle.load(f)
                self.isolation_model = model_data['pipeline']
                self.model_features = model_data.get('features', [])
            
                # Penting: ambil score_min & score_max
                self.score_min = model_data.get('score_min', None)
                self.score_max = model_data.get('score_max', None)
                
                if self.score_min is None or self.score_max is None:
                    # Jika tidak ada di model, coba ambil dari threshold_info_universal.json
                    try:
                        with open('threshold_info_universal.json', 'r') as f:
                            threshold_info = json.load(f)
                            self.thresholds = threshold_info
                            
                            # Ambil score_min dan score_max dari threshold_info
                            scoring_info = threshold_info.get('scoring_information', {})
                            self.score_min = scoring_info.get('score_min', -0.1437)
                            self.score_max = scoring_info.get('score_max', 0.2414)
                    except Exception as e:
                        print(f"⚠️ Warning: Tidak dapat membaca threshold_info: {str(e)}")
                        self.thresholds = {'lower_threshold': 0.2595, 'upper_threshold': 0.5750}
                        # Default values dari rba_universal_isolation_0.9068_info.txt
                        self.score_min = -0.1437
                        self.score_max = 0.2414
            
            # Load threshold info
            with open('threshold_info_universal.json', 'r') as f:
                threshold_info = json.load(f)
                self.thresholds = threshold_info
            
            print("✅ Model dan threshold berhasil dimuat")
            print(f"✅ Score range: [{self.score_min}, {self.score_max}]")
        except Exception as e:
            print(f"❌ Error memuat model: {str(e)}")
            self.isolation_model = None
            self.model_features = []
            self.thresholds = {'lower_threshold': 0.2595, 'upper_threshold': 0.5750}
            self.score_min = -0.1437
            self.score_max = 0.2414
    
    def get_geolocation_info(self, ip_address):
        """Mendapatkan informasi geolokasi dari IP address"""
        try:
            # Untuk IP lokal/private, return data lokal sederhana
            if ip_address in ['127.0.0.1', 'localhost'] or ip_address.startswith(('192.168.', '10.', '172.')):
                # Pairwise test mode: izinkan override geolokasi agar tidak selalu anomali
                try:
                    if getattr(app_config, 'ENABLE_PAIRWISE_TEST', False):
                        override = getattr(app_config, 'PAIRWISE_LOCKS', {}).get('geo_override_for_local')
                        if override and isinstance(override, dict):
                            return {
                                'asn': override.get('asn', 0),
                                'country': override.get('country', 'Local'),
                                'region': override.get('region', 'Local'),
                                'org': override.get('org', 'Local Network')
                            }
                except Exception:
                    pass
                return {
                    'asn': 0,
                    'country': 'Local',
                    'region': 'Local',
                    'org': 'Local Network'
                }
            
            if GEOLOCATION_AVAILABLE and self.cymru_client:
                # Gunakan IPWhois terlebih dahulu untuk informasi lengkap
                try:
                    obj = IPWhois(ip_address)
                    whois_result = obj.lookup_rdap(depth=1)
                    
                    # Ekstrak informasi dari IPWhois
                    geo_info = {
                        'asn': int(whois_result.get('asn', '0').replace('AS', '')) if whois_result.get('asn') else 0,
                        'country': whois_result.get('asn_country_code', 'Unknown'),
                        'region': whois_result.get('network', {}).get('country', 'Unknown'),
                        'org': whois_result.get('network', {}).get('name', 'Unknown')
                    }
                    
                    # Gunakan Cymru sebagai backup untuk ASN jika IPWhois gagal
                    if geo_info['asn'] == 0:
                        result = self.cymru_client.lookup(ip_address)
                        geo_info['asn'] = result.asn if result.asn else 0
                        if not geo_info['org'] or geo_info['org'] == 'Unknown':
                            geo_info['org'] = result.owner if result.owner else 'Unknown'
                    
                    return geo_info
                    
                except Exception as whois_error:
                    print(f"⚠️ IPWhois error untuk {ip_address}: {str(whois_error)}")
                    # Fallback ke Cymru
                    try:
                        result = self.cymru_client.lookup(ip_address)
                        return {
                            'asn': result.asn if result.asn else 0,
                            'country': result.cc if result.cc else 'Unknown',
                            'region': result.cc if result.cc else 'Unknown',
                            'org': result.owner if result.owner else 'Unknown'
                        }
                    except Exception as cymru_error:
                        print(f"⚠️ Cymru error untuk {ip_address}: {str(cymru_error)}")
                        raise
            else:
                # Fallback untuk IP public tanpa library geolokasi
                return {
                    'asn': 7713,  # Default Telkom Indonesia
                    'country': 'Indonesia',
                    'region': 'Jakarta', 
                    'org': 'PT Telekomunikasi Indonesia'
                }
                
        except Exception as e:
            print(f"❌ Error geolokasi untuk {ip_address}: {str(e)}")
            return {
                'asn': 0,
                'country': 'Unknown',
                'region': 'Unknown',
                'org': 'Unknown'
            }
    
    def ensure_timezone(self, dt):
        """Pastikan datetime object memiliki timezone WIB yang konsisten"""
        if not dt:
            return datetime.now(jakarta_tz)
        
        if not dt.tzinfo:
            # Jika tidak ada timezone, anggap sebagai WIB
            return jakarta_tz.localize(dt)
        elif dt.tzinfo != jakarta_tz:
            # Jika timezone berbeda, konversi ke WIB
            return dt.astimezone(jakarta_tz)
        else:
            # Sudah WIB, return as is
            return dt
    
    def calculate_anomaly_features(self, login_data, user_id, reference_time=None, history_limit=None):
        """
        Menghitung fitur anomali berdasarkan data historis dengan rumus universal yang sama dengan pelatihan
        """
        import os
        import json
        from datetime import datetime, timedelta
        from collections import Counter
        import numpy as np
        
        # Ekstraksi informasi login saat ini dengan timezone yang benar
        current_time = self.ensure_timezone(reference_time if reference_time else datetime.now())
        current_hour = current_time.hour
        current_browser = login_data.get('browser', 'Unknown')
        current_os = login_data.get('platform', 'Unknown')
        current_device = login_data.get('device_type', 'desktop')
        current_ip = login_data.get('ip_address', '127.0.0.1')
        
        # Dapatkan informasi geolokasi untuk IP saat ini
        current_geo = self.get_geolocation_info(current_ip)
        current_asn = current_geo['asn']
        current_region = current_geo.get('region', 'Unknown')
        
        # Baca data historis dari database (prioritas utama) dengan fallback ke file JSON
        history = self._load_login_history_from_database(user_id, current_time)
        if not history:
            # Fallback ke file JSON jika database kosong
            history = self._load_login_history_from_files(login_data.get('username', ''), current_time)
        
        # Simpan parameter yang diekstrak untuk transparansi
        extracted_params = {
            'current_time': current_time.strftime('%Y-%m-%d %H:%M:%S WIB'),
            'current_hour': current_hour,
            'current_browser': current_browser,
            'current_os': current_os,
            'current_device': current_device,
            'current_ip': current_ip,
            'current_geo': current_geo,
            'total_history_count': len(history),
            'history_limit_used': history_limit
        }
        
        # Inisialisasi fitur anomali
        anomaly_features = {}
        # Kontainer debug
        feature_debug = {
            'meta': {
                'user_id': user_id,
                'username': login_data.get('username'),
                'generated_at': current_time.strftime('%Y-%m-%d %H:%M:%S WIB')
            },
            'inputs': extracted_params,
            'history_summary': {},
            'features': {}
        }
        
        if not history:
            # Cold start - user baru atau tidak ada histori
            anomaly_features = {
                'OS Name_anomaly': 0.0,
                'Browser Name_anomaly': 0.0,
                'Device Type_anomaly': 0.0,
                'TimeOfHour_anomaly': 0.1,  # Sedikit anomali karena belum ada pola
                'DailyLoginCount_anomaly': 0.1,  # Login pertama hari ini
                'TimeBetweenLogins_anomaly': 0.0,  # Tidak ada login sebelumnya
                'FailedLogin_combined_anomaly': 0.0,
                'Geolocation_Anomaly': 0.0
            }
            extracted_params['analysis_type'] = 'cold_start'
        else:
            # Hitung fitur berdasarkan histori yang tersedia
            total_logins = len(history)
            extracted_params['analysis_type'] = 'historical_analysis'
            # Ringkasan histori
            try:
                recent_preview = [
                    {
                        'timestamp': h.get('timestamp'),
                        'hour': h.get('hour'),
                        'browser': h.get('browser'),
                        'os': h.get('platform'),
                        'device_type': h.get('device_type'),
                        'asn': h.get('asn'),
                        'region': h.get('region')
                    } for h in history[:5]
                ]
            except Exception:
                recent_preview = []
            feature_debug['history_summary'] = {
                'total_logins': total_logins,
                'recent_preview': recent_preview
            }
            
            # 1. OS Name Anomaly (Universal Categorical Formula)
            os_history = [h.get('platform', 'Unknown') for h in history if h.get('success', True)]
            os_similarity = self._calculate_categorical_similarity(current_os, os_history)
            anomaly_features['OS Name_anomaly'] = 1.0 - os_similarity
            feature_debug['features']['OS Name_anomaly'] = {
                'current': current_os,
                'history_counts': dict(Counter(os_history)),
                'similarity': round(os_similarity, 6),
                'anomaly': round(anomaly_features['OS Name_anomaly'], 6)
            }
            
            # 2. Browser Name Anomaly (Universal Categorical Formula)
            browser_history = [h.get('browser', 'Unknown') for h in history if h.get('success', True)]
            browser_similarity = self._calculate_categorical_similarity(current_browser, browser_history)
            anomaly_features['Browser Name_anomaly'] = 1.0 - browser_similarity
            feature_debug['features']['Browser Name_anomaly'] = {
                'current': current_browser,
                'history_counts': dict(Counter(browser_history)),
                'similarity': round(browser_similarity, 6),
                'anomaly': round(anomaly_features['Browser Name_anomaly'], 6)
            }
            
            # 3. Device Type Anomaly (Universal Categorical Formula)
            device_history = [h.get('device_type', 'desktop') for h in history if h.get('success', True)]
            device_similarity = self._calculate_categorical_similarity(current_device, device_history)
            anomaly_features['Device Type_anomaly'] = 1.0 - device_similarity
            feature_debug['features']['Device Type_anomaly'] = {
                'current': current_device,
                'history_counts': dict(Counter(device_history)),
                'similarity': round(device_similarity, 6),
                'anomaly': round(anomaly_features['Device Type_anomaly'], 6)
            }
            
            # 4. Time of Hour Anomaly (Universal Cyclic Formula - Persamaan 3.4.11)
            hour_history = [h.get('hour', 0) for h in history if h.get('success', True)]
            hour_similarity = self._calculate_cyclic_similarity(current_hour, hour_history, period=24, bins=24)
            anomaly_features['TimeOfHour_anomaly'] = 1.0 - hour_similarity
            # Buat histogram 24 bin untuk debug
            hour_hist = [0] * 24
            for v in hour_history:
                try:
                    bin_index = int(v * 24 / 24)
                    if bin_index >= 24:
                        bin_index = 23
                    hour_hist[bin_index] += 1
                except Exception:
                    pass
            feature_debug['features']['TimeOfHour_anomaly'] = {
                'current_hour': current_hour,
                'hour_histogram_24': hour_hist,
                'similarity': round(hour_similarity, 6),
                'anomaly': round(anomaly_features['TimeOfHour_anomaly'], 6)
            }
            
            # 5. Daily Login Count Anomaly (Universal Formula)
            daily_login_anomaly, daily_debug = self._calculate_daily_login_count_universal(
                user_id, current_time, return_debug=True
            )
            anomaly_features['DailyLoginCount_anomaly'] = daily_login_anomaly
            feature_debug['features']['DailyLoginCount_anomaly'] = daily_debug
            
            # 6. Time Between Logins Anomaly (Universal Formula)
            time_between_anomaly, tbl_debug = self._calculate_time_between_logins_universal(
                user_id, current_time, return_debug=True
            )
            anomaly_features['TimeBetweenLogins_anomaly'] = time_between_anomaly
            feature_debug['features']['TimeBetweenLogins_anomaly'] = tbl_debug
            
            # 7. Failed Login Combined (Universal Formula)
            failed_login_anomaly, failed_debug = self._calculate_failed_login_anomaly_universal(
                user_id, current_time, return_debug=True
            )
            anomaly_features['FailedLogin_combined_anomaly'] = failed_login_anomaly
            feature_debug['features']['FailedLogin_combined_anomaly'] = failed_debug
            
            # 8. Geolocation Anomaly (Universal Formula - G4 dan G5)
            geolocation_anomaly, geo_debug = self._calculate_geolocation_anomaly_universal(
                user_id, current_asn, current_region, history, return_debug=True
            )
            anomaly_features['Geolocation_Anomaly'] = geolocation_anomaly
            feature_debug['features']['Geolocation_Anomaly'] = geo_debug
        
        # Simpan parameter ekstraksi untuk transparansi
        anomaly_features['_extracted_params'] = extracted_params
        
        # Pairwise test mode: netralisasi fitur yang tidak dimask
        try:
            if getattr(app_config, 'ENABLE_PAIRWISE_TEST', False):
                allowed = set(getattr(app_config, 'PAIRWISE_FEATURE_MASK', []) or [])
                features_for_masking = {k: v for k, v in anomaly_features.items() if not k.startswith('_')}
                for feature_name in features_for_masking:
                    if feature_name not in allowed:
                        anomaly_features[feature_name] = 0.0
                # Tambahkan informasi pairwise ke debug nanti
                anomaly_features['_pairwise'] = {
                    'enabled': True,
                    'mask': list(allowed)
                }
        except Exception as e:
            print(f"⚠️ Pairwise test mode error: {str(e)}")

        # Tulis file debug jika diaktifkan
        try:
            enable_debug = getattr(app_config, 'ENABLE_FEATURE_DEBUG', True)
        except Exception:
            enable_debug = True
        if enable_debug:
            try:
                self._write_feature_debug_file(feature_debug)
            except Exception as e:
                print(f"⚠️ Gagal menulis debug fitur: {str(e)}")
        
        return anomaly_features
    
    def _calculate_categorical_similarity(self, current_value, user_history):
        """
        Menghitung similarity score untuk fitur kategorikal berdasarkan persamaan 3.4.2 dari paper
        """
        if not user_history or pd.isna(current_value):
            return 0.0
        
        # Hitung bobot setiap nilai dalam histori pengguna
        value_counts = Counter(user_history)
        total_weight = sum(value_counts.values())
        
        # Jika nilai saat ini ada dalam histori, hitung similaritas
        if current_value in value_counts:
            return value_counts[current_value] / total_weight
        return 0.0
    
    def _calculate_cyclic_similarity(self, current_value, user_history, period=24, bins=24):
        """
        Menghitung similarity score untuk fitur siklik berdasarkan persamaan 3.4.11 dari paper
        """
        if not user_history:
            return 0.0
        
        # Buat histogram untuk fitur siklik
        histogram = [0] * bins
        
        # Isi histogram berdasarkan histori
        for value in user_history:
            bin_index = int(value * bins / period)
            if bin_index >= bins:
                bin_index = bins - 1
            histogram[bin_index] += 1
        
        # Konversi nilai saat ini ke representasi sudut
        theta_x = 2 * np.pi * current_value / period
        
        # Hitung similaritas berdasarkan histori
        total_weight = sum(histogram)
        
        if total_weight > 0:
            weighted_sum = 0.0
            for i, weight in enumerate(histogram):
                theta_i = 2 * np.pi * i / bins
                weighted_sum += weight * np.cos(theta_x - theta_i)
            
            # Persamaan 3.4.11 dari paper
            similarity = 0.5 * (weighted_sum / total_weight + 1)
            return similarity
        
        return 0.0
    
    def _calculate_geolocation_anomaly_universal(self, user_id, current_asn, current_region, history, return_debug: bool = False):
        """
        Menghitung geolocation anomaly berdasarkan rumus universal (G4 dan G5)
        """
        if not history:
            return (0.0, {
                'current_asn': current_asn,
                'current_region': current_region,
                'used_asns_recent': [],
                'recent_regions': [],
                'g4_asn_new': 0.0,
                'g5_location_volatility_10': 0.0,
                'anomaly': 0.0
            }) if return_debug else 0.0
        
        # Ambil 10 login terakhir untuk analisis
        recent_history = history[:10] if len(history) >= 10 else history
        
        # G4: asn_new - 0 bila ASN pernah dipakai, 1 jika belum
        used_asns = set()
        for h in recent_history:
            asn = h.get('asn', 0)
            if asn is not None:
                used_asns.add(asn)
        
        g4_score = 0.0 if current_asn in used_asns else 1.0
        
        # G5: location_volatility_10 - (#perpindahan region ≠ sebelumnya dlm 10 login) / 10
        recent_regions = []
        for h in recent_history:
            region = h.get('region', 'Unknown')
            if region and region != 'Unknown':
                recent_regions.append(region)
        
        if len(recent_regions) > 0:
            # Hitung perpindahan region yang berbeda
            changes = 0
            for region in recent_regions:
                if region != current_region:
                    changes += 1
            g5_score = min(changes / 10.0, 1.0)
        else:
            g5_score = 0.0
        
        # Hitung skor anomali gabungan dengan 2 fitur terpilih
        # Bobot optimal: G4=0.60 (dominan), G5=0.40
        geolocation_anomaly = (
            0.60 * g4_score +   # ASN new (bobot tertinggi)
            0.40 * g5_score     # Location volatility
        )
        
        result = min(1.0, geolocation_anomaly)
        if return_debug:
            debug = {
                'current_asn': current_asn,
                'current_region': current_region,
                'used_asns_recent': list(used_asns),
                'recent_regions': recent_regions,
                'g4_asn_new': g4_score,
                'g5_location_volatility_10': g5_score,
                'weights': {'g4': 0.60, 'g5': 0.40},
                'anomaly': result
            }
            return result, debug
        return result
    
    def _load_login_history_from_files(self, username, current_time):
        """Membaca data historis login dari file JSON"""
        import os
        import json
        from datetime import datetime, timedelta
        
        history = []
        data_dir = app_config.DATA_DIR
        
        if not os.path.exists(data_dir):
            return history
        
        try:
            # Baca semua file JSON di direktori login_data
            for filename in os.listdir(data_dir):
                if filename.startswith('login_') and filename.endswith('.json'):
                    filepath = os.path.join(data_dir, filename)
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            login_data = json.load(f)
                            
                        # Filter berdasarkan username dan waktu (hanya data sebelum login saat ini)
                        if login_data.get('username') == username:
                            login_time = self._parse_timestamp(login_data.get('timestamp', ''))
                            if login_time and login_time < current_time:
                                # Tambahkan informasi yang diperlukan
                                login_data['hour'] = login_time.hour
                                login_data['date'] = login_time.strftime('%Y-%m-%d')
                                login_data['asn'] = login_data.get('geolocation_info', {}).get('asn', 0)
                                login_data['region'] = login_data.get('geolocation_info', {}).get('region', 'Unknown')
                                login_data['success'] = login_data.get('success', True)
                                history.append(login_data)
                                
                    except Exception as e:
                        print(f"⚠️ Error membaca file {filename}: {str(e)}")
                        continue
            
            # Sort berdasarkan timestamp (terbaru di atas)
            history.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            
            # Batasi jumlah data historis (opsional)
            if len(history) > 50:
                history = history[:50]
                
        except Exception as e:
            print(f"❌ Error membaca data historis: {str(e)}")
        
        return history
    
    def _load_login_history_from_database(self, user_id, current_time):
        """Membaca data historis login dari database"""
        conn = get_db_connection()
        conn.select_db(app_config.DB_NAME)
        cursor = conn.cursor()
        
        try:
            # PERBAIKAN: Hapus CONVERT_TZ karena database sudah WIB
            cursor.execute("""
                SELECT 
                    login_timestamp, 
                    browser, 
                    os_name, 
                    device_type,
                    ip_address,
                    asn,
                    region,
                    DATE(login_timestamp) as login_date
                FROM login_history 
                WHERE user_id = %s AND success = 1 AND login_timestamp < %s
                ORDER BY login_timestamp DESC 
                LIMIT 50
            """, (user_id, current_time))
            
            history = cursor.fetchall()
            
            # Konversi ke format yang konsisten dengan file JSON
            formatted_history = []
            for record in history:
                login_time = record['login_timestamp']  # Sudah WIB
                formatted_record = {
                    'timestamp': login_time.isoformat(),
                    'browser': record['browser'],
                    'platform': record['os_name'],  # Gunakan os_name sebagai platform
                    'device_type': record['device_type'],
                    'ip_address': record['ip_address'],
                    'hour': login_time.hour,
                    'date': login_time.strftime('%Y-%m-%d'),
                    'asn': record.get('asn', 0),
                    'region': record.get('region', 'Unknown'),
                    'success': True  # Semua data dari query ini adalah login sukses
                }
                formatted_history.append(formatted_record)
            
            return formatted_history
            
        except Exception as e:
            print(f"❌ Error membaca data historis dari database: {str(e)}")
            return []
        finally:
            cursor.close()
            conn.close()
    
    def _parse_timestamp(self, timestamp_str):
        """Parse timestamp string ke datetime object dengan timezone WIB yang konsisten"""
        if not timestamp_str:
            return None
        
        try:
            dt = None
            
            # Coba parse ISO format dengan timezone
            if '+' in timestamp_str or 'Z' in timestamp_str:
                # Handle Z suffix (UTC) dan timezone offset
                if timestamp_str.endswith('Z'):
                    timestamp_str = timestamp_str.replace('Z', '+00:00')
                
                dt = datetime.fromisoformat(timestamp_str)
                
                # PERBAIKAN: Selalu konversi ke WIB untuk konsistensi
                if dt.tzinfo:
                    dt = dt.astimezone(jakarta_tz)
                else:
                    # Jika tidak ada timezone info, anggap sebagai WIB
                    dt = jakarta_tz.localize(dt)
            else:
                # Fallback ke format sederhana dan tambahkan timezone WIB
                try:
                    # Coba format dengan mikrodetik
                    dt = datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S.%f')
                except ValueError:
                    try:
                        # Coba format tanpa mikrodetik
                        dt = datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S')
                    except ValueError:
                        # Coba format sederhana
                        dt = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                
                # PERBAIKAN: Pastikan selalu ada timezone WIB
                if dt and not dt.tzinfo:
                    dt = jakarta_tz.localize(dt)
            
            return dt
        except Exception as e:
            print(f"⚠️ Error parsing timestamp {timestamp_str}: {str(e)}")
            # Fallback: gunakan waktu saat ini dengan WIB
            return datetime.now(jakarta_tz)
    

    def _calculate_failed_login_anomaly_universal(self, user_id, current_time, return_debug: bool = False):
        """Menghitung failed login anomaly berdasarkan rumus universal linear features"""
        conn = get_db_connection()
        conn.select_db(app_config.DB_NAME)
        cursor = conn.cursor()
        
        try:
            # PERBAIKAN: Pastikan current_time memiliki timezone WIB
            current_time = self.ensure_timezone(current_time)
            
            cursor.execute("""
                SELECT 
                    login_timestamp,
                    success
                FROM login_history 
                WHERE user_id = %s AND login_timestamp < %s
                ORDER BY login_timestamp DESC
                LIMIT 20
            """, (user_id, current_time))
            
            login_records = cursor.fetchall()
            
            if not login_records:
                return (0.0, {
                    'consecutive_failed': 0,
                    'threshold_N': 5,
                    'anomaly': 0.0
                }) if return_debug else 0.0
            
            # Hitung consecutive failed logins saat ini
            consecutive_failed = 0
            for record in login_records:
                if record['success'] == 0:  # Login gagal
                    consecutive_failed += 1
                else:  # Login sukses, berhenti menghitung
                    break
            
            # Hitung failed login anomaly berdasarkan rumus universal
            N = 3  # Threshold untuk login gagal (sesuai paper)
            failed_login_anomaly = 1.0 - max(0, 1 - consecutive_failed/N)
            result = min(1.0, failed_login_anomaly)
            if return_debug:
                return result, {
                    'consecutive_failed': consecutive_failed,
                    'threshold_N': N,
                    'anomaly': result
                }
            return result
            
        except Exception as e:
            print(f"❌ Error calculating universal failed login anomaly: {str(e)}")
            import traceback
            traceback.print_exc()
            return 0.0
        finally:
            cursor.close()
            conn.close()
    
    def _calculate_time_between_logins_universal(self, user_id, current_time, return_debug: bool = False):
        """Menghitung time between logins anomaly berdasarkan rumus universal"""
        conn = get_db_connection()
        conn.select_db(app_config.DB_NAME)
        cursor = conn.cursor()
        
        try:
            # PERBAIKAN: Pastikan current_time memiliki timezone WIB
            current_time = self.ensure_timezone(current_time)
            
            # Ambil login terakhir dari database
            # PERBAIKAN: Tambahkan margin waktu untuk menghindari login yang sama
            margin_seconds = 5  # Margin 5 detik untuk menghindari login yang sama
            adjusted_current_time = current_time - timedelta(seconds=margin_seconds)
            
            cursor.execute("""
                SELECT login_timestamp
                FROM login_history 
                WHERE user_id = %s AND success = 1 AND login_timestamp < %s
                ORDER BY login_timestamp DESC
                LIMIT 20
            """, (user_id, adjusted_current_time))
            
            login_records = cursor.fetchall()
            
            if len(login_records) < 1:
                return (0.0, {
                    'last_login': None,
                    'current_time': current_time.isoformat(),
                    'current_diff_seconds': None,
                    'ema_seconds': None,
                    'std_dev_seconds': None,
                    'z_score': None,
                    'similarity': None,
                    'interval_mode': 'none',
                    'anomaly': 0.0
                }) if return_debug else 0.0
            
            # Hitung time between logins untuk login saat ini
            last_login_time = login_records[0]['login_timestamp']
            
            # PERBAIKAN: Pastikan last_login_time memiliki timezone yang sama
            if not last_login_time.tzinfo:
                last_login_time = jakarta_tz.localize(last_login_time)
                
            current_time_diff = (current_time - last_login_time).total_seconds()
            
            # Debug info
            print(f"🔍 TimeBetweenLogins Debug:")
            print(f"  - Current: {current_time}")
            print(f"  - Last: {last_login_time}")
            print(f"  - Diff: {current_time_diff}s ({current_time_diff/60:.1f}m)")
            
            # PERBAIKAN: Deteksi login yang terlalu cepat
            if current_time_diff < 60:
                print(f"  - Result: 1.0 (terlalu cepat < 1 menit)")
                return (1.0, {
                    'last_login': last_login_time.isoformat(),
                    'current_time': current_time.isoformat(),
                    'current_diff_seconds': current_time_diff,
                    'ema_seconds': None,
                    'std_dev_seconds': None,
                    'z_score': None,
                    'similarity': 0.0,
                    'interval_mode': 'too_fast',
                    'anomaly': 1.0
                }) if return_debug else 1.0
            
            # PERBAIKAN: Sesuai paper - threshold 2 jam (7200 detik)
            if current_time_diff > 7200:  # > 2 jam = normal (sesuai paper)
                print(f"  - Result: 0.0 (normal > 2 jam)")
                return (0.0, {
                    'last_login': last_login_time.isoformat(),
                    'current_time': current_time.isoformat(),
                    'current_diff_seconds': current_time_diff,
                    'ema_seconds': None,
                    'std_dev_seconds': None,
                    'z_score': None,
                    'similarity': 1.0,
                    'interval_mode': 'paper_2hour_threshold',
                    'anomaly': 0.0
                }) if return_debug else 0.0
            
            # Jika hanya ada 1 login sebelumnya, gunakan fungsi linear bertingkat
            if len(login_records) < 2:
                # Sesuai paper - interval berdasarkan threshold 2 jam
                # Format: (batas_bawah_interval, batas_atas_interval, skor_anomali)
                intervals = [
                    (60, 300, 0.8),       # 1-5 menit: anomali tinggi
                    (300, 1800, 0.6),     # 5-30 menit: anomali sedang-tinggi  
                    (1800, 3600, 0.4),    # 30-60 menit: anomali sedang
                    (3600, 7200, 0.2),    # 1-2 jam: anomali rendah (sesuai paper)
                    # > 7200 = normal (sudah dihandle di atas)
                ]
                
                # Cari interval yang sesuai
                for low, high, score in intervals:
                    if low <= current_time_diff < high:
                        print(f"  - Result: {score} (interval {low/60:.1f}m-{high/60:.1f}m)")
                        if return_debug:
                            return score, {
                                'last_login': last_login_time.isoformat(),
                                'current_time': current_time.isoformat(),
                                'current_diff_seconds': current_time_diff,
                                'ema_seconds': None,
                                'std_dev_seconds': None,
                                'z_score': None,
                                'similarity': None,
                                'interval_mode': f'paper_interval_{int(low)}_{int(high)}',
                                'anomaly': score
                            }
                        return score
                        
                # Fallback jika tidak ada interval yang cocok
                print(f"  - Result: 0.1 (fallback - dalam range 2 jam)")
                return (0.1, {
                    'last_login': last_login_time.isoformat(),
                    'current_time': current_time.isoformat(),
                    'current_diff_seconds': current_time_diff,
                    'ema_seconds': None,
                    'std_dev_seconds': None,
                    'z_score': None,
                    'similarity': None,
                    'interval_mode': 'paper_fallback',
                    'anomaly': 0.1
                }) if return_debug else 0.1
            
            # Hitung time between logins historis
            time_diffs = []
            for i in range(len(login_records) - 1):
                current_time_obj = login_records[i]['login_timestamp']
                prev_time_obj = login_records[i+1]['login_timestamp']
                
                # PERBAIKAN: Pastikan timestamps memiliki timezone yang sama
                if not current_time_obj.tzinfo:
                    current_time_obj = jakarta_tz.localize(current_time_obj)
                if not prev_time_obj.tzinfo:
                    prev_time_obj = jakarta_tz.localize(prev_time_obj)
                    
                time_diff = (current_time_obj - prev_time_obj).total_seconds()
                time_diffs.append(time_diff)
            
            if not time_diffs:
                return (0.0, {
                    'last_login': last_login_time.isoformat(),
                    'current_time': current_time.isoformat(),
                    'current_diff_seconds': current_time_diff,
                    'ema_seconds': None,
                    'std_dev_seconds': None,
                    'z_score': None,
                    'similarity': None,
                    'interval_mode': 'no_history_diffs',
                    'anomaly': 0.0
                }) if return_debug else 0.0
            
            # Hitung EMA dan std_dev untuk time between logins
            ema_time = time_diffs[0]
            std_dev_time = 3600.0  # Ubah dari 1.0 detik menjadi 1 jam (3600 detik)
            alpha = 0.3  # Ubah dari 0.1 menjadi 0.3 untuk adaptasi lebih cepat
            
            for time_diff in time_diffs[1:]:
                # Update EMA
                ema_time = alpha * time_diff + (1 - alpha) * ema_time
                
                # Update std_dev
                squared_diff = (time_diff - ema_time) ** 2
                std_dev_time = np.sqrt(alpha * squared_diff + (1 - alpha) * (std_dev_time ** 2))
            
            # Pastikan std_dev tidak terlalu kecil
            std_dev_time = max(std_dev_time, 1800.0)  # Minimal 30 menit
            
            # PERBAIKAN: Deteksi login yang terlalu cepat (tambahan)
            if current_time_diff < 60:
                print(f"  - Result: 1.0 (terlalu cepat < 1 menit)")
                return (1.0, {
                    'last_login': last_login_time.isoformat(),
                    'current_time': current_time.isoformat(),
                    'current_diff_seconds': current_time_diff,
                    'ema_seconds': ema_time,
                    'std_dev_seconds': std_dev_time,
                    'z_score': None,
                    'similarity': 0.0,
                    'interval_mode': 'too_fast',
                    'anomaly': 1.0
                }) if return_debug else 1.0
            
            # Hitung similaritas menggunakan persamaan Gaussian
            if std_dev_time > 0:
                # Clip z-score untuk mengurangi sensitivitas
                z_score = (current_time_diff - ema_time) / std_dev_time
                z_score = max(-3.0, min(3.0, z_score))  # Clip ke range [-3, 3]
                
                similarity = np.exp(-0.5 * (z_score ** 2))
            else:
                similarity = 1.0 if current_time_diff == ema_time else 0.0
            
            # Hitung anomali dan terapkan skala non-linear
            anomaly = 1.0 - similarity
            
            # Skala non-linear untuk mengurangi false positives
            if anomaly < 0.3:
                anomaly = anomaly * 0.5  # Kurangi anomali rendah
            elif anomaly > 0.7:
                anomaly = min(1.0, anomaly * 1.2)  # Tingkatkan anomali tinggi
            
            print(f"  - Result: {anomaly:.4f} (gaussian)")
            if return_debug:
                similarity = 1.0 - (anomaly if anomaly <= 1.0 else 1.0)
                return anomaly, {
                    'last_login': last_login_time.isoformat(),
                    'current_time': current_time.isoformat(),
                    'current_diff_seconds': current_time_diff,
                    'ema_seconds': ema_time,
                    'std_dev_seconds': std_dev_time,
                    'z_score': z_score,
                    'similarity': similarity,
                    'interval_mode': 'gaussian',
                    'anomaly': anomaly
                }
            return anomaly
            
        except Exception as e:
            print(f"❌ Error TimeBetweenLogins: {str(e)}")
            import traceback
            traceback.print_exc()
            return (0.0, {
                'last_login': None,
                'current_time': current_time.isoformat(),
                'current_diff_seconds': None,
                'ema_seconds': None,
                'std_dev_seconds': None,
                'z_score': None,
                'similarity': None,
                'interval_mode': 'error',
                'anomaly': 0.0
            }) if return_debug else 0.0
        finally:
            cursor.close()
            conn.close()
    
    def _calculate_daily_login_count_universal(self, user_id, current_time, return_debug: bool = False):
        """Menghitung daily login count anomaly berdasarkan rumus universal"""
        conn = get_db_connection()
        conn.select_db(app_config.DB_NAME)
        cursor = conn.cursor()
        
        try:
            # PERBAIKAN: Pastikan current_time memiliki timezone WIB
            current_time = self.ensure_timezone(current_time)
            
            # PERBAIKAN: Query database dengan timezone yang konsisten
            cursor.execute("""
                SELECT 
                    DATE(login_timestamp) as login_date,
                    COUNT(*) as login_count
                FROM login_history 
                WHERE user_id = %s AND success = 1 
                AND login_timestamp >= DATE_SUB(%s, INTERVAL 30 DAY)
                AND login_timestamp < %s
                GROUP BY DATE(login_timestamp)
                ORDER BY login_date ASC
            """, (user_id, current_time, current_time))
            
            login_records = cursor.fetchall()
            
            if not login_records:
                return (0.0, {
                    'today_count': 0,
                    'historical_counts_filtered': [],
                    'ema': None,
                    'std_dev': None,
                    'z_score': None,
                    'similarity': None,
                    'anomaly': 0.0,
                    'special_case': 'no_history'
                }) if return_debug else 0.0
            
            # Hitung daily login count untuk setiap hari dari hasil GROUP BY
            daily_counts = {}
            for record in login_records:
                date_str = record['login_date'].strftime('%Y-%m-%d')
                daily_counts[date_str] = record['login_count']
            
            if not daily_counts:
                return (0.0, {
                    'today_count': 0,
                    'historical_counts_filtered': [],
                    'ema': None,
                    'std_dev': None,
                    'z_score': None,
                    'similarity': None,
                    'anomaly': 0.0,
                    'special_case': 'no_daily_counts'
                }) if return_debug else 0.0
            
            # PERBAIKAN: Hitung daily login count untuk hari ini dengan timezone yang benar
            today = current_time.date().strftime('%Y-%m-%d')
            
            # Hitung login hari ini secara terpisah untuk akurasi
            cursor.execute("""
                SELECT COUNT(*) as today_count
                FROM login_history 
                WHERE user_id = %s AND success = 1 
                AND DATE(login_timestamp) = DATE(%s)
                AND login_timestamp < %s
            """, (user_id, current_time, current_time))
            
            today_result = cursor.fetchone()
            today_count = today_result['today_count'] if today_result else 0
            
            # Filter outlier sebelum menghitung EMA dan std_dev
            daily_count_values = list(daily_counts.values())
            filtered_counts = [count for count in daily_count_values if count <= 5]  # Maksimal 5 login per hari
            
            # Jika setelah filtering data terlalu sedikit, gunakan nilai default yang lebih toleran
            if len(filtered_counts) < 2:
                if today_count == 0:
                    return (0.0, {
                        'today_count': today_count,
                        'historical_counts_filtered': filtered_counts,
                        'ema': None,
                        'std_dev': None,
                        'z_score': None,
                        'similarity': 1.0,
                        'anomaly': 0.0,
                        'special_case': 'first_login_of_day'
                    }) if return_debug else 0.0
                elif today_count > 5:
                    return (1.0, {
                        'today_count': today_count,
                        'historical_counts_filtered': filtered_counts,
                        'ema': None,
                        'std_dev': None,
                        'z_score': None,
                        'similarity': 0.0,
                        'anomaly': 1.0,
                        'special_case': 'too_many_logins'
                    }) if return_debug else 1.0
                else:
                    return (0.3, {
                        'today_count': today_count,
                        'historical_counts_filtered': filtered_counts,
                        'ema': None,
                        'std_dev': None,
                        'z_score': None,
                        'similarity': None,
                        'anomaly': 0.3,
                        'special_case': 'insufficient_data'
                    }) if return_debug else 0.3
            
            # Hitung EMA dan std_dev untuk daily login count menggunakan data yang sudah difilter
            ema_count = filtered_counts[0]
            std_dev_count = 1.0
            alpha = 0.1
            
            for count in filtered_counts[1:]:
                # Update EMA
                ema_count = alpha * count + (1 - alpha) * ema_count
                
                # Update std_dev
                squared_diff = (count - ema_count) ** 2
                std_dev_count = np.sqrt(alpha * squared_diff + (1 - alpha) * (std_dev_count ** 2))
            
            # Pastikan std_dev tidak terlalu kecil
            std_dev_count = max(std_dev_count, 1.0)
            
            # Special case: Login pertama hari ini (today_count = 0) = normal
            if today_count == 0:
                similarity = 1.0
                anomaly = 0.0
            else:
                # Hitung similaritas menggunakan persamaan Gaussian
                if std_dev_count > 0:
                    # Clip z-score untuk mengurangi sensitivitas
                    z_score = (today_count - ema_count) / std_dev_count
                    z_score = max(-3.0, min(3.0, z_score))  # Clip ke range [-3, 3]
                    
                    similarity = np.exp(-0.5 * (z_score ** 2))
                else:
                    similarity = 1.0 if today_count == ema_count else 0.0
                
                # Hitung anomali dan terapkan skala non-linear
                anomaly = 1.0 - similarity
                
                # Skala non-linear untuk mengurangi false positives
                if anomaly < 0.3:
                    anomaly = anomaly * 0.5  # Kurangi anomali rendah
                elif anomaly > 0.7:
                    anomaly = min(1.0, anomaly * 1.2)  # Tingkatkan anomali tinggi
            
            if return_debug:
                debug_info = {
                    'today_count': today_count,
                    'historical_counts_filtered': filtered_counts,
                    'ema': ema_count,
                    'std_dev': std_dev_count,
                    'similarity': similarity,
                    'anomaly': anomaly
                }
                
                # Tambahkan informasi khusus untuk special case
                if today_count == 0:
                    debug_info['special_case'] = 'first_login_of_day'
                    debug_info['z_score'] = None
                else:
                    debug_info['z_score'] = z_score
                    debug_info['special_case'] = 'normal_calculation'
                
                return anomaly, debug_info
            return anomaly
            
        except Exception as e:
            print(f"❌ Error calculating universal daily login count anomaly: {str(e)}")
            import traceback
            traceback.print_exc()
            return 0.0
        finally:
            cursor.close()
            conn.close()

    def _write_feature_debug_file(self, payload: dict):
        """Menyimpan payload debug fitur ke folder debug/ dalam format JSON."""
        try:
            os.makedirs('debug', exist_ok=True)
            username = payload.get('meta', {}).get('username') or 'unknown'
            ts = payload.get('meta', {}).get('generated_at') or datetime.now(jakarta_tz).strftime('%Y-%m-%d %H:%M:%S WIB')
            # Format nama file: feature_debug_<username>_<YYYYMMDD_HHMMSS>_<uuid>.json
            try:
                dt = datetime.strptime(ts.replace(' WIB', ''), '%Y-%m-%d %H:%M:%S')
            except Exception:
                dt = datetime.now(jakarta_tz)
            filename = f"feature_debug_{username}_{dt.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}.json"
            filepath = os.path.join('debug', filename)
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
            print(f"📝 Feature debug disimpan: {filepath}")
        except Exception as e:
            print(f"⚠️ Gagal menyimpan feature debug: {str(e)}")

    def predict_risk(self, anomaly_features):
        """Prediksi risiko dengan hybrid approach (IF + Weighted Rule)"""
        
        # Check apakah weighted rule system diaktifkan
        use_weighted_rule = getattr(app_config, 'USE_WEIGHTED_RULE', True)
        
        if not use_weighted_rule:
            # MODE TESTING: Hanya menggunakan IF_score
            print("🔧 MODE TESTING: Menggunakan IF_score saja (Feature weights dinonaktifkan)")
            
            # Hapus parameter ekstraksi dari perhitungan
            features_for_calculation = {k: v for k, v in anomaly_features.items() if not k.startswith('_')}
            
            # Hitung Isolation Forest score menggunakan decision function
            if_score = self.calculate_if_score(features_for_calculation)
            
            # Combined score = IF_score (tanpa rule_score)
            combined_score = if_score
            
            # Tentukan risk level berdasarkan IF_score saja
            risk_level = self.determine_risk_level(combined_score)
            
            return {
                'if_score': if_score,
                'rule_score': 0.0,  # Rule score diset 0 karena dinonaktifkan
                'combined_score': combined_score,
                'risk_level': risk_level
            }
        
        # Hapus parameter ekstraksi dari perhitungan
        features_for_calculation = {k: v for k, v in anomaly_features.items() if not k.startswith('_')}
        
        # 1. Hitung Isolation Forest score menggunakan decision function
        if_score = self.calculate_if_score(features_for_calculation)
        
        # 2. Hitung Rule Weighted Score
        rule_score = calculate_rule_weighted_score(features_for_calculation)
        
        # 3. Hitung Hybrid Score
        alpha = getattr(app_config, 'WEIGHTED_RULE_ALPHA', 0.5)
        combined_score = calculate_hybrid_score(if_score, rule_score, alpha)
        
        # 4. Tentukan risk level berdasarkan combined score
        risk_level = determine_risk_level_hybrid(combined_score, self.thresholds)
        
        return {
            'if_score': if_score,
            'rule_score': rule_score,
            'combined_score': combined_score,
            'risk_level': risk_level
        }
    
    def calculate_if_score(self, anomaly_features):
        """Menghitung Isolation Forest score menggunakan decision function"""
        try:
            if self.isolation_model is None:
                # Fallback ke rata-rata jika model tidak tersedia
                values = list(anomaly_features.values())
                return sum(values) / len(values) if values else 0.0
            
            # Siapkan data model (pastikan urutan fitur tepat)
            feature_values = [
                anomaly_features.get(feature, 0.0) for feature in self.model_features
            ]
            X = np.array([feature_values])
            
            # Ambil skor decision_function, negasikan seperti training
            raw_if_score = -self.isolation_model.decision_function(X)[0]
            
            # Normalisasi menggunakan score_min dan score_max dari training
            normalized_score = (raw_if_score - self.score_min) / (self.score_max - self.score_min)
            
            # Clip ke [0,1]
            normalized_score = np.clip(normalized_score, 0.0, 1.0)
            
            return normalized_score
            
        except Exception as e:
            print(f"❌ Error calculating IF score: {str(e)}")
            # Fallback ke rata-rata
            values = list(anomaly_features.values())
            return sum(values) / len(values) if values else 0.0
    
    def predict_risk_original(self, anomaly_features):
        """Original predict_risk method untuk backward compatibility"""
        
        # Hapus parameter ekstraksi dari perhitungan
        features_for_calculation = {k: v for k, v in anomaly_features.items() if not k.startswith('_')}
        
        # Hitung mean anomaly score (rata-rata dari semua fitur)
        total_score = sum(features_for_calculation.values())
        num_features = len(features_for_calculation)
        
        if num_features == 0:
            avg_score = 0.0
        else:
            avg_score = total_score / num_features
        
        # Pastikan score dalam rentang [0, 1]
        risk_score = max(0.0, min(1.0, avg_score))
        
        # Tentukan risk level berdasarkan threshold
        risk_level = self.determine_risk_level(risk_score)
        
        return {
            'if_score': risk_score,
            'rule_score': risk_score,
            'combined_score': risk_score,
            'risk_level': risk_level
        }
    
    def determine_risk_level(self, score: float) -> int:
        """Menentukan level risiko berdasarkan score"""
        lower_threshold = self.thresholds.get('lower_threshold', 0.2595)
        upper_threshold = self.thresholds.get('upper_threshold', 0.5750)
        
        if score <= lower_threshold:
            return 0  # Rendah
        elif score <= upper_threshold:
            return 1  # Sedang
        else:
            return 2  # Tinggi
    
    def get_feature_details(self, anomaly_features, risk_score, risk_level):
        """Mendapatkan detail fitur untuk transparansi"""
        feature_details = []
        
        feature_descriptions = {
            'OS Name_anomaly': 'Konsistensi Sistem Operasi',
            'Browser Name_anomaly': 'Konsistensi Browser',
            'Device Type_anomaly': 'Konsistensi Jenis Perangkat',
            'TimeOfHour_anomaly': 'Pola Waktu Login',
            'DailyLoginCount_anomaly': 'Frekuensi Login Harian',
            'TimeBetweenLogins_anomaly': 'Interval Antar Login',
            'FailedLogin_combined_anomaly': 'Riwayat Login Gagal',
            'Geolocation_Anomaly': 'Konsistensi Lokasi'
        }
        
        # Filter fitur yang tidak dimulai dengan underscore
        clean_features = {k: v for k, v in anomaly_features.items() if not k.startswith('_')}
        
        for feature, score in clean_features.items():
            description = feature_descriptions.get(feature, feature)
            
            # Tentukan warna berdasarkan score
            if score <= 0.2:
                color = 'success'
                category = 'Rendah'
            elif score <= 0.5:
                color = 'warning'
                category = 'Sedang'
            else:
                color = 'danger'
                category = 'Tinggi'
            
            feature_details.append({
                'name': feature,  # Gunakan nama asli fitur (OS Name_anomaly, dll)
                'feature': feature,
                'description': description,  # Tetap gunakan deskripsi untuk tampilan
                'score': round(score, 4),
                'contribution': round(score * 100, 2),
                'color': color,
                'category': category
            })
        
        # Sort berdasarkan score (descending)
        feature_details.sort(key=lambda x: x['score'], reverse=True)
        
        return {
            'feature_details': feature_details,
            'total_features': len(feature_details),
            'risk_score': round(risk_score, 4),
            'risk_level': risk_level
        }
    
 