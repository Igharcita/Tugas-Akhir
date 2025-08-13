from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from user_agents import parse
from datetime import datetime, timedelta
import json
import uuid
import os
from functools import wraps
import pytz

# Import modul lokal
from database import get_db_connection, save_login_history, save_login_data
from models import RBAModel
from utils import create_login_info, get_risk_info
from otp_service import OTPService
from email_service import EmailService
from cleanup_scheduler import cleanup_scheduler
import app_config

# Set timezone untuk aplikasi
jakarta_tz = pytz.timezone('Asia/Jakarta')

app = Flask(__name__)
app.secret_key = app_config.SECRET_KEY
app.permanent_session_lifetime = app_config.SESSION_LIFETIME

# Inisialisasi model RBA dan services
rba_model = RBAModel()
otp_service = OTPService()
email_service = EmailService()

# Mulai cleanup scheduler untuk OTP
cleanup_scheduler.start()

# Fungsi helper untuk memastikan waktu memiliki timezone
def ensure_timezone(dt):
    if not dt.tzinfo:
        return jakarta_tz.localize(dt)
    return dt

# Middleware untuk mengecek verifikasi
def require_verification(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Anda harus login terlebih dahulu!', 'warning')
            return redirect(url_for('login_page'))
        
        if session.get('needs_verification'):
            flash('Anda harus menyelesaikan verifikasi tambahan!', 'warning')
            return redirect(url_for('verify'))
            
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    
    username = request.form.get('username')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    email = request.form.get('email')
    security_question = request.form.get('security_question')
    security_answer = request.form.get('security_answer')
    
    # Validasi input
    if not all([username, password, confirm_password, email, security_question, security_answer]):
        flash('Semua field harus diisi', 'danger')
        return render_template('register.html')
    
    if password != confirm_password:
        flash('Password tidak cocok', 'danger')
        return render_template('register.html')
        
    conn = get_db_connection()
    conn.select_db(app_config.DB_NAME)
    cursor = conn.cursor()
    
    try:
        # Cek username sudah ada
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        if cursor.fetchone():
            flash('Username sudah digunakan', 'danger')
            return render_template('register.html')
        
        # Simpan user baru
        hashed_password = generate_password_hash(password)
        cursor.execute(
            """INSERT INTO users (username, password, email, security_question, security_answer) 
               VALUES (%s, %s, %s, %s, %s)""",
            (username, hashed_password, email, security_question, security_answer.lower())
        )
        conn.commit()
        
        # Dapatkan ID user baru dan inisialisasi user_behavior
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        user_data = cursor.fetchone()
        user_id = user_data['id']
        
        cursor.execute("INSERT INTO user_behavior (user_id) VALUES (%s)", (user_id,))
        conn.commit()
        
        flash('Registrasi berhasil! Silakan login', 'success')
        return redirect(url_for('login_page'))

    except Exception as e:
        flash(f'Terjadi kesalahan: {str(e)}', 'danger')
    finally:
        cursor.close()
        conn.close()
    
    return render_template('register.html')

@app.route('/login', methods=['GET'])
def login_page():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not username or not password:
        flash('Username dan password harus diisi', 'danger')
        return redirect(url_for('login_page'))
    
    conn = get_db_connection()
    conn.select_db(app_config.DB_NAME)
    cursor = conn.cursor()
    
    # Cek kredensial
    cursor.execute("SELECT id, username, password, email FROM users WHERE username = %s", (username,))
    user_data = cursor.fetchone()
    
    if user_data and check_password_hash(user_data['password'], password):
        user_id = user_data['id']
        
        # Generate session_id untuk OTP
        session_id = str(uuid.uuid4())
        session['session_id'] = session_id
        
        # Buat informasi login
        login_info = create_login_info(username, request)

        # Hitung fitur anomali
        anomaly_features = rba_model.calculate_anomaly_features(login_info, user_id)

        # Prediksi risiko menggunakan weighted rule system
        # MODE TESTING: Feature weights dinonaktifkan, hanya menggunakan IF_score
        prediction_result = rba_model.predict_risk(anomaly_features)
        risk_score = prediction_result['combined_score']  # Sekarang = IF_score saja
        risk_level = prediction_result['risk_level']
        
        # Dapatkan detail fitur untuk transparansi
        feature_analysis = rba_model.get_feature_details(anomaly_features, risk_score, risk_level)

        # Ekstrak informasi geolokasi dari parameter
        extracted_params = anomaly_features.get('_extracted_params', {})
        current_geo = extracted_params.get('current_geo', {})
        asn = current_geo.get('asn', 0)
        region = current_geo.get('region', 'Unknown')

        # Simpan ke database dengan informasi geolokasi dan hybrid scores
        save_login_history(
            user_id, request.remote_addr, login_info['user_agent'],
            login_info['browser'], login_info['platform'], login_info['device_type'],
            True, risk_score, risk_level, asn, region,
            prediction_result['if_score'],
            prediction_result['rule_score'], 
            prediction_result['combined_score']
        )

        # Simpan data login ke file
        login_info.update({
            'risk_score': risk_score,
            'risk_level': risk_level,
            'if_score': prediction_result['if_score'],
            'rule_score': prediction_result['rule_score'],
            'combined_score': prediction_result['combined_score'],
            'anomaly_features': {k: v for k, v in anomaly_features.items() if not k.startswith('_')},
            'geolocation_info': current_geo
        })
        save_login_data(login_info)

        # Simpan detail fitur untuk transparansi
        current_time = ensure_timezone(datetime.now())
        session['last_feature_details'] = {
            'username': username,
            'login_time': current_time.strftime('%Y-%m-%d %H:%M:%S WIB'),
            'ip_address': request.remote_addr,
            'browser': login_info['browser'],
            'platform': login_info['platform'],
            'risk_score': risk_score,
            'risk_level': risk_level,
            'feature_details': feature_analysis['feature_details'],
            'extracted_params': extracted_params,
            'anomaly_features': {k: v for k, v in anomaly_features.items() if not k.startswith('_')}
        }

        # Set session
        session.permanent = True
        session['user_id'] = user_id
        session['username'] = username
        session['risk_level'] = risk_level
        session['risk_score'] = round(risk_score, 4)

        risk_info = get_risk_info(risk_level)
        session['risk_color'] = risk_info['color']
        session['risk_label'] = risk_info['label']

        # Redirect berdasarkan level risiko
        if risk_level == 1:  # Medium Risk
            session['needs_verification'] = True
            session['verification_type'] = 'otp'
            if user_data['email']:
                otp_sent, otp_message = otp_service.send_otp_email(
                    user_id=user_id,
                    username=username,
                    email=user_data['email'],
                    ip_address=request.remote_addr,
                    session_id=session_id
                )
                if not otp_sent:
                    flash(f'Gagal mengirim OTP: {otp_message}', 'danger')
            return redirect(url_for('verify'))
        elif risk_level == 2:  # High Risk
            session['needs_verification'] = True
            session['verification_type'] = 'otp_kba'
            if user_data['email']:
                otp_sent, otp_message = otp_service.send_otp_email(
                    user_id=user_id,
                    username=username,
                    email=user_data['email'],
                    ip_address=request.remote_addr,
                    session_id=session_id
                )
                if not otp_sent:
                    flash(f'Gagal mengirim OTP: {otp_message}', 'danger')
            return redirect(url_for('verify_otp'))
        else:  # Low Risk
            session['needs_verification'] = False
            flash('Login berhasil!', 'success')
            return redirect(url_for('dashboard'))
    else:
        # Jika login gagal, tetap catat ke login_history
        user_id = user_data['id'] if user_data else None
        if user_id:
            login_info = create_login_info(username, request)
            # Catat login gagal dengan skor risiko 0
            save_login_history(
                user_id, request.remote_addr, login_info['user_agent'],
                login_info['browser'], login_info['platform'], login_info['device_type'],
                False, 0.0, 2, 0, 'Unknown', 0.0, 0.0, 0.0  # risk_level=2 (tinggi) untuk login gagal
            )
        flash('Username atau password salah', 'danger')
        return redirect(url_for('login_page'))

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    # Untuk medium risk (OTP saja)
    if 'needs_verification' not in session or session.get('verification_type') != 'otp':
        return redirect(url_for('login_page'))
    if request.method == 'POST':
        verification_code = request.form.get('verification_code')
        user_id = session.get('user_id')
        session_id = session.get('session_id')
        if not user_id or not session_id:
            flash('Session tidak valid. Silakan login ulang.', 'danger')
            return redirect(url_for('login_page'))
        otp_valid, otp_message = otp_service.verify_otp(user_id, verification_code, session_id)
        if not otp_valid:
            flash(f'Kode OTP salah! {otp_message}', 'danger')
            return render_template('verify.html', verification_type='otp')
        session.pop('needs_verification', None)
        session.pop('verification_type', None)
        flash('Verifikasi berhasil! Selamat datang.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('verify.html', verification_type='otp')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    # Untuk high risk tahap 1: OTP
    if 'needs_verification' not in session or session.get('verification_type') != 'otp_kba':
        return redirect(url_for('login_page'))
    if request.method == 'POST':
        verification_code = request.form.get('verification_code')
        user_id = session.get('user_id')
        session_id = session.get('session_id')
        if not user_id or not session_id:
            flash('Session tidak valid. Silakan login ulang.', 'danger')
            return redirect(url_for('login_page'))
        otp_valid, otp_message = otp_service.verify_otp(user_id, verification_code, session_id)
        if not otp_valid:
            flash(f'Kode OTP salah! {otp_message}', 'danger')
            return render_template('verify.html', verification_type='otp_kba', show_otp=True)
        # Jika OTP valid, lanjut ke KBA
        session['otp_verified'] = True
        return redirect(url_for('verify_kba'))
    return render_template('verify.html', verification_type='otp_kba', show_otp=True)

@app.route('/verify-kba', methods=['GET', 'POST'])
def verify_kba():
    # Untuk high risk tahap 2: KBA
    if 'needs_verification' not in session or session.get('verification_type') != 'otp_kba' or 'otp_verified' not in session:
        return redirect(url_for('login_page'))
    # Ambil security question
    conn = get_db_connection()
    conn.select_db(app_config.DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT security_question, security_answer FROM users WHERE id = %s", (session.get('user_id'),))
    user_data = cursor.fetchone()
    cursor.close()
    conn.close()
    user_security_question = user_data['security_question'] if user_data else None
    if request.method == 'POST':
        security_answer = request.form.get('security_answer', '').lower().strip()
        if not user_data or user_data['security_answer'].lower().strip() != security_answer:
            flash('Jawaban pertanyaan keamanan salah!', 'danger')
            return render_template('verify.html', verification_type='otp_kba', show_kba=True, user_security_question=user_security_question)
        # Jika KBA valid
        session.pop('needs_verification', None)
        session.pop('verification_type', None)
        session.pop('otp_verified', None)
        flash('Verifikasi berhasil! Selamat datang.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('verify.html', verification_type='otp_kba', show_kba=True, user_security_question=user_security_question)

@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    """
    Mengirim ulang kode OTP
    """
    if 'needs_verification' not in session:
        return jsonify({'success': False, 'message': 'Session tidak valid'})
    
    user_id = session.get('user_id')
    username = session.get('username')
    session_id = session.get('session_id')
    
    if not user_id or not username or not session_id:
        return jsonify({'success': False, 'message': 'Session tidak valid'})
    
    # Ambil email user
    conn = get_db_connection()
    conn.select_db(app_config.DB_NAME)
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT email FROM users WHERE id = %s", (user_id,))
        user_data = cursor.fetchone()
        
        if not user_data or not user_data['email']:
            return jsonify({'success': False, 'message': 'Email tidak ditemukan'})
        
        user_email = user_data['email']
        
        # Kirim OTP baru
        otp_sent, otp_message = otp_service.send_otp_email(
            user_id=user_id,
            username=username,
            email=user_email,
            ip_address=request.remote_addr,
            session_id=session_id
        )
        
        if otp_sent:
            return jsonify({'success': True, 'message': otp_message})
        else:
            return jsonify({'success': False, 'message': otp_message})
            
    except Exception as e:
        return jsonify({'success': False, 'message': 'Error sistem'})
    finally:
        cursor.close()
        conn.close()

@app.route('/otp-status')
def otp_status():
    """
    Mendapatkan status OTP untuk user
    """
    if 'needs_verification' not in session:
        return jsonify({'success': False, 'message': 'Session tidak valid'})
    
    user_id = session.get('user_id')
    session_id = session.get('session_id')
    
    if not user_id or not session_id:
        return jsonify({'success': False, 'message': 'Session tidak valid'})
    
    status = otp_service.get_otp_status(user_id, session_id)
    
    if status:
        return jsonify({'success': True, 'status': status})
    else:
        return jsonify({'success': False, 'message': 'OTP tidak ditemukan'})

@app.route('/dashboard')
@require_verification
def dashboard():
    # Ambil riwayat login terbaru
    conn = get_db_connection()
    conn.select_db(app_config.DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT login_timestamp, ip_address, browser, os_name, device_type, risk_level 
        FROM login_history 
        WHERE user_id = %s AND success = 1
        ORDER BY login_timestamp DESC 
        LIMIT 5
    """, (session['user_id'],))
    
    login_history = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    # Parse user agent untuk info browser dan OS saat ini
    user_agent = parse(request.headers.get('User-Agent', ''))
    
    return render_template(
        'dashboard.html', 
        username=session['username'],
        risk_level=session['risk_level'],
        risk_color=session['risk_color'],
        risk_label=session['risk_label'],
        risk_score=session['risk_score'],
        login_history=login_history,
        browser_info=user_agent.browser.family,
        os_info=user_agent.os.family
    )

@app.route('/profile')
@require_verification
def profile():
    conn = get_db_connection()
    conn.select_db(app_config.DB_NAME)
    cursor = conn.cursor()
    
    try:
        # Ambil data profil user dengan timezone yang benar
        cursor.execute("""
            SELECT u.username, u.email, 
                   CONVERT_TZ(u.created_at, '+00:00', '+07:00') as created_at
            FROM users u
            WHERE u.id = %s
        """, (session['user_id'],))
        user_profile = cursor.fetchone()
        
        # Ambil statistik login real-time dari login_history
        cursor.execute("""
            SELECT 
                COUNT(*) as total_logins,
                SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed_logins,
                AVG(risk_score) as avg_risk,
                CONVERT_TZ(MAX(login_timestamp), '+00:00', '+07:00') as last_login
            FROM login_history 
            WHERE user_id = %s
        """, (session['user_id'],))
        login_stats = cursor.fetchone()
        
        # Pastikan nilai default jika None
        if login_stats['total_logins'] is None:
            login_stats['total_logins'] = 0
        if login_stats['failed_logins'] is None:
            login_stats['failed_logins'] = 0
        if login_stats['avg_risk'] is None:
            login_stats['avg_risk'] = 0.0
        
        return render_template('profile.html', profile=user_profile, stats=login_stats)
        
    except Exception as e:
        flash(f'Terjadi kesalahan: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))
    finally:
        cursor.close()
        conn.close()



@app.route('/feature-details')
@require_verification
def feature_details():
    if 'last_feature_details' not in session:
        flash('Data analisis fitur tidak tersedia', 'warning')
        return redirect(url_for('dashboard'))
    
    # Pastikan waktu dalam timezone WIB
    details = session['last_feature_details']
    if 'login_time' in details:
        try:
            # Parse waktu dan konversi ke WIB jika perlu
            login_time = datetime.strptime(details['login_time'], '%Y-%m-%d %H:%M:%S WIB')
            if not login_time.tzinfo:
                login_time = jakarta_tz.localize(login_time)
            details['login_time'] = login_time.strftime('%d/%m/%Y %H:%M:%S WIB')
        except Exception as e:
            print(f"Error konversi waktu: {str(e)}")
    
    return render_template('feature_details.html', **details)



@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    
    # Invalidasi OTP yang aktif untuk keamanan
    if user_id:
        otp_service.invalidate_user_otps(user_id)
    
    session.clear()
    flash('Anda telah logout!', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True) 
