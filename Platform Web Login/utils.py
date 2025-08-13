import uuid
import json
import os
import pytz
from datetime import datetime
from user_agents import parse
import app_config

# Set timezone untuk Jakarta (WIB)
jakarta_tz = pytz.timezone('Asia/Jakarta')

def create_login_info(username, request):
    """Membuat informasi login dari request dengan timezone WIB"""
    user_agent_string = request.headers.get('User-Agent', '')
    user_agent = parse(user_agent_string)
    
    return {
        'login_id': str(uuid.uuid4()),
        'timestamp': datetime.now(jakarta_tz).isoformat(),
        'username': username,
        'ip_address': request.remote_addr,
        'user_agent': user_agent_string,
        'browser': user_agent.browser.family,
        'platform': user_agent.os.family,
        'device_type': 'mobile' if user_agent.is_mobile else 'desktop',
        'success': True
    }

def save_login_data(login_info):
    """Menyimpan data login ke file JSON"""
    os.makedirs(app_config.DATA_DIR, exist_ok=True)
    filename = os.path.join(app_config.DATA_DIR, f'login_{login_info["login_id"]}.json')
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(login_info, f, indent=4, ensure_ascii=False)
    except Exception as e:
        print(f"Error menyimpan file login: {str(e)}")
        # Fallback tanpa encoding khusus
        with open(filename, 'w') as f:
            json.dump(login_info, f, indent=4)

def get_risk_info(risk_level):
    """Mendapatkan informasi risiko berdasarkan level"""
    return {
        'label': app_config.RISK_LABELS.get(risk_level, 'Unknown'),
        'color': app_config.RISK_COLORS.get(risk_level, 'secondary')
    } 