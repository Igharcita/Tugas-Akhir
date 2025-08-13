#!/usr/bin/env python3
"""
Script untuk menjalankan RBA Login System
"""

from app import app
from database import init_database

if __name__ == '__main__':
    print("🚀 Starting RBA Login System...")
    print("=" * 40)
    
    # Inisialisasi database jika belum ada
    try:
        init_database()
        print("✅ Database ready")
    except Exception as e:
        print(f"⚠️ Database warning: {str(e)}")
    
    # Jalankan aplikasi
    print("🌐 Starting Flask server...")
    print("📍 URL: http://localhost:5001")
    print("🛑 Press Ctrl+C to stop")
    print("=" * 40)
    
    app.run(host='0.0.0.0', port=5001, debug=True) 
