#!/usr/bin/env python3

import sys
import subprocess
import os

def display_menu():
    """نمایش منو برای انتخاب اسکریپت"""
    print("\n" + "="*50)
    print("🌐 IP Scanner - انتخاب سرویس")
    print("="*50)
    print("\n1️⃣  Cloudflare IP Scanner")
    print("   - تست IPs روی شبکه Cloudflare")
    print("   - Ping، Latency، Upload/Download Speed")
    print("\n2️⃣  Fastly IP Scanner")
    print("   - تست IPs روی شبکه Fastly")
    print("   - بررسی SSL/TLS و سرعت")
    print("\n0️⃣  خروج")
    print("\n" + "="*50)
    
    while True:
        choice = input("\nلطفاً انتخاب کنید (0-2): ").strip()
        if choice in ['0', '1', '2']:
            return choice
        print("❌ انتخاب نامعتبر! لطفاً دوباره سعی کنید.")

def run_cloudflare():
    """اجرای Cloudflare Scanner"""
    print("\n🔄 در حال اجرای Cloudflare Scanner...\n")
    try:
        subprocess.run([sys.executable, 'start.py'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"\n❌ خطا در اجرای Cloudflare Scanner: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n⛔ توسط کاربر متوقف شد")
        sys.exit(0)

def run_fastly():
    """اجرای Fastly Scanner"""
    print("\n🔄 در حال اجرای Fastly Scanner...\n")
    try:
        subprocess.run([sys.executable, 'fastly.py'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"\n❌ خطا در اجرای Fastly Scanner: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n⛔ توسط کاربر متوقف شد")
        sys.exit(0)

def main():
    """تابع اصلی"""
    print("\n" + "🎯 خوش آمدید!" + "\n")
    
    while True:
        choice = display_menu()
        
        if choice == '0':
            print("\n👋 خداحافظ!\n")
            sys.exit(0)
        elif choice == '1':
            run_cloudflare()
            print("\n✅ Cloudflare Scanner تکمیل شد.\n")
        elif choice == '2':
            run_fastly()
            print("\n✅ Fastly Scanner تکمیل شد.\n")
        
        # پرسش از کاربر برای ادامه یا خروج
        again = input("\nمیخواهید دوباره اجرا کنید؟ (بله/خیر): ").strip().lower()
        if again not in ['بله', 'yes', 'y', 'ب']:
            print("\n👋 خداحافظ!\n")
            break

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⛔ برنامه توسط کاربر متوقف شد.")
        sys.exit(0)
