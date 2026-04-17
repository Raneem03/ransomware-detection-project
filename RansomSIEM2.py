import os
import time
import joblib
import shutil
import requests
import json
import psutil
from extract_features import extract_static_features

# 🟦 مسار المجلد المشترك على جهازك
WATCH_FOLDER = r"C:\Users\Raneem\OneDrive - Balqa Applied University\Desktop\VM_Share"
PROCESSED_FOLDER = os.path.join(WATCH_FOLDER, "processed")
MODEL_PATH = "hybrid_rf_model.pkl"

# 🟩 إعدادات Splunk HEC
SPLUNK_URL = "http://127.0.0.1:8088"
SPLUNK_TOKEN = "f26c72a7-3158-46b2-b274-bf9c03a48c92"

# تحميل النموذج المدرب
model = joblib.load(MODEL_PATH)

# مجلد لنقل الملفات المعالجة
os.makedirs(PROCESSED_FOLDER, exist_ok=True)

# ✅ دالة إرسال تنبيه إلى Splunk
def send_alert_to_splunk(filename, verdict):
    payload = {
        "event": {
            "alert": "Malicious file detected!",
            "filename": filename,
            "verdict": verdict
        },
        "sourcetype": "_json"
    }

    headers = {
        "Authorization": f"Splunk {SPLUNK_TOKEN}"
    }

    try:
        response = requests.post(
            f"{SPLUNK_URL}/services/collector",
            headers=headers,
            data=json.dumps(payload),
            verify=False
        )

        if response.status_code == 200:
            print(f"[+] Alert sent to Splunk for: {filename}")
        else:
            print(f"[!] Failed to send alert to Splunk: {response.text}")

    except Exception as e:
        print(f"[!] Error sending alert to Splunk: {e}")

# 🔍 تحليل ديناميكي خفيف بمراقبة العمليات
def quick_dynamic_analysis():
    suspicious_keywords = ['cmd', 'powershell', 'vssadmin', 'taskkill']
    suspicious = False

    for proc in psutil.process_iter(['pid', 'name']):
        try:
            name = proc.info['name'].lower()
            for keyword in suspicious_keywords:
                if keyword in name:
                    suspicious = True
                    print(f"[!] Suspicious process detected: {name}")
        except:
            continue
    return suspicious

# 🕵️‍♀️ بدء مراقبة المجلد
print(f"[+] Monitoring folder: {WATCH_FOLDER}")
already_seen = set(os.listdir(WATCH_FOLDER))

while True:
    try:
        current_files = set(os.listdir(WATCH_FOLDER))
        new_files = [f for f in current_files - already_seen if f.endswith(".exe")]

        for filename in new_files:
            file_path = os.path.join(WATCH_FOLDER, filename)
            print(f"\n[+] New file detected: {filename}")

            # تحليل ثابت
            features = extract_static_features(file_path)
            if features is None:
                print("[!] Failed to extract static features.")
                continue

            # عرض الخصائص
            print("[DEBUG] Extracted features:")
            for k, v in features.items():
                print(f"{k}: {v}")

            # ✅ استخدام الخصائص العشرة المرتبة كما درّبتي النموذج
            expected_features = [
                "FileSize", "Entropy", "NumberOfSections", "NumberOfImports",
                "HasResources", "HasSignature", "SuspiciousAPICalls",
                "TotalEntropy", "SuspiciousStringCount", "IsPacked"
            ]

            feature_vector = [features.get(k, 0) for k in expected_features]

            if len(feature_vector) != 10:
                print(f"[!] Feature vector malformed: expected 10 features, got {len(feature_vector)} → Skipping file.")
                continue

            # التنبؤ
            proba = model.predict_proba([feature_vector])[0][1]
            print(f"[i] Static Detection Confidence: {proba:.2f}")

            # القرار حسب الثقة
            if proba > 0.9:
                print(" Ransomware detected with high confidence!")
                send_alert_to_splunk(filename, "malicious")

            elif proba < 0.1:
                print("[✓] File is likely benign.")

            elif 0.4 < proba < 0.6:
                print("[!] Confidence is uncertain. Please execute the file inside the VM.")
                time.sleep(10)
                if quick_dynamic_analysis():
                    print("Suspicious behavior detected → Marked as Ransomware.")
                    send_alert_to_splunk(filename, "malicious")
                else:
                    print("[✓] No suspicious behavior found → Likely Benign.")

            else:
                print("[~] Result uncertain. Manual review recommended.")

            # نقل الملف بعد التحليل
            shutil.move(file_path, os.path.join(PROCESSED_FOLDER, filename))

        already_seen = current_files
        time.sleep(5)

    except KeyboardInterrupt:
        print("\n[!] Monitoring stopped by user.")
        break
