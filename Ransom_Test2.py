import os
import time
import joblib
import shutil
from extract_features import extract_static_features
import psutil

# 📁 مسار المجلد المشترك
WATCH_FOLDER = r"C:\Users\Raneem\OneDrive - Balqa Applied University\Desktop\VM_Share"
PROCESSED_FOLDER = os.path.join(WATCH_FOLDER, "processed")
MODEL_PATH = "hybrid_rf_model.pkl"

# تحميل النموذج المدرب
model = joblib.load(MODEL_PATH)

# مجلد لنقل الملفات المعالجة
os.makedirs(PROCESSED_FOLDER, exist_ok=True)

# ✅ الميزات المطلوبة كما تم تدريب النموذج
REQUIRED_FEATURES = [
    'FileSize', 'Entropy', 'NumberOfSections', 'NumberOfImports', 'HasResources',
    'HasSignature', 'SuspiciousAPICalls', 'TotalEntropy', 'SuspiciousStringCount', 'IsPacked',
    'Timestamp', 'Machine', 'SizeOfOptionalHeader', 'Characteristics', 'MajorLinkerVersion',
    'MinorLinkerVersion', 'SizeOfCode', 'AddressOfEntryPoint', 'BaseOfCode', 'ImageBase',
    'SectionAlignment', 'FileAlignment', 'Subsystem', 'DllCharacteristics'
]

# 🔍 تحليل ديناميكي سريع
def quick_dynamic_analysis():
    suspicious_keywords = ['cmd', 'powershell', 'vssadmin', 'taskkill']
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            name = proc.info['name'].lower()
            if any(keyword in name for keyword in suspicious_keywords):
                print(f"[!] Suspicious process detected: {name}")
                return True
        except:
            continue
    return False

# 👀 بدء المراقبة
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
            if not features:
                print("[!] Failed to extract static features.")
                continue

            # تجهيز الخصائص بالترتيب الصحيح
            try:
                ordered_values = [features.get(key, -1) for key in REQUIRED_FEATURES]
                proba = model.predict_proba([ordered_values])[0][1]
            except Exception as e:
                print(f"[!] Error in prediction: {e}")
                continue

            print(f"[i] Static Detection Confidence: {proba:.2f}")

            # اتخاذ القرار حسب الثقة
            if proba > 0.9:
                print("[🔥] Ransomware detected with high confidence!")
            elif proba < 0.1:
                print("[✓] File is likely benign.")
            elif 0.4 < proba < 0.6:
                print("[!] Confidence uncertain — running quick dynamic check...")
                time.sleep(10)
                if quick_dynamic_analysis():
                    print("[🚨] Suspicious behavior detected → Marked as Ransomware.")
                else:
                    print("[✓] No suspicious behavior found → Likely Benign.")
            else:
                print("[~] Result uncertain — manual review recommended.")

            # نقل الملف بعد التحليل
            shutil.move(file_path, os.path.join(PROCESSED_FOLDER, filename))

        already_seen = current_files
        time.sleep(5)

    except KeyboardInterrupt:
        print("\n[!] Monitoring stopped by user.")
        break
