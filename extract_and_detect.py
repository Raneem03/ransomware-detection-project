import pyzipper
import rarfile
import os
import joblib
import shutil
import tempfile
from static_feature_extractor import extract_static_features

model_path = "hybrid_rf_model.pkl"
model = joblib.load(model_path)

zip_path = "sample.zip"
zip_password = b'infected'
rar_password = 'infected'

temp_dir = tempfile.mkdtemp()

try:
    # فك ضغط ZIP
    with pyzipper.AESZipFile(zip_path) as zf:
        zf.extractall(temp_dir, pwd=zip_password)
        print("✅ ZIP extracted successfully!")
        print("📂 Files in extracted ZIP:", os.listdir(temp_dir))

    # البحث عن RAR داخل ZIP
    rar_files = [f for f in os.listdir(temp_dir) if f.endswith(".rar")]
    print("🧩 Found RAR files:", rar_files)

    for rar_name in rar_files:
        rar_path = os.path.join(temp_dir, rar_name)
        with rarfile.RarFile(rar_path) as rf:
            rf.extractall(temp_dir, pwd=rar_password)
            print(f"✅ RAR extracted: {rar_name}")

    # البحث عن EXE داخل المجلد المؤقت
    exe_files = [f for f in os.listdir(temp_dir) if f.endswith(".exe")]
    print("🧪 Found EXE files:", exe_files)

    for exe in exe_files:
        exe_path = os.path.join(temp_dir, exe)
        features = extract_static_features(exe_path)

        if features is None:
            print(f"⚠️ Skipped {exe} (feature extraction failed)")
            continue

        prediction = model.predict([features])[0]
        result = "🔴 Ransomware" if prediction == 1 else "🟢 Benign"
        print(f"{exe} → {result}")

except Exception as e:
    print("❌ Error:", str(e))
finally:
    shutil.rmtree(temp_dir)
