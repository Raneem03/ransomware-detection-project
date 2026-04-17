import os
import time
import logging
import logging.handlers
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import zipfile
import shutil
from extract_features import extract_features_from_exe  # سكربتك
import joblib
import pandas as pd

WATCH_FOLDER = "incoming_files"
MODEL_PATH = "hybrid_rf_model.pkl"
SIEM_IP = "192.168.1.100"  # غيريه حسب عنوان الـ SIEM عندك

# إعداد syslog للـ SIEM
logger = logging.getLogger()
logger.setLevel(logging.INFO)
handler = logging.handlers.SysLogHandler(address=(SIEM_IP, 514))
logger.addHandler(handler)

# تحميل النموذج المدرب
model = joblib.load(MODEL_PATH)

def analyze_file(filepath):
    if filepath.endswith(".zip"):
        with zipfile.ZipFile(filepath, 'r') as zip_ref:
            zip_ref.extractall("temp_unzip/")
        for file in os.listdir("temp_unzip"):
            if file.endswith(".exe"):
                full_path = os.path.join("temp_unzip", file)
                result = predict_file(full_path)
                logger.info(f"Ransomware Detection: {file} => {result}")
        shutil.rmtree("temp_unzip")

    elif filepath.endswith(".exe"):
        result = predict_file(filepath)
        logger.info(f"Ransomware Detection: {os.path.basename(filepath)} => {result}")

def predict_file(file_path):
    features = extract_features_from_exe(file_path)  # تابعك الجاهز
    df = pd.DataFrame([features])
    prediction = model.predict(df)[0]
    return "Malicious" if prediction == 1 else "Benign"

class FolderWatcher(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        if event.src_path.endswith((".zip", ".exe")):
            time.sleep(1)  # انتظر شوي لتكمل النسخ
            analyze_file(event.src_path)

if __name__ == "__main__":
    observer = Observer()
    observer.schedule(FolderWatcher(), path=WATCH_FOLDER, recursive=False)
    observer.start()
    print(f"[+] Watching folder: {WATCH_FOLDER}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
