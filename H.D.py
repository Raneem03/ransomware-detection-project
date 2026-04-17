import pandas as pd
import re
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib

# تحميل ملفات static و dynamic
static_df = pd.read_csv("final_combined_features.csv")

# تجهيز static: توليد SampleID من FileName
static_df['SampleID'] = static_df['FileName'].str.lower().str.replace(r'\.exe$', '', regex=True)
static_df = static_df.drop(columns=['FileName', 'SHA256', 'FilePath', 'FileType', 'CompileTime'], errors='ignore')

# قراءة dynamic من ملف .txt وتحويله إلى DataFrame
samples = []
current = {}
with open("results2.txt", "r", encoding="utf-8") as file:
    for line in file:
        line = line.strip()
        if not line or line.startswith("---"):
            continue
        match = re.match(r"^(.*?):\s*(.*)$", line)
        if match:
            key, value = match.groups()
            if key.lower() == "file" and current:
                samples.append(current)
                current = {}
            current[key] = value
if current:
    samples.append(current)

dynamic_df = pd.DataFrame(samples)

# تجهيز dynamic: توليد SampleID من اسم الملف بعد إزالة .zip
dynamic_df['SampleID'] = dynamic_df['File'].astype(str).str.lower().str.replace(r'\.zip$', '', regex=True)
dynamic_df = dynamic_df.drop(columns=['File', 'File name'], errors='ignore')

# ✅ دمج outer يشمل جميع العينات من النوعين
merged_df = pd.merge(static_df, dynamic_df, on='SampleID', how='outer')
print(f"✅ تم الدمج. عدد العينات بعد الدمج: {len(merged_df)}")

# حذف الأعمدة اللي كلها فاضية
merged_df = merged_df.dropna(axis=1, how='all')

# تعويض القيم الفارغة
merged_df = merged_df.fillna(-1)

# 🔍 إزالة العينات اللي مش مصنفة (Label = -1)
merged_df = merged_df[merged_df['Label'] != -1]

# تأكيد أن Label موجود
if 'Label' not in merged_df.columns:
    raise ValueError("❌ العمود 'Label' غير موجود بعد الدمج! تأكد من وجوده في ملف static.")

# فصل الميزات والوسم
y = merged_df['Label'].astype(int)
X = merged_df.drop(columns=['SampleID', 'Label'], errors='ignore')

# أخذ فقط الأعمدة الرقمية
X = X.select_dtypes(include=['number'])

# معالجة القيم الناقصة
imputer = SimpleImputer(strategy="mean")
X_imputed = imputer.fit_transform(X)

# تقسيم البيانات للتدريب والاختبار
X_train, X_test, y_train, y_test = train_test_split(
    X_imputed, y, test_size=0.2, random_state=42, stratify=y
)

# تدريب النموذج
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# التقييم
y_pred = model.predict(X_test)
print("\n✅ تقييم النموذج:")
print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# حفظ النموذج
joblib.dump(model, "hybrid_rf_model.pkl")
print("\n✅ تم حفظ النموذج كـ hybrid_rf_model.pkl")
