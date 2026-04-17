import joblib
import pandas as pd

# حمّل البيانات اللي تدربت عليها
static_df = pd.read_csv("final_combined_features.csv")
static_df['SampleID'] = static_df['FileName'].str.lower().str.replace(r'\.exe$', '', regex=True)
static_df = static_df.drop(columns=['FileName', 'SHA256', 'FilePath', 'FileType', 'CompileTime'], errors='ignore')

# جهز بيانات التحليل الديناميكي
import re
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
dynamic_df['SampleID'] = dynamic_df['File'].astype(str).str.lower().str.replace(r'\.zip$', '', regex=True)
dynamic_df = dynamic_df.drop(columns=['File', 'File name'], errors='ignore')

# دمج البيانات
merged_df = pd.merge(static_df, dynamic_df, on='SampleID', how='outer')
merged_df = merged_df.dropna(axis=1, how='all')
merged_df = merged_df.fillna(-1)
merged_df = merged_df[merged_df['Label'] != -1]

# حضّر الخصائص فقط (X)
X = merged_df.drop(columns=['SampleID', 'Label'], errors='ignore')
X = X.select_dtypes(include=['number'])

# اطبع النتيجة
print("✅ عدد الخصائص التي تدرب عليها النموذج:", X.shape[1])
print("\n📌 أسماء الخصائص:")
for col in X.columns:
    print("-", col)
