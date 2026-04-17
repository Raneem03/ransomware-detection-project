import pefile
import os

def extract_features_from_exe(file_path):
    try:
        pe = pefile.PE(file_path)
        
        features = {
            "Size": os.path.getsize(file_path),
            "NumberOfSections": len(pe.sections),
            "NumberOfImports": count_imports(pe),
            "EntropyMean": calc_entropy(pe),
            # أضيفي خصائص ثانية حسب نموذجك
        }

        return features

    except Exception as e:
        print(f"[!] Error extracting features: {e}")
        return {
            "Size": 0,
            "NumberOfSections": 0,
            "NumberOfImports": 0,
            "EntropyMean": 0.0
        }

def count_imports(pe):
    try:
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return sum(len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT)
        else:
            return 0
    except:
        return 0

def calc_entropy(pe):
    try:
        entropies = [section.get_entropy() for section in pe.sections]
        return sum(entropies) / len(entropies) if entropies else 0.0
    except:
        return 0.0
