import os
import hashlib
import pefile
import magic
import datetime
import math

def get_file_size(filepath):
    try:
        return os.path.getsize(filepath)
    except:
        return None

def get_file_type(filepath):
    try:
        return magic.from_file(filepath)
    except:
        return "Unknown"

def get_sha256(filepath):
    try:
        with open(filepath, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except:
        return None

def get_entropy(data):
    if not data:
        return None
    occurences = dict((x, 0) for x in range(256))
    for x in data:
        occurences[x] += 1
    entropy = 0
    for x in occurences.values():
        if x:
            p_x = x / len(data)
            entropy -= p_x * math.log2(p_x)
    return entropy

def extract_pe_features(filepath):
    try:
        pe = pefile.PE(filepath)
        section_entropy = pe.sections[0].get_entropy() if pe.sections else None
        num_sections = len(pe.sections)
        num_imports = len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else None
        has_resources = int(hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'))
        has_signature = int(hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'))

        try:
            timestamp = pe.FILE_HEADER.TimeDateStamp
            compile_time = datetime.datetime.utcfromtimestamp(timestamp).isoformat()
        except:
            compile_time = None

        suspicious_apis = ['VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread', 'WinExec', 'ShellExecute']
        api_count = 0
        try:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name and any(api.lower() in imp.name.decode(errors='ignore').lower() for api in suspicious_apis):
                        api_count += 1
        except:
            api_count = None

        try:
            with open(filepath, 'rb') as f:
                data = f.read()
                total_entropy = get_entropy(data)
        except:
            total_entropy = None

        suspicious_strings = [b'bitcoin', b'encrypt', b'decrypt', b'wallet', b'key', b'ransom']
        sus_string_count = 0
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
                for s in suspicious_strings:
                    if s in data:
                        sus_string_count += 1
        except:
            sus_string_count = None

        is_packed = 0
        try:
            for section in pe.sections:
                name = section.Name.decode(errors='ignore').strip('\x00')
                if 'UPX' in name:
                    is_packed = 1
        except:
            is_packed = 0

        return {
            "Entropy": section_entropy,
            "NumberOfSections": num_sections,
            "NumberOfImports": num_imports,
            "HasResources": has_resources,
            "HasSignature": has_signature,
            "CompileTime": compile_time,
            "SuspiciousAPICalls": api_count,
            "TotalEntropy": total_entropy,
            "SuspiciousStringCount": sus_string_count,
            "IsPacked": is_packed
        }
    except:
        return {
            "Entropy": None,
            "NumberOfSections": None,
            "NumberOfImports": None,
            "HasResources": None,
            "HasSignature": None,
            "CompileTime": None,
            "SuspiciousAPICalls": None,
            "TotalEntropy": None,
            "SuspiciousStringCount": None,
            "IsPacked": None
        }

def extract_static_features(filepath):
    features = {
        "FileName": os.path.basename(filepath),
        "SHA256": get_sha256(filepath),
        "FileSize": get_file_size(filepath),
        "FileType": get_file_type(filepath)
    }

    if features["FileType"] and "PE32" in features["FileType"]:
        pe_features = extract_pe_features(filepath)
        features.update(pe_features)
    else:
        features.update({
            "Entropy": None,
            "NumberOfSections": None,
            "NumberOfImports": None,
            "HasResources": None,
            "HasSignature": None,
            "CompileTime": None,
            "SuspiciousAPICalls": None,
            "TotalEntropy": None,
            "SuspiciousStringCount": None,
            "IsPacked": None
        })
    return features
