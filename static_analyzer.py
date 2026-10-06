import hashlib
import math
import os
import pefile
import numpy as np

class StaticAnalyzer:
    # Các section packer/crypter phổ biến
    SUSPICIOUS_SECTION_NAMES = [
        b".upx", b"upx0", b"upx1", b"upx2", b".aspack", b".mpress", 
        b".themida", b".vmp", b".nsp", b".enigma", b".petite", b".fsg"
    ]

    # Danh mục Windows API nhạy cảm thường dùng trong tấn công mạng
    SUSPICIOUS_API_CATEGORIES = {
        "injection": [
            "virtualalloc", "virtualallocex", "virtualprotect", "virtualprotectex",
            "writeprocessmemory", "createremotethread", "queueuserapc",
            "ntwritevirtualmemory", "ntprotectvirtualmemory", "setthreadcontext"
        ],
        "persistence": [
            "regsetvalueexa", "regsetvalueexw", "regcreatekeyexa", "regcreatekeyexw",
            "createservicea", "createservicew", "openscmanagera", "openscmanagerw"
        ],
        "evasion": [
            "isdebuggerpresent", "checkremotedebuggerpresent", "findwindowa", "findwindoww",
            "gettickcount", "outputdebugstringa", "sleep", "blockinput"
        ],
        "network": [
            "urldownloadtofilea", "urldownloadtofilew", "internetopena", "internetopenurla",
            "httpsendrequesta", "httpsendrequestw", "wsastartup", "connect", "socket"
        ],
        "execution": [
            "winexec", "shellexecutea", "shellexecutew", "createprocessa", "createprocessw"
        ],
        "spying": [
            "getasynckeystate", "getkeystate", "setwindowshookexa", "setwindowshookexw",
            "getclipboarddata"
        ]
    }

    @staticmethod
    def calculate_hashes(file_path):
        """Tính toán MD5, SHA-1 và SHA-256 của file."""
        hasher_md5 = hashlib.md5()
        hasher_sha1 = hashlib.sha1()
        hasher_sha256 = hashlib.sha256()

        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher_md5.update(chunk)
                hasher_sha1.update(chunk)
                hasher_sha256.update(chunk)

        return {
            "md5": hasher_md5.hexdigest(),
            "sha1": hasher_sha1.hexdigest(),
            "sha256": hasher_sha256.hexdigest()
        }

    @staticmethod
    def calculate_entropy(data):
        """Tính Shannon Entropy của chuỗi byte (0.0 - 8.0)."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        for x in range(256):
            p_x = float(data.count(bytes([x]))) / length
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    @classmethod
    def extract_features(cls, file_path):
        """
        Trích xuất vector 12 đặc trưng toàn diện phục vụ mô hình AI và bảng phân tích tĩnh:
        [file_size, num_sections, overall_entropy, max_section_entropy, 
         num_imported_dlls, num_imported_funcs, has_suspicious_section, 
         size_anomaly_count, count_injection_apis, count_persistence_apis, 
         count_evasion_apis, count_network_apis]
        """
        hashes = cls.calculate_hashes(file_path)
        
        with open(file_path, "rb") as f:
            raw_bytes = f.read()

        file_size = len(raw_bytes)
        overall_entropy = cls.calculate_entropy(raw_bytes)

        has_suspicious_sec = 0
        max_sec_entropy = 0.0
        num_sections = 0
        num_imported_dlls = 0
        num_imported_funcs = 0
        size_anomaly_count = 0
        imphash = "N/A"
        is_pe = False

        sections_info = []
        detected_suspicious_apis = {cat: [] for cat in cls.SUSPICIOUS_API_CATEGORIES}

        try:
            pe = pefile.PE(file_path)
            is_pe = True
            try:
                imphash = pe.get_imphash()
            except Exception:
                imphash = "N/A"

            num_sections = len(pe.sections)

            for sec in pe.sections:
                sec_entropy = round(sec.get_entropy(), 3)
                if sec_entropy > max_sec_entropy:
                    max_sec_entropy = sec_entropy

                raw_name = sec.Name.rstrip(b"\x00")
                try:
                    sec_name = raw_name.decode("utf-8", errors="ignore")
                except Exception:
                    sec_name = str(raw_name)

                clean_name_lower = raw_name.lower()
                is_suspicious_name = any(sus in clean_name_lower for sus in cls.SUSPICIOUS_SECTION_NAMES)
                if is_suspicious_name:
                    has_suspicious_sec = 1

                # Kiểm tra bất thường về kích thước (VirtualSize >> SizeOfRawData -> dấu hiệu unpacked trong RAM)
                virt_size = sec.Misc_VirtualSize
                raw_size = sec.SizeOfRawData
                is_size_anomaly = (raw_size > 0 and (virt_size / raw_size > 3.0)) or (raw_size == 0 and virt_size > 0)
                if is_size_anomaly:
                    size_anomaly_count += 1

                sections_info.append({
                    "name": sec_name,
                    "virtual_size": virt_size,
                    "raw_size": raw_size,
                    "entropy": sec_entropy,
                    "is_suspicious": is_suspicious_name or sec_entropy > 7.2 or is_size_anomaly
                })

            # Bóc tách thư viện và hàm API được import
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                num_imported_dlls = len(pe.DIRECTORY_ENTRY_IMPORT)
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        num_imported_funcs += 1
                        if imp.name:
                            try:
                                func_name = imp.name.decode("utf-8", errors="ignore").lower()
                                for category, apis in cls.SUSPICIOUS_API_CATEGORIES.items():
                                    if func_name in apis:
                                        if func_name not in detected_suspicious_apis[category]:
                                            detected_suspicious_apis[category].append(func_name)
                            except Exception:
                                pass
            pe.close()
        except Exception:
            # File không phải PE hoặc bị lỗi định dạng
            is_pe = False

        count_injection = len(detected_suspicious_apis["injection"])
        count_persistence = len(detected_suspicious_apis["persistence"])
        count_evasion = len(detected_suspicious_apis["evasion"])
        count_network = len(detected_suspicious_apis["network"])

        feature_vector = np.array([
            file_size,
            num_sections,
            overall_entropy,
            max_sec_entropy,
            num_imported_dlls,
            num_imported_funcs,
            has_suspicious_sec,
            size_anomaly_count,
            count_injection,
            count_persistence,
            count_evasion,
            count_network
        ], dtype=np.float32)

        metadata = {
            "filename": os.path.basename(file_path),
            "file_size": file_size,
            "is_pe": is_pe,
            "md5": hashes["md5"],
            "sha1": hashes["sha1"],
            "sha256": hashes["sha256"],
            "imphash": imphash,
            "overall_entropy": round(overall_entropy, 3),
            "max_section_entropy": round(max_sec_entropy, 3),
            "num_sections": num_sections,
            "num_imported_dlls": num_imported_dlls,
            "num_imported_funcs": num_imported_funcs,
            "has_suspicious_section": bool(has_suspicious_sec),
            "size_anomaly_count": size_anomaly_count,
            "sections": sections_info,
            "suspicious_apis": detected_suspicious_apis
        }

        return feature_vector, metadata