import json
import os
import requests
from datetime import datetime

CACHE_FILE = "cache/vt_cache.json"

class CloudThreatIntel:
    # Cơ sở dữ liệu mẫu uy tín cho Demo thuyết trình (WannaCry, Emotet, Clean Notepad...)
    KNOWN_DEMO_HASHES = {
        # WannaCry Ransomware
        "ed01ebf83334a1f6f164887864750e527ec40e18c641f553e524d1e2ee60ea53": {
            "status": "FOUND",
            "positives": 68,
            "total": 72,
            "cloud_score": 0.9444,
            "threat_classification": "Ransomware.WannaCry / Win32.WannaCrypt",
            "top_detections": {
                "Microsoft": "Ransom:Win32/WannaCrypt",
                "Kaspersky": "Trojan-Ransom.Win32.Wanna.m",
                "CrowdStrike": "win/malicious_confidence_100% (W)",
                "Sophos": "Troj/Wanna-G"
            },
            "first_seen": "2017-05-12",
            "source": "VirusTotal Threat Intelligence (Demo Cache)"
        },
        # Emotet Banking Trojan
        "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c": {
            "status": "FOUND",
            "positives": 61,
            "total": 71,
            "cloud_score": 0.8592,
            "threat_classification": "Trojan.Emotet / Heur.Bzc",
            "top_detections": {
                "Microsoft": "Trojan:Win32/Emotet.RP",
                "Kaspersky": "Trojan-Banker.Win32.Emotet",
                "CrowdStrike": "win/malicious_confidence_98%",
                "Sophos": "Mal/Emotet-AE"
            },
            "first_seen": "2020-07-17",
            "source": "VirusTotal Threat Intelligence (Demo Cache)"
        }
    }

    def __init__(self, api_key=""):
        self.api_key = api_key.strip() if api_key else ""
        self.base_url = "https://www.virustotal.com/api/v3/files/"
        self.cache = self._load_cache()

    def _load_cache(self):
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_cache(self):
        try:
            with open(CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def lookup_hash(self, sha256_hash):
        """
        Tra cứu danh tiếng file trên VirusTotal thông qua mã băm SHA-256:
        - Kiểm tra cache cục bộ
        - Kiểm tra cơ sở dữ liệu mẫu demo
        - Tra cứu trực tiếp VirusTotal API v3 nếu có API key
        """
        sha256_lower = sha256_hash.lower()

        # 1. Kiểm tra cache
        if sha256_lower in self.cache:
            res = self.cache[sha256_lower].copy()
            res["source"] = "Local Cache"
            return res

        # 2. Kiểm tra danh mục Demo
        if sha256_lower in self.KNOWN_DEMO_HASHES:
            return self.KNOWN_DEMO_HASHES[sha256_lower]

        # 3. Nếu chưa nhập API key hoặc dùng key mặc định
        if not self.api_key or self.api_key in ["YOUR_VT_API_KEY", ""]:
            return {
                "status": "NO_API_KEY",
                "positives": 0,
                "total": 0,
                "cloud_score": 0.0,
                "threat_classification": "Không xác định (Chưa cấu hình API Key)",
                "top_detections": {},
                "source": "Offline (Không có API Key)"
            }

        headers = {"x-apikey": self.api_key}
        try:
            response = requests.get(f"{self.base_url}{sha256_lower}", headers=headers, timeout=12)
            if response.status_code == 200:
                data = response.json().get("data", {})
                attributes = data.get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                results = attributes.get("last_analysis_results", {})

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                total = malicious + suspicious + harmless + undetected

                # Trích xuất phát hiện từ các AV danh tiếng
                top_engines = ["Microsoft", "Kaspersky", "CrowdStrike", "Sophos", "Symantec", "BitDefender"]
                top_detections = {}
                for eng in top_engines:
                    if eng in results and results[eng].get("category") in ["malicious", "suspicious"]:
                        top_detections[eng] = results[eng].get("result", "Malicious")

                threat_class = attributes.get("popular_threat_classification", {})
                suggested_label = threat_class.get("suggested_threat_label", "Chưa phân loại cụ thể")

                res_data = {
                    "status": "FOUND",
                    "positives": malicious + suspicious,
                    "total": total,
                    "cloud_score": round((malicious + suspicious) / total, 4) if total > 0 else 0.0,
                    "threat_classification": suggested_label,
                    "top_detections": top_detections,
                    "source": "VirusTotal Cloud Live API"
                }

                self.cache[sha256_lower] = res_data
                self._save_cache()
                return res_data

            elif response.status_code == 404:
                # File chưa từng xuất hiện trên VirusTotal (rất có khả năng là file mới hoặc Zero-Day)
                res_data = {
                    "status": "NOT_FOUND",
                    "positives": 0,
                    "total": 0,
                    "cloud_score": 0.0,
                    "threat_classification": "Tệp hoàn toàn mới (Chưa có chữ ký mẫu trên Cloud)",
                    "top_detections": {},
                    "source": "VirusTotal (Hash Not Found)"
                }
                return res_data

            elif response.status_code == 429:
                return {
                    "status": "RATE_LIMITED",
                    "positives": 0,
                    "total": 0,
                    "cloud_score": 0.0,
                    "threat_classification": "Vượt giới hạn lượt gọi API VirusTotal (Quota Exceeded)",
                    "top_detections": {},
                    "source": "VirusTotal API"
                }
            else:
                return {
                    "status": f"HTTP_{response.status_code}",
                    "positives": 0,
                    "total": 0,
                    "cloud_score": 0.0,
                    "threat_classification": "Lỗi phản hồi máy chủ đám mây",
                    "top_detections": {},
                    "source": "VirusTotal API"
                }

        except requests.RequestException as e:
            return {
                "status": "NETWORK_ERROR",
                "positives": 0,
                "total": 0,
                "cloud_score": 0.0,
                "threat_classification": f"Lỗi kết nối mạng: {str(e)}",
                "top_detections": {},
                "source": "Offline (Network Error)"
            }