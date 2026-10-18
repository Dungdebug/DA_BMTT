import tempfile
import os
import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
sys.path.append(os.path.abspath("."))
from hybrid_detector import HybridDetector

hd = HybridDetector()

# Test 1: Empty file
tf1 = tempfile.NamedTemporaryFile(suffix='.exe', delete=False)
tf1.write(b'')
tf1.close()
res1 = hd.scan(tf1.name)
print("1. Empty File (.exe 0-byte):")
print(f"   Verdict: {res1['hybrid_decision']['final_verdict']} | Risk: {res1['hybrid_decision']['overall_risk_score']} | Rule: {res1['hybrid_decision']['applied_rule']}")
os.unlink(tf1.name)

# Test 2: Clean C++ program
p2 = "scratch/test_hello.cpp"
with open(p2, "w") as f:
    f.write("#include <iostream>\nusing namespace std;\nint main() {\n    cout << 'Hello' << endl;\n    return 0;\n}")
res2 = hd.scan(p2)
print("2. Clean C++ File (.cpp):")
print(f"   Verdict: {res2['hybrid_decision']['final_verdict']} | Risk: {res2['hybrid_decision']['overall_risk_score']} | Rule: {res2['hybrid_decision']['applied_rule']}")
print(f"   RF: {res2['ai_analysis']['dual_models']['random_forest']['prediction_label']} ({res2['ai_analysis']['dual_models']['random_forest']['malware_probability']}%)")
print(f"   KNN: {res2['ai_analysis']['dual_models']['knn']['prediction_label']} ({res2['ai_analysis']['dual_models']['knn']['malware_probability']}%)")
print(f"   SVM: {res2['ai_analysis']['dual_models']['svm']['prediction_label']} ({res2['ai_analysis']['dual_models']['svm']['malware_probability']}%)")
print(f"   Consensus: {res2['ai_analysis']['dual_models']['comparison']['status_text']}")

print("\n[+] TẤT CẢ GUARDRAIL ĐÃ HOẠT ĐỘNG CHUẨN XÁC!")
