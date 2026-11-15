BENIGN_THR = 0.80   # tuned on val.csv
MAL_THR = 0.85
SEVERITY = {"SQLi": "high", "PathTraversal": "high", "XSS": "medium"}

def triage(label, confidence, attack_type=None, benign_thr=BENIGN_THR, mal_thr=MAL_THR):
    if label == "benign" and confidence >= benign_thr:
        return "AUTO_CLOSE"
    if label == "malicious" and confidence >= mal_thr and SEVERITY.get(attack_type) == "high":
        return "HIGH_PRIORITY_ALERT"
    return "FLAG_FOR_REVIEW"
