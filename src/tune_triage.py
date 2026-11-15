import pandas as pd
from src.classifier import classify
from src.triage import triage

val = pd.read_csv("data/val.csv")
res = [classify(l) for l in val.log_line]
val["pred"] = [r[0] for r in res]; val["conf"] = [r[1] for r in res]
print("val accuracy:", (val.pred == val.label).mean())
print("benign_thr mal_thr | malicious_auto_closed benign_auto_closed alerts review")
for b in [0.80, 0.90, 0.95]:
    for m in [0.70, 0.85, 0.95]:
        d = [triage(p, c, t, b, m) for p, c, t in zip(val.pred, val.conf, val.attack_type)]
        val["d"] = d
        bad = ((val.label == "malicious") & (val.d == "AUTO_CLOSE")).sum()
        good = ((val.label == "benign") & (val.d == "AUTO_CLOSE")).sum()
        print(f"{b:.2f} {m:.2f} | {bad} {good} {(val.d == 'HIGH_PRIORITY_ALERT').sum()} {(val.d == 'FLAG_FOR_REVIEW').sum()}")
