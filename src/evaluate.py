import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix
from src.classifier import classify
from src.triage import triage

test = pd.read_csv("data/test_20.csv")
res = [classify(l) for l in test.log_line]
test["pred"] = [r[0] for r in res]; test["conf"] = [round(r[1], 3) for r in res]
test["decision"] = [triage(p, c, t) for p, c, t in zip(test.pred, test.conf, test.attack_type)]
acc = accuracy_score(test.label, test.pred)
print(f"test accuracy: {acc:.2f} ({int(acc * 20)}/20, target >= 16/20)")
print(confusion_matrix(test.label, test.pred, labels=["malicious", "benign"]))
print(test[["id", "label", "attack_type", "pred", "conf", "decision"]].to_string(index=False))
test.to_csv("results/classifier_results.csv", index=False)
