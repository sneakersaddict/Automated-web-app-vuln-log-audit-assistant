import pandas as pd, joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.pipeline import make_pipeline
from sklearn.metrics import accuracy_score, confusion_matrix
from src.features import request_text

train = pd.read_csv("data/train.csv"); val = pd.read_csv("data/val.csv")
Xtr = train.log_line.map(request_text); Xva = val.log_line.map(request_text)

model = make_pipeline(TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5)),
                      CalibratedClassifierCV(LogisticRegression(max_iter=1000), cv=3))
model.fit(Xtr, train.label)

print("train accuracy:", model.score(Xtr, train.label))
pred = model.predict(Xva)
print("val accuracy:  ", accuracy_score(val.label, pred))
print(confusion_matrix(val.label, pred, labels=["malicious", "benign"]))
joblib.dump(model, "src/classifier_planb.joblib")
print("saved src/classifier_planb.joblib")
