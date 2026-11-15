import os, json, joblib
from src.features import request_text

_here = os.path.dirname(__file__)
_cache = {}
LABELS = ["benign", "malicious"]

def _load():
    if "m" in _cache:
        return _cache["m"]
    ft_dir = os.environ.get("FT_MODEL_DIR")
    if ft_dir and os.path.isdir(ft_dir):
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
        tok = AutoTokenizer.from_pretrained(ft_dir)
        model = AutoModelForSequenceClassification.from_pretrained(ft_dir).eval()
        T = json.load(open(os.path.join(ft_dir, "temperature.json")))["T"]
        _cache["m"] = ("ft", tok, model, T)
    else:
        _cache["m"] = ("planb", joblib.load(os.path.join(_here, "classifier_planb.joblib")))
    return _cache["m"]

def classify(log_line):
    """Return (label, confidence) where confidence = probability of the predicted label."""
    text = request_text(log_line)
    m = _load()
    if m[0] == "ft":
        import torch
        _, tok, model, T = m
        enc = tok(text, truncation=True, max_length=128, return_tensors="pt")
        with torch.no_grad():
            p = torch.softmax(model(**enc).logits[0].cpu() / T, dim=0)
        i = int(p.argmax())
        return LABELS[i], float(p[i])
    pipe = m[1]
    probs = pipe.predict_proba([text])[0]
    i = probs.argmax()
    return str(pipe.classes_[i]), float(probs[i])
