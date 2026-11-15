import re, random
import pandas as pd
from urllib.parse import unquote_plus
from sklearn.model_selection import train_test_split

random.seed(42)

SQLI = re.compile(r"(?i)(\bunion\b.+\bselect\b|'\s*or\s|\bor\b\s+\d+\s*=\s*\d+|\bdrop\s+table\b|\bsleep\s*\(|--)")
XSS  = re.compile(r"(?i)(<\s*script|javascript:|onerror\s*=|onload\s*=|<\s*img|<\s*svg|alert\s*\()")
PT   = re.compile(r"(?i)(\.\./|\.\.\\|/etc/passwd|boot\.ini|win\.ini)")

def attack_type(s):
    d = unquote_plus(s)
    if XSS.search(d): return "XSS"
    if PT.search(d): return "PathTraversal"
    if SQLI.search(d): return "SQLi"
    return "none"

def make_line(method, pq, status):
    ip = f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"
    ts = f"{random.randint(1,28):02d}/Nov/2026:{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d} +0000"
    return f'{ip} - - [{ts}] "{method} {pq} HTTP/1.1" {status} {random.randint(200,5000)}'

raw = pd.read_csv("data/raw/csic_database.csv").rename(columns={"Unnamed: 0": "tag"})

def to_request(r):
    url = re.sub(r" HTTP/\d\.\d$", "", str(r.URL))
    pq = re.sub(r"^https?://[^/]+", "", url)
    if r.Method == "POST" and pd.notna(r.content):   # POST body goes into the query so the payload is visible
        pq += ("&" if "?" in pq else "?") + str(r.content).strip()
    return (r.Method, pq)

# benign: sample 3000 normal requests, keep those matching no attack pattern
benign = [to_request(r) for r in raw[raw.tag == "Normal"].sample(3000, random_state=42).itertuples()]
benign = list({pq: (m, pq) for m, pq in benign if attack_type(pq) == "none"}.values())

# attacks: remove duplicates (CSIC has each attack as both GET and POST)
attacks = {}
for r in raw[raw.tag == "Anomalous"].itertuples():
    m, pq = to_request(r)
    attacks[pq] = (m, pq, attack_type(pq))
attacks = list(attacks.values())

rows = []
# benign from CSIC (54)
for m, pq in random.sample(benign, 54):
    rows.append((make_line(m, pq, random.choice([200, 304])), "benign", "none", "csic"))
# malicious from CSIC (up to 27 per type)
for t in ["SQLi", "XSS", "PathTraversal"]:
    pool = [a for a in attacks if a[2] == t]
    print(t, "available in CSIC:", len(pool))
    for m, pq, _ in random.sample(pool, min(27, len(pool))):
        rows.append((make_line(m, pq, random.choice([200, 400, 403, 500])), "malicious", t, "csic"))

# manual obfuscated attacks (9) and ambiguous benign (6)
manual = [
 ("/search?q=1%27%2F**%2FoR%2F**%2F1%3D1", "SQLi"),
 ("/item?id=1/**/UNION/**/SELECT/**/null,null", "SQLi"),
 ("/login?user=admin%27%20oR%20%271%27%3D%271", "SQLi"),
 ("/search?q=%3CScRiPt%3Ealert(1)%3C/ScRiPt%3E", "XSS"),
 ("/profile?name=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E", "XSS"),
 ("/comment?text=%253Cscript%253Ealert(1)%253C/script%253E", "XSS"),
 ("/download?file=..%252f..%252fetc%252fpasswd", "PathTraversal"),
 ("/view?page=....//....//etc/passwd", "PathTraversal"),
 ("/files?path=..%2F..%2Fwindows%2Fwin.ini", "PathTraversal"),
 ("/search?q=O%27Brien", "none"),
 ("/search?q=select+a+gift+from+our+store", "none"),
 ("/files?path=reports/2026--final.pdf", "none"),
 ("/blog?title=how-to-use-the-script-tag", "none"),
 ("/search?q=1%3D1+is+true+in+math", "none"),
 ("/products?id=5&sort=price--desc", "none"),
]
for pq, t in manual:
    rows.append((make_line("GET", pq, random.choice([200, 403])),
                 "benign" if t == "none" else "malicious", t, "manual"))

df = pd.DataFrame(rows, columns=["log_line", "label", "attack_type", "source"])
df = df.sample(frac=1, random_state=42).reset_index(drop=True)
df.insert(0, "id", range(1, len(df) + 1))
print(df.groupby(["label", "attack_type"]).size())

def pick(t, n_manual, total):
    sub = df[df.attack_type == t]
    man = sub[sub.source == "manual"].sample(n_manual, random_state=42)
    oth = sub[sub.source != "manual"].sample(total - n_manual, random_state=42)
    return pd.concat([man, oth])

test = pd.concat([pick("SQLi", 1, 5), pick("XSS", 1, 5), pick("PathTraversal", 1, 4), pick("none", 3, 6)])
rest = df.drop(test.index)
train, val = train_test_split(rest, test_size=30, stratify=rest.label, random_state=42)

df.to_csv("data/logs_150.csv", index=False)
train.to_csv("data/train.csv", index=False)
val.to_csv("data/val.csv", index=False)
test.to_csv("data/test_20.csv", index=False)
print("total/train/val/test:", len(df), len(train), len(val), len(test))
