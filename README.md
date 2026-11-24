# Automated Web App Vuln Log Audit Assistant

Pipeline: parse log -> classify (malicious/benign) -> retrieve OWASP passages -> Gemini incident report -> triage

## Repo structure
- data/: logs_150.csv, train.csv, val.csv, test_20.csv (built by src/build_dataset.py from CSIC 2010 + hand-written cases)
- src/: classifier.py, triage.py, features.py, train_planb.py, tune_triage.py, evaluate.py, classifier_planb.joblib
- knowledge_base/owasp_kb.csv: 11 OWASP passages (SQLi, XSS, Path Traversal)
- notebooks/: Automated_Web_App_Vuln_Log_Audit_Assistant.ipynb (single notebook: classifier, parser, OWASP retrieval, Gemini reports, triage and evaluation)
- results/: master_pipeline_predictions.csv, master_retrieval_evaluation.csv, master_pipeline_vs_baseline.csv, master_classifier_metrics.json

## Results (20 test cases)
- Classifier + triage accuracy: 19/20 (one miss: SSI injection at the end of a long request)
- Retrieval: top-1 11/14, recall@3 14/14 (knowledge base enriched after the first run)
- Gemini-only baseline: 19/20 (same accuracy as the pipeline)
- Benign reports without remediation advice: 6/6

## How to run
1. pip install -r requirements.txt
2. Plan B classifier: python3 -m src.train_planb ; evaluation: python3 -m src.evaluate
3. Fine-tuned model: weights are in Google Drive (https://drive.google.com/drive/folders/1L-6Hf1VPh37gvZNZh2MomIPddOFTsCj4?usp=sharing). Set FT_MODEL_DIR to the folder.
4. Full pipeline: open notebooks/Automated_Web_App_Vuln_Log_Audit_Assistant.ipynb in Colab (needs GEMINI_API_KEY in Colab Secrets).

## Rules
- Never commit API keys or model weights.
- Run `git pull origin main` before you push.
