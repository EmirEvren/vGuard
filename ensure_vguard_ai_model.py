import os
import json
import datetime
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_FILE = os.path.join(BASE_DIR, "vguard_brain.pkl")
REPORT_FILE = os.path.join(BASE_DIR, "vguard_model_report.json")
DATASET_FILE = os.path.join(BASE_DIR, "dataset.csv")

FEATURE_COLUMNS = ["Size", "Reqs", "Entropy", "SpChar"]
LABEL_COLUMN = "Label"

AI_OBSERVE_THRESHOLD = 0.65
AI_WARNING_THRESHOLD = 0.80
AI_BLOCK_THRESHOLD = 0.92

RANDOM_STATE = 42


def now_str():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def create_demo_dataset():
    """
    Creates a small demo-compatible training dataset if no model exists.
    This is enough to keep the DPI engine online and make AI scoring usable for demos.
    For full benchmark evaluation, you can still replace this with CICIDS2017 preprocessing + ai_trainer.py.
    """
    rng = np.random.default_rng(RANDOM_STATE)

    normal_rows = []
    attack_rows = []

    for _ in range(300):
        normal_rows.append({
            "Size": int(rng.integers(20, 500)),
            "Reqs": int(rng.integers(1, 25)),
            "Entropy": float(rng.uniform(1.0, 4.5)),
            "SpChar": float(rng.uniform(0.0, 0.06)),
            "Label": 0,
        })

    for _ in range(300):
        attack_rows.append({
            "Size": int(rng.integers(250, 2500)),
            "Reqs": int(rng.integers(15, 180)),
            "Entropy": float(rng.uniform(3.5, 7.5)),
            "SpChar": float(rng.uniform(0.08, 0.45)),
            "Label": 1,
        })

    df = pd.DataFrame(normal_rows + attack_rows)
    df = df.sample(frac=1.0, random_state=RANDOM_STATE).reset_index(drop=True)
    return df


def train_and_save_model(df):
    X = df[FEATURE_COLUMNS].values
    y = df[LABEL_COLUMN].values

    model = RandomForestClassifier(
        n_estimators=120,
        random_state=RANDOM_STATE,
        class_weight="balanced"
    )
    model.fit(X, y)

    y_pred = model.predict(X)

    metrics = {
        "accuracy": float(accuracy_score(y, y_pred)),
        "precision": float(precision_score(y, y_pred, zero_division=0)),
        "recall": float(recall_score(y, y_pred, zero_division=0)),
        "f1_score": float(f1_score(y, y_pred, zero_division=0)),
        "confusion_matrix": confusion_matrix(y, y_pred).tolist(),
    }

    feature_importance = {
        feature: float(score)
        for feature, score in zip(FEATURE_COLUMNS, model.feature_importances_)
    }

    bundle = {
        "project": "v-Guard",
        "model": model,
        "model_type": "RandomForestClassifier",
        "created_at": now_str(),
        "feature_columns": FEATURE_COLUMNS,
        "label_column": LABEL_COLUMN,
        "observe_threshold": AI_OBSERVE_THRESHOLD,
        "warning_threshold": AI_WARNING_THRESHOLD,
        "block_threshold": AI_BLOCK_THRESHOLD,
        "random_state": RANDOM_STATE,
        "dataset_summary": {
            "total_records": int(len(df)),
            "normal_records": int((df[LABEL_COLUMN] == 0).sum()),
            "attack_records": int((df[LABEL_COLUMN] == 1).sum()),
            "source": "auto-generated demo dataset"
        },
        "metrics": metrics,
        "feature_importance": feature_importance,
        "notes": (
            "Auto-generated v-Guard demo model. "
            "Use data_preprocessor.py + ai_trainer.py later if you want to replace it with a CICIDS2017-derived model."
        )
    }

    joblib.dump(bundle, MODEL_FILE)

    report = {
        "project": "v-Guard",
        "report_type": "Auto Demo AI Model Report",
        "created_at": now_str(),
        "model_file": MODEL_FILE,
        "features": FEATURE_COLUMNS,
        "metrics": metrics,
        "feature_importance": feature_importance,
        "dataset_summary": bundle["dataset_summary"],
        "important_note": (
            "This script is used to prevent dpi_engine.py from stopping when vguard_brain.pkl is missing. "
            "It creates a demo-compatible RandomForest model so the engine heartbeat and dashboard status work."
        )
    }

    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)

    if not os.path.exists(DATASET_FILE):
        df.to_csv(DATASET_FILE, index=False)

    return metrics


def main():
    print("[*] v-Guard AI model check")

    if os.path.exists(MODEL_FILE):
        print(f"[+] Model already exists: {MODEL_FILE}")
        return

    print("[!] vguard_brain.pkl not found.")
    print("[*] Creating demo-compatible AI model...")

    df = create_demo_dataset()
    metrics = train_and_save_model(df)

    print("[+] Demo AI model created successfully.")
    print(f"    Model : {MODEL_FILE}")
    print(f"    Report: {REPORT_FILE}")
    print(f"    Accuracy: {metrics['accuracy'] * 100:.2f}%")
    print("[*] You can start dpi_engine.py now.")


if __name__ == "__main__":
    main()
