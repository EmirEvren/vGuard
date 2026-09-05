import os
import sys
import json
import datetime
import joblib
import pandas as pd
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)


# ============================================================
# v-Guard AI Trainer
#
# Trains the supervised ML model used by dpi_engine.py.
#
# Expected dataset columns:
# Size, Reqs, Entropy, SpChar, Label
#
# Output:
# - vguard_brain.pkl          -> model bundle
# - vguard_model_report.json  -> readable training report
# ============================================================


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATASET_FILE = os.path.join(BASE_DIR, "dataset.csv")
MODEL_FILE = os.path.join(BASE_DIR, "vguard_brain.pkl")
REPORT_FILE = os.path.join(BASE_DIR, "vguard_model_report.json")

FEATURE_COLUMNS = ["Size", "Reqs", "Entropy", "SpChar"]
LABEL_COLUMN = "Label"

RANDOM_STATE = 42
TEST_SIZE = 0.2


# ============================================================
# Professional AI Decision Thresholds
#
# These values are read by dpi_engine.py.
#
# OBSERVE:
#   AI sees weak suspicious behavior.
#   System only logs the event.
#
# WARNING:
#   AI sees stronger suspicious behavior.
#   System creates a warning log but does not block yet.
#
# BLOCK:
#   AI sees critical suspicious behavior.
#   System blocks packet and temporarily bans IP.
# ============================================================

AI_OBSERVE_THRESHOLD = 0.65
AI_WARNING_THRESHOLD = 0.80
AI_BLOCK_THRESHOLD = 0.92


def fail(message):
    print(f"[!] HATA: {message}")
    sys.exit(1)


def load_dataset():
    print("[*] V-Guard Yapay Zeka Eğitim Modülü Başlatılıyor...")

    if not os.path.exists(DATASET_FILE):
        fail(
            f"{DATASET_FILE} bulunamadı.\n"
            f"Önce şu komutu çalıştır:\n"
            f"    python data_preprocessor.py"
        )

    print(f"[*] Dataset okunuyor: {DATASET_FILE}")

    try:
        df = pd.read_csv(DATASET_FILE)
    except Exception as e:
        fail(f"Dataset okunamadı: {e}")

    return df


def validate_dataset(df):
    required_columns = FEATURE_COLUMNS + [LABEL_COLUMN]

    missing_columns = [
        col for col in required_columns
        if col not in df.columns
    ]

    if missing_columns:
        print("[!] Eksik kolonlar:")
        for col in missing_columns:
            print(f"    - {col}")

        print("\n[*] Dataset içinde bulunan kolonlar:")
        for col in df.columns:
            print(f"    - {col}")

        fail("Dataset formatı ai_trainer.py ile uyumlu değil.")

    if len(df) == 0:
        fail("Dataset boş.")

    # Label temizliği
    df[LABEL_COLUMN] = (
        pd.to_numeric(df[LABEL_COLUMN], errors="coerce")
        .fillna(0)
        .astype(int)
    )

    unique_labels = sorted(df[LABEL_COLUMN].unique().tolist())

    if len(unique_labels) < 2:
        fail(
            "Dataset içinde tek sınıf var. Model eğitilemez.\n"
            "Label kolonunda hem 0 yani normal trafik hem de 1 yani saldırı trafiği olmalı."
        )

    # Feature temizliği
    for col in FEATURE_COLUMNS:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    # Sadece beklenen label değerlerini tut
    df = df[df[LABEL_COLUMN].isin([0, 1])].copy()

    if len(df) == 0:
        fail("Temizlikten sonra dataset boş kaldı.")

    return df


def print_dataset_summary(df):
    total = len(df)
    normal_count = int((df[LABEL_COLUMN] == 0).sum())
    attack_count = int((df[LABEL_COLUMN] == 1).sum())

    print("\n=============================================")
    print(" V-GUARD DATASET SUMMARY")
    print("=============================================")
    print(f" Total records : {total}")
    print(f" Normal traffic: {normal_count}")
    print(f" Attack traffic: {attack_count}")

    if total > 0:
        print(f" Attack ratio  : %{(attack_count / total) * 100:.2f}")

    print("=============================================\n")


def train_model(X_train, y_train):
    print("[*] Random Forest modeli eğitiliyor...")

    model = RandomForestClassifier(
        n_estimators=300,
        random_state=RANDOM_STATE,
        n_jobs=-1,
        class_weight="balanced",
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1
    )

    model.fit(X_train, y_train)

    print("[+] Eğitim başarılı!")

    return model


def evaluate_model(model, X_test, y_test):
    print("\n[*] Model test verisiyle değerlendiriliyor...")

    y_pred = model.predict(X_test)

    if hasattr(model, "predict_proba"):
        y_proba = model.predict_proba(X_test)

        if y_proba.shape[1] > 1:
            attack_probs = y_proba[:, 1]
        else:
            attack_probs = y_proba[:, 0]
    else:
        attack_probs = y_pred.astype(float)

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)

    observed_count = int((attack_probs >= AI_OBSERVE_THRESHOLD).sum())
    warning_count = int((attack_probs >= AI_WARNING_THRESHOLD).sum())
    blocked_count = int((attack_probs >= AI_BLOCK_THRESHOLD).sum())

    print("\n=============================================")
    print(" V-GUARD MODEL PERFORMANCE")
    print("=============================================")
    print(f" Accuracy : %{accuracy * 100:.2f}")
    print(f" Precision: %{precision * 100:.2f}")
    print(f" Recall   : %{recall * 100:.2f}")
    print(f" F1 Score : %{f1 * 100:.2f}")
    print("=============================================\n")

    print("Confusion Matrix:")
    print(cm)

    print("\nProfessional AI Threshold Simulation:")
    print(f" OBSERVE threshold %{AI_OBSERVE_THRESHOLD * 100:.0f}+ -> {observed_count} test sample")
    print(f" WARNING threshold %{AI_WARNING_THRESHOLD * 100:.0f}+ -> {warning_count} test sample")
    print(f" BLOCK threshold   %{AI_BLOCK_THRESHOLD * 100:.0f}+ -> {blocked_count} test sample")

    print("\nDetaylı Classification Report:")
    print(
        classification_report(
            y_test,
            y_pred,
            target_names=["Normal Trafik (0)", "Siber Saldırı (1)"],
            zero_division=0
        )
    )

    return {
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1),
        "confusion_matrix": cm.tolist(),
        "threshold_simulation": {
            "observe_threshold": float(AI_OBSERVE_THRESHOLD),
            "warning_threshold": float(AI_WARNING_THRESHOLD),
            "block_threshold": float(AI_BLOCK_THRESHOLD),
            "observed_samples": observed_count,
            "warning_samples": warning_count,
            "blocked_samples": blocked_count
        }
    }


def get_feature_importance(model):
    print("\n=============================================")
    print(" FEATURE IMPORTANCE")
    print("=============================================")

    if not hasattr(model, "feature_importances_"):
        print("[!] Bu model feature_importances_ desteklemiyor.")
        return {}

    importances = model.feature_importances_

    feature_scores = sorted(
        zip(FEATURE_COLUMNS, importances),
        key=lambda item: item[1],
        reverse=True
    )

    for feature, score in feature_scores:
        print(f" {feature:<10}: {score:.4f}")

    print("=============================================\n")

    return {
        feature: float(score)
        for feature, score in feature_scores
    }


def save_model_bundle(model, metrics, feature_importance, df):
    """
    dpi_engine.py artık düz model değil, model bundle okuyor.
    Bu sayede threshold, feature listesi ve metadata tek dosyada taşınır.
    """
    created_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    model_bundle = {
        "project": "v-Guard",
        "model": model,
        "model_type": "RandomForestClassifier",
        "created_at": created_at,

        "feature_columns": FEATURE_COLUMNS,
        "label_column": LABEL_COLUMN,

        "observe_threshold": AI_OBSERVE_THRESHOLD,
        "warning_threshold": AI_WARNING_THRESHOLD,
        "block_threshold": AI_BLOCK_THRESHOLD,

        "random_state": RANDOM_STATE,
        "test_size": TEST_SIZE,

        "dataset_summary": {
            "total_records": int(len(df)),
            "normal_records": int((df[LABEL_COLUMN] == 0).sum()),
            "attack_records": int((df[LABEL_COLUMN] == 1).sum())
        },

        "metrics": metrics,
        "feature_importance": feature_importance,

        "notes": (
            "This is a v-Guard AI model bundle. "
            "dpi_engine.py uses predict_proba to make staged IDS/IPS decisions. "
            "Observe and warning events are logged without banning. "
            "Only critical AI confidence levels trigger packet blocking and temporary IP ban."
        )
    }

    try:
        joblib.dump(model_bundle, MODEL_FILE)
    except Exception as e:
        fail(f"Model bundle kaydedilemedi: {e}")

    print(f"[+] Yapay zeka model paketi kaydedildi:")
    print(f"    {MODEL_FILE}")


def save_report(metrics, feature_importance, df):
    report = {
        "project": "v-Guard",
        "model": "RandomForestClassifier",
        "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

        "dataset_file": os.path.basename(DATASET_FILE),
        "model_file": os.path.basename(MODEL_FILE),

        "features": FEATURE_COLUMNS,
        "label": LABEL_COLUMN,

        "random_state": RANDOM_STATE,
        "test_size": TEST_SIZE,

        "ai_decision_thresholds": {
            "observe_threshold": AI_OBSERVE_THRESHOLD,
            "warning_threshold": AI_WARNING_THRESHOLD,
            "block_threshold": AI_BLOCK_THRESHOLD
        },

        "dataset_summary": {
            "total_records": int(len(df)),
            "normal_records": int((df[LABEL_COLUMN] == 0).sum()),
            "attack_records": int((df[LABEL_COLUMN] == 1).sum())
        },

        "metrics": metrics,
        "feature_importance": feature_importance,

        "decision_policy": {
            "normal": "Traffic is allowed.",
            "observe": "Suspicious traffic is logged only.",
            "warning": "Higher risk traffic is logged as warning but not blocked.",
            "block": "Critical AI confidence triggers packet blocking and temporary IP ban."
        },

        "important_note": (
            "Security models should not be evaluated with accuracy alone. "
            "Recall, precision, F1 score, confusion matrix and threshold behavior should be reviewed. "
            "The current feature format is designed to stay compatible with the live v-Guard DPI engine."
        )
    }

    try:
        with open(REPORT_FILE, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4, ensure_ascii=False)

    except Exception as e:
        fail(f"Model raporu kaydedilemedi: {e}")

    print(f"[+] Model raporu kaydedildi:")
    print(f"    {REPORT_FILE}")


def split_dataset(X, y):
    try:
        return train_test_split(
            X,
            y,
            test_size=TEST_SIZE,
            random_state=RANDOM_STATE,
            stratify=y
        )

    except ValueError:
        print("[!] Stratify uygulanamadı. Normal split ile devam ediliyor.")

        return train_test_split(
            X,
            y,
            test_size=TEST_SIZE,
            random_state=RANDOM_STATE
        )


def main():
    df = load_dataset()
    df = validate_dataset(df)

    print_dataset_summary(df)

    X = df[FEATURE_COLUMNS].values
    y = df[LABEL_COLUMN].values

    X_train, X_test, y_train, y_test = split_dataset(X, y)

    print("[*] Eğitim/Test bölünmesi tamamlandı.")
    print(f"    Train size: {len(X_train)}")
    print(f"    Test size : {len(X_test)}")

    model = train_model(X_train, y_train)

    metrics = evaluate_model(model, X_test, y_test)
    feature_importance = get_feature_importance(model)

    save_model_bundle(model, metrics, feature_importance, df)
    save_report(metrics, feature_importance, df)

    print("\n[*] Eğitim tamamlandı.")
    print("[*] Yeni model bundle formatı oluşturuldu.")
    print("[*] Artık DPI motorunu başlatabilirsin:")
    print("    sudo .venv/bin/python dpi_engine.py")


if __name__ == "__main__":
    main()