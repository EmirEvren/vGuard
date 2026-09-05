import os
import sys
import json
import datetime
import pandas as pd
import numpy as np


# ============================================================
# v-Guard Data Preprocessor
#
# Converts raw CICIDS2017 flow dataset into v-Guard ML format:
# Size, Reqs, Entropy, SpChar, Label
#
# Output:
# - dataset.csv
# - vguard_dataset_report.json
#
# NOTE:
# CICIDS2017 is a flow-based dataset. It does not contain raw HTTP
# payload strings. The live DPI engine extracts Entropy and SpChar
# from real payload text, so this preprocessor creates compatible
# synthetic payload-like features for training/demo compatibility.
# ============================================================


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

RAW_DATASET_FILE = os.path.join(BASE_DIR, "raw_dataset.csv")
OUTPUT_DATASET_FILE = os.path.join(BASE_DIR, "dataset.csv")
DATASET_REPORT_FILE = os.path.join(BASE_DIR, "vguard_dataset_report.json")

RANDOM_SEED = 42
np.random.seed(RANDOM_SEED)


REQUIRED_COLUMNS = [
    "Total Length of Fwd Packets",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Duration",
    "Label"
]

OUTPUT_COLUMNS = [
    "Size",
    "Reqs",
    "Entropy",
    "SpChar",
    "Label"
]


def fail(message):
    print(f"[!] ERROR: {message}")
    sys.exit(1)


def load_raw_dataset():
    print("[*] Initializing V-Guard Data Preprocessor...")
    print("[*] Reading raw CICIDS2017 dataset...")

    if not os.path.exists(RAW_DATASET_FILE):
        fail(
            f"'raw_dataset.csv' not found.\n"
            f"Expected path: {RAW_DATASET_FILE}\n"
            f"Please place the CICIDS2017 CSV file in the same folder and rename it to raw_dataset.csv."
        )

    try:
        df_raw = pd.read_csv(
            RAW_DATASET_FILE,
            skipinitialspace=True,
            low_memory=False
        )
    except Exception as e:
        fail(f"Failed to read raw dataset: {e}")

    df_raw.columns = df_raw.columns.str.strip()

    print(f"[+] Successfully loaded {len(df_raw)} network flow records.")

    return df_raw


def validate_columns(df_raw):
    missing_columns = [
        col for col in REQUIRED_COLUMNS
        if col not in df_raw.columns
    ]

    if missing_columns:
        print("[!] Missing required columns:")
        for col in missing_columns:
            print(f"    - {col}")

        print("\n[*] Available columns in your CSV:")
        for col in df_raw.columns:
            print(f"    - {col}")

        fail("Dataset format is not compatible with this preprocessor.")


def safe_numeric(series):
    """
    Converts a pandas Series to numeric.
    Invalid values become 0.
    """
    return pd.to_numeric(series, errors="coerce").fillna(0)


def normalize_labels(label_series):
    """
    BENIGN -> 0
    Anything else -> 1
    """
    labels = label_series.astype(str).str.strip().str.upper()
    is_attack = labels != "BENIGN"
    return labels, is_attack


def build_processed_dataset(df_raw):
    print("[*] Translating flow features to V-Guard DPI payload feature format...")

    df_processed = pd.DataFrame()

    total_fwd_length = safe_numeric(df_raw["Total Length of Fwd Packets"])
    total_fwd_packets = safe_numeric(df_raw["Total Fwd Packets"])
    total_bwd_packets = safe_numeric(df_raw["Total Backward Packets"])
    flow_duration = safe_numeric(df_raw["Flow Duration"])

    labels, is_attack = normalize_labels(df_raw["Label"])

    # ------------------------------------------------------------
    # Feature 1: Size
    # Average forward packet size.
    # +1 prevents division by zero.
    # ------------------------------------------------------------
    df_processed["Size"] = (
        total_fwd_length / (total_fwd_packets + 1)
    ).replace([np.inf, -np.inf], 0).fillna(0).clip(0, 100000).astype(int)

    # ------------------------------------------------------------
    # Feature 2: Reqs
    # Approximate packets per second.
    # CICIDS2017 Flow Duration is in microseconds.
    # ------------------------------------------------------------
    duration_sec = (flow_duration / 1_000_000) + 0.0001
    total_packets = total_fwd_packets + total_bwd_packets

    df_processed["Reqs"] = (
        total_packets / duration_sec
    ).replace([np.inf, -np.inf], 0).fillna(0).clip(0, 500).astype(int)

    # ------------------------------------------------------------
    # Feature 3: Entropy
    # Synthetic payload-like entropy feature.
    # Attack samples receive higher entropy-like distribution.
    # Normal samples receive lower entropy-like distribution.
    # ------------------------------------------------------------
    df_processed["Entropy"] = np.where(
        is_attack,
        np.random.normal(loc=6.5, scale=0.8, size=len(df_raw)).clip(5.0, 7.9),
        np.random.normal(loc=3.0, scale=0.5, size=len(df_raw)).clip(1.0, 4.5)
    )

    # ------------------------------------------------------------
    # Feature 4: SpChar
    # Synthetic special-character-ratio-like feature.
    # This simulates payload characteristics such as SQLi/XSS symbols.
    # ------------------------------------------------------------
    df_processed["SpChar"] = np.where(
        is_attack,
        np.random.normal(loc=0.20, scale=0.08, size=len(df_raw)).clip(0.08, 0.45),
        np.random.normal(loc=0.01, scale=0.01, size=len(df_raw)).clip(0.0, 0.04)
    )

    # ------------------------------------------------------------
    # Label
    # 0 = Normal
    # 1 = Attack
    # ------------------------------------------------------------
    df_processed["Label"] = is_attack.astype(int)

    # Keep exact trainer-compatible order
    df_processed = df_processed[OUTPUT_COLUMNS]

    # Final cleanup
    df_processed.replace([np.inf, -np.inf], np.nan, inplace=True)
    df_processed.fillna(0, inplace=True)

    return df_processed, labels


def print_dataset_summary(df_processed, original_labels):
    total_rows = len(df_processed)
    normal_count = int((df_processed["Label"] == 0).sum())
    attack_count = int((df_processed["Label"] == 1).sum())

    print("\n=============================================")
    print(" v-Guard Dataset Summary")
    print("=============================================")
    print(f" Total records : {total_rows}")
    print(f" Normal traffic: {normal_count}")
    print(f" Attack traffic: {attack_count}")

    if total_rows > 0:
        print(f" Attack ratio  : %{(attack_count / total_rows) * 100:.2f}")

    print("=============================================\n")

    print("[*] Generated columns:")
    for col in df_processed.columns:
        print(f"    - {col}")

    print("\n[*] Original label distribution:")
    label_counts = original_labels.value_counts().head(20)

    for label, count in label_counts.items():
        print(f"    - {label}: {count}")


def save_processed_dataset(df_processed):
    try:
        df_processed.to_csv(OUTPUT_DATASET_FILE, index=False)
    except Exception as e:
        fail(f"Failed to write dataset.csv: {e}")

    print(f"\n[+] Success! Processed dataset saved:")
    print(f"    {OUTPUT_DATASET_FILE}")


def save_dataset_report(df_processed, original_labels):
    total_rows = len(df_processed)
    normal_count = int((df_processed["Label"] == 0).sum())
    attack_count = int((df_processed["Label"] == 1).sum())

    label_distribution = {
        str(label): int(count)
        for label, count in original_labels.value_counts().items()
    }

    report = {
        "project": "v-Guard",
        "report_type": "Dataset Preprocessing Report",
        "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "raw_dataset_file": RAW_DATASET_FILE,
        "output_dataset_file": OUTPUT_DATASET_FILE,
        "random_seed": RANDOM_SEED,
        "required_columns": REQUIRED_COLUMNS,
        "output_columns": OUTPUT_COLUMNS,
        "summary": {
            "total_records": total_rows,
            "normal_records": normal_count,
            "attack_records": attack_count,
            "attack_ratio": float((attack_count / total_rows) if total_rows > 0 else 0.0)
        },
        "original_label_distribution": label_distribution,
        "feature_mapping": {
            "Size": "Average forward packet size calculated from CICIDS2017 flow fields.",
            "Reqs": "Approximate packets per second calculated from flow duration and packet counts.",
            "Entropy": "Synthetic payload-like entropy feature generated for compatibility with live DPI engine.",
            "SpChar": "Synthetic special-character-ratio-like feature generated for compatibility with live DPI engine.",
            "Label": "0 for BENIGN traffic, 1 for any non-BENIGN attack label."
        },
        "important_note": (
            "CICIDS2017 is a flow-based dataset and does not include raw HTTP payload text. "
            "The live v-Guard DPI engine calculates Entropy and SpChar from real payload text. "
            "This preprocessor generates synthetic payload-like Entropy and SpChar values to keep "
            "offline model training compatible with the live engine feature format."
        )
    }

    try:
        with open(DATASET_REPORT_FILE, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
    except Exception as e:
        fail(f"Failed to write dataset report: {e}")

    print(f"[+] Dataset report saved:")
    print(f"    {DATASET_REPORT_FILE}")


def main():
    df_raw = load_raw_dataset()
    validate_columns(df_raw)

    df_processed, original_labels = build_processed_dataset(df_raw)

    print_dataset_summary(df_processed, original_labels)
    save_processed_dataset(df_processed)
    save_dataset_report(df_processed, original_labels)

    print("\n[*] V-Guard AI trainer is now ready to run.")
    print("[*] Next command:")
    print("    python ai_trainer.py")


if __name__ == "__main__":
    main()