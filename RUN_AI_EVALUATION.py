#!/usr/bin/env python3
"""
v-Guard AI Evaluation Runner

Purpose
-------
This helper script standardizes the AI/model evaluation workflow for the
v-Guard IDS/IPS project.

It supports two modes:

1) Dataset mode:
   If raw_dataset.csv exists, it runs:
     python data_preprocessor.py
     python ai_trainer.py

   This produces:
     dataset.csv
     vguard_dataset_report.json
     vguard_brain.pkl
     vguard_model_report.json

2) Demo-safe mode:
   If raw_dataset.csv is missing, it can still ensure that a demo-compatible
   model bundle exists by running:
     python ensure_vguard_ai_model.py

   This keeps dpi_engine.py usable for demonstrations.

It then reads vguard_model_report.json, if available, and creates:
  - vguard_ai_evaluation_summary.md
  - vguard_ai_metrics_table.csv
  - vguard_ai_confusion_matrix.csv
"""

import argparse
import csv
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional


def run_cmd(cmd, cwd: Path, required: bool = True) -> bool:
    print(f"[*] $ {' '.join(map(str, cmd))}")
    completed = subprocess.run(
        [str(x) for x in cmd],
        cwd=str(cwd),
        text=True,
        capture_output=True,
    )

    if completed.stdout.strip():
        print(completed.stdout.strip())
    if completed.stderr.strip():
        print(completed.stderr.strip())

    if completed.returncode != 0:
        message = f"Command failed with exit code {completed.returncode}: {' '.join(map(str, cmd))}"
        if required:
            raise SystemExit(f"[!] {message}")
        print(f"[!] {message}")
        return False

    return True


def load_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except Exception as exc:
        print(f"[!] Failed to read {path.name}: {exc}")
        return None


def percent(value: Any) -> str:
    try:
        return f"{float(value) * 100:.2f}%"
    except Exception:
        return "-"


def number(value: Any) -> str:
    if value is None:
        return "-"
    try:
        return f"{float(value):.4f}"
    except Exception:
        return str(value)


def write_metrics_csv(project_dir: Path, report: Dict[str, Any]) -> None:
    metrics = report.get("metrics", {}) if isinstance(report.get("metrics"), dict) else {}
    output = project_dir / "vguard_ai_metrics_table.csv"

    rows = [
        ["Metric", "Value"],
        ["Accuracy", number(metrics.get("accuracy"))],
        ["Precision", number(metrics.get("precision"))],
        ["Recall", number(metrics.get("recall"))],
        ["F1 Score", number(metrics.get("f1_score"))],
    ]

    thresholds = report.get("ai_decision_thresholds", {})
    if isinstance(thresholds, dict):
        rows.extend([
            ["Observe Threshold", number(thresholds.get("observe_threshold"))],
            ["Warning Threshold", number(thresholds.get("warning_threshold"))],
            ["Block Threshold", number(thresholds.get("block_threshold"))],
        ])

    with output.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(rows)

    print(f"[+] Wrote {output.name}")


def write_confusion_matrix_csv(project_dir: Path, report: Dict[str, Any]) -> None:
    metrics = report.get("metrics", {}) if isinstance(report.get("metrics"), dict) else {}
    cm = metrics.get("confusion_matrix")
    output = project_dir / "vguard_ai_confusion_matrix.csv"

    with output.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["", "Predicted Normal (0)", "Predicted Attack (1)"])

        if isinstance(cm, list) and len(cm) >= 2 and all(isinstance(row, list) for row in cm[:2]):
            normal_row = cm[0] + [""] * max(0, 2 - len(cm[0]))
            attack_row = cm[1] + [""] * max(0, 2 - len(cm[1]))
            writer.writerow(["Actual Normal (0)", normal_row[0], normal_row[1]])
            writer.writerow(["Actual Attack (1)", attack_row[0], attack_row[1]])
        else:
            writer.writerow(["Actual Normal (0)", "", ""])
            writer.writerow(["Actual Attack (1)", "", ""])

    print(f"[+] Wrote {output.name}")


def write_markdown_summary(project_dir: Path, report: Optional[Dict[str, Any]], dataset_report: Optional[Dict[str, Any]]) -> None:
    output = project_dir / "vguard_ai_evaluation_summary.md"

    if not report:
        output.write_text(
            "# v-Guard AI Evaluation Summary\n\n"
            "No `vguard_model_report.json` file was found. The demo-compatible model may still exist, "
            "but full supervised model metrics require `dataset.csv` and `ai_trainer.py`.\n",
            encoding="utf-8",
        )
        print(f"[+] Wrote {output.name}")
        return

    metrics = report.get("metrics", {}) if isinstance(report.get("metrics"), dict) else {}
    dataset_summary = report.get("dataset_summary", {}) if isinstance(report.get("dataset_summary"), dict) else {}
    feature_importance = report.get("feature_importance", {}) if isinstance(report.get("feature_importance"), dict) else {}
    thresholds = report.get("ai_decision_thresholds", {}) if isinstance(report.get("ai_decision_thresholds"), dict) else {}

    lines = []
    lines.append("# v-Guard AI Evaluation Summary")
    lines.append("")
    lines.append("## Model Overview")
    lines.append("")
    lines.append(f"- Project: {report.get('project', 'v-Guard')}")
    lines.append(f"- Model: {report.get('model', report.get('model_type', 'Unknown'))}")
    lines.append(f"- Created at: {report.get('created_at', '-')}")
    ds_name = Path(str(report.get('dataset_file', 'dataset.csv'))).name
    mdl_name = Path(str(report.get('model_file', 'vguard_brain.pkl'))).name
    lines.append(f"- Dataset file: {ds_name}")
    lines.append(f"- Model file: {mdl_name}")
    lines.append("")
    lines.append("## Dataset Summary")
    lines.append("")
    lines.append(f"- Total records: {dataset_summary.get('total_records', '-')}")
    lines.append(f"- Normal records: {dataset_summary.get('normal_records', '-')}")
    lines.append(f"- Attack records: {dataset_summary.get('attack_records', '-')}")
    lines.append("")
    if dataset_report:
        lines.append("## Preprocessing Report")
        lines.append("")
        for key, value in dataset_report.items():
            if isinstance(value, (str, int, float, bool)):
                lines.append(f"- {key}: {value}")
        lines.append("")
    lines.append("## Model Metrics")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---:|")
    lines.append(f"| Accuracy | {percent(metrics.get('accuracy'))} |")
    lines.append(f"| Precision | {percent(metrics.get('precision'))} |")
    lines.append(f"| Recall | {percent(metrics.get('recall'))} |")
    lines.append(f"| F1 Score | {percent(metrics.get('f1_score'))} |")
    lines.append("")
    lines.append("## Confusion Matrix")
    lines.append("")
    cm = metrics.get("confusion_matrix")
    if isinstance(cm, list) and len(cm) >= 2 and all(isinstance(row, list) for row in cm[:2]):
        n0 = cm[0][0] if len(cm[0]) > 0 else ""
        n1 = cm[0][1] if len(cm[0]) > 1 else ""
        a0 = cm[1][0] if len(cm[1]) > 0 else ""
        a1 = cm[1][1] if len(cm[1]) > 1 else ""
        lines.append("| Actual / Predicted | Normal (0) | Attack (1) |")
        lines.append("|---|---:|---:|")
        lines.append(f"| Normal (0) | {n0} | {n1} |")
        lines.append(f"| Attack (1) | {a0} | {a1} |")
    else:
        lines.append("Confusion matrix was not available in the model report.")
    lines.append("")
    lines.append("## AI Decision Thresholds")
    lines.append("")
    lines.append("| Stage | Threshold | Behavior |")
    lines.append("|---|---:|---|")
    lines.append(f"| Observe | {percent(thresholds.get('observe_threshold'))} | Suspicious traffic is logged only. |")
    lines.append(f"| Warning | {percent(thresholds.get('warning_threshold'))} | Higher risk traffic is logged as warning. |")
    lines.append(f"| Block | {percent(thresholds.get('block_threshold'))} | Critical confidence triggers blocking/ban behavior. |")
    lines.append("")
    lines.append("## Feature Importance")
    lines.append("")
    if feature_importance:
        lines.append("| Feature | Importance |")
        lines.append("|---|---:|")
        for feature, score in sorted(feature_importance.items(), key=lambda item: float(item[1]), reverse=True):
            lines.append(f"| {feature} | {float(score):.4f} |")
    else:
        lines.append("Feature importance was not available.")
    lines.append("")
    lines.append("## Interpretation")
    lines.append("")
    lines.append(
        "The AI component is used as a staged anomaly scoring layer that complements the signature-based DPI engine. "
        "The model output should not be interpreted by accuracy alone. Precision, recall, F1 score, confusion matrix "
        "and threshold behavior should be reviewed together. In the final demonstration, the AI model supports the "
        "DPI engine by assigning probability-based risk levels while rule-based signatures remain the primary "
        "explainable detection mechanism for common attacks."
    )
    lines.append("")

    output.write_text("\n".join(lines), encoding="utf-8")
    print(f"[+] Wrote {output.name}")


def main():
    parser = argparse.ArgumentParser(description="Run and summarize v-Guard AI/model evaluation.")
    parser.add_argument("--project-dir", default=".", help="v-Guard project root. Default: current directory.")
    parser.add_argument("--python", default=sys.executable, help="Python executable to use.")
    parser.add_argument(
        "--demo-safe",
        action="store_true",
        help="If raw_dataset.csv is missing, run ensure_vguard_ai_model.py instead of failing.",
    )
    parser.add_argument(
        "--skip-training",
        action="store_true",
        help="Do not run data_preprocessor.py or ai_trainer.py; only summarize existing reports.",
    )
    args = parser.parse_args()

    project_dir = Path(args.project_dir).resolve()
    py = Path(args.python).resolve() if not Path(args.python).is_absolute() else Path(args.python)

    required = ["ai_trainer.py", "ensure_vguard_ai_model.py"]
    missing = [name for name in required if not (project_dir / name).exists()]
    if missing:
        raise SystemExit(f"[!] Missing required project files: {', '.join(missing)}")

    raw_dataset = project_dir / "raw_dataset.csv"
    dataset = project_dir / "dataset.csv"

    if not args.skip_training:
        if raw_dataset.exists():
            if (project_dir / "data_preprocessor.py").exists():
                print("[*] raw_dataset.csv found. Running data_preprocessor.py...")
                run_cmd([py, "data_preprocessor.py"], cwd=project_dir, required=True)
            else:
                print("[!] raw_dataset.csv exists but data_preprocessor.py is missing.")

            print("[*] Running ai_trainer.py...")
            run_cmd([py, "ai_trainer.py"], cwd=project_dir, required=True)

        elif dataset.exists():
            print("[*] dataset.csv found. Running ai_trainer.py...")
            run_cmd([py, "ai_trainer.py"], cwd=project_dir, required=True)

        elif args.demo_safe:
            print("[*] No raw_dataset.csv or dataset.csv found. Running ensure_vguard_ai_model.py...")
            run_cmd([py, "ensure_vguard_ai_model.py"], cwd=project_dir, required=True)
        else:
            raise SystemExit(
                "[!] No raw_dataset.csv or dataset.csv found.\n"
                "Add a dataset, or run with --demo-safe to create a demo-compatible model."
            )

    report = load_json(project_dir / "vguard_model_report.json")
    dataset_report = load_json(project_dir / "vguard_dataset_report.json")

    write_markdown_summary(project_dir, report, dataset_report)

    if report:
        write_metrics_csv(project_dir, report)
        write_confusion_matrix_csv(project_dir, report)

    print("\n[+] AI evaluation workflow finished.")
    print("[+] Check these files:")
    print("    - vguard_ai_evaluation_summary.md")
    print("    - vguard_ai_metrics_table.csv")
    print("    - vguard_ai_confusion_matrix.csv")
    print("    - vguard_model_report.json")
    print("    - vguard_brain.pkl")


if __name__ == "__main__":
    main()
