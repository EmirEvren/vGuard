# v-Guard AI Evaluation Summary

## Model Overview

- Project: v-Guard
- Model: RandomForestClassifier
- Created at: 2026-09-05 05:16:53
- Dataset file: dataset.csv
- Model file: vguard_brain.pkl

## Dataset Summary

- Total records: 600
- Normal records: 300
- Attack records: 300

## Model Metrics

| Metric | Value |
|---|---:|
| Accuracy | 100.00% |
| Precision | 100.00% |
| Recall | 100.00% |
| F1 Score | 100.00% |

## Confusion Matrix

| Actual / Predicted | Normal (0) | Attack (1) |
|---|---:|---:|
| Normal (0) | 60 | 0 |
| Attack (1) | 0 | 60 |

## AI Decision Thresholds

| Stage | Threshold | Behavior |
|---|---:|---|
| Observe | 65.00% | Suspicious traffic is logged only. |
| Warning | 80.00% | Higher risk traffic is logged as warning. |
| Block | 92.00% | Critical confidence triggers blocking/ban behavior. |

## Feature Importance

| Feature | Importance |
|---|---:|
| SpChar | 0.4565 |
| Reqs | 0.3230 |
| Size | 0.2076 |
| Entropy | 0.0129 |

## Interpretation

The AI component is used as a staged anomaly scoring layer that complements the signature-based DPI engine. The model output should not be interpreted by accuracy alone. Precision, recall, F1 score, confusion matrix and threshold behavior should be reviewed together. In the final demonstration, the AI model supports the DPI engine by assigning probability-based risk levels while rule-based signatures remain the primary explainable detection mechanism for common attacks.
