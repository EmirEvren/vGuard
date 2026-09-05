# v-Guard AI Evaluation Guide

This guide standardizes the AI/model evaluation part of the v-Guard project.

The v-Guard detection flow is hybrid:

- signature-based DPI detects explainable known attack patterns
- AI probability scoring supports anomaly/risk classification
- staged thresholds map AI confidence to observe, warning and block behavior

The AI component should be defended as a supporting detection layer, not as the only detection method.

## Files involved

```text
data_preprocessor.py          Converts raw CICIDS2017-like flow data into v-Guard features
ai_trainer.py                 Trains RandomForestClassifier and writes model/report files
ensure_vguard_ai_model.py     Creates a demo-compatible model if no dataset is available
vguard_brain.pkl              Model bundle used by dpi_engine.py
vguard_model_report.json      Training metrics and model metadata
vguard_dataset_report.json    Dataset preprocessing report, if generated
RUN_AI_EVALUATION.py          Standard workflow runner added in this step
```

## Expected feature format

The model uses these columns:

```text
Size, Reqs, Entropy, SpChar, Label
```

Where:

- `Size` represents traffic/payload size-like behavior
- `Reqs` represents request or packet-flow volume
- `Entropy` represents payload randomness/complexity
- `SpChar` represents special character density
- `Label` is `0` for normal traffic and `1` for attack traffic

## Recommended workflow with a real/preprocessed dataset

From the project root:

```bash
python RUN_AI_EVALUATION.py
```

This checks for `raw_dataset.csv` or `dataset.csv`.

If `raw_dataset.csv` exists:

```text
raw_dataset.csv -> data_preprocessor.py -> dataset.csv -> ai_trainer.py
```

If `dataset.csv` already exists:

```text
dataset.csv -> ai_trainer.py
```

## Demo-safe workflow

If no dataset is available, use:

```bash
python RUN_AI_EVALUATION.py --demo-safe
```

This runs `ensure_vguard_ai_model.py` so that the DPI engine can still start for a demonstration.

Important: demo-safe mode is suitable for operational demos, but the final report should clearly distinguish it from a full dataset-based supervised evaluation.

## Generated outputs

```text
vguard_brain.pkl
vguard_model_report.json
vguard_ai_evaluation_summary.md
vguard_ai_metrics_table.csv
vguard_ai_confusion_matrix.csv
```

Use these in the final defense:

- `vguard_model_report.json` for exact metrics
- `vguard_ai_evaluation_summary.md` for a readable explanation
- `vguard_ai_metrics_table.csv` for report tables
- `vguard_ai_confusion_matrix.csv` for the confusion matrix table

## Architecture and Model Operation

Suggested wording:

> v-Guard uses a hybrid detection strategy. Signature-based DPI is the primary explainable detection mechanism for known attack patterns such as SQL injection, XSS and path traversal. The AI model is used as a supporting anomaly/risk scoring layer. It receives compact traffic features such as size, request count, entropy and special-character density, and returns a probability score. The score is then mapped into observe, warning or block stages using predefined thresholds.

## Evaluation and Metric Guidelines

Do not evaluate the model using accuracy alone.

Include:

- accuracy
- precision
- recall
- F1 score
- confusion matrix
- threshold behavior

If the dataset was generated through compatibility preprocessing, explain that the feature format was selected to keep the offline dataset and live DPI engine consistent.
