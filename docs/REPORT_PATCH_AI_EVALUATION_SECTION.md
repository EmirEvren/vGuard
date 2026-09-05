# Report Patch: AI Evaluation Section

You can paste/adapt this section into Chapter 6 or Chapter 7 of the final report.

## AI-Based Anomaly Scoring and Evaluation

In addition to signature-based deep packet inspection, v-Guard includes an AI-assisted anomaly scoring component. The purpose of this component is to provide a probability-based risk score that complements the rule-based detection engine. While signature-based detection provides explainable matching for known attack patterns, the AI model supports the detection flow by evaluating compact traffic features and assigning a staged risk level.

The implemented model uses a supervised machine learning approach based on a Random Forest classifier. The input feature vector consists of `Size`, `Reqs`, `Entropy` and `SpChar`. These features represent traffic size behavior, request volume, payload entropy and special-character density. The label column represents the traffic class, where `0` indicates normal traffic and `1` indicates attack traffic.

The trained model is saved as a model bundle in `vguard_brain.pkl`. This bundle stores the classifier, feature list, metadata and decision thresholds. The DPI engine loads this bundle during startup and uses probability estimates to support staged IDS/IPS decisions. Three AI thresholds are used: observe, warning and block. Observe-level events are logged without prevention, warning-level events are highlighted as higher risk, and block-level events may trigger prevention behavior when the confidence is critical.

The evaluation process produces `vguard_model_report.json`, which includes accuracy, precision, recall, F1 score, confusion matrix, feature importance and threshold simulation results. Since security models should not be assessed using accuracy alone, precision, recall, F1 score and confusion matrix values are reviewed together. This is important because false negatives may allow attacks to pass undetected, while false positives may unnecessarily disrupt legitimate traffic.

In the final prototype, the AI component is treated as a supporting anomaly/risk scoring layer rather than a replacement for signature-based DPI. This hybrid approach improves flexibility while preserving explainability for common web attack patterns such as SQL injection, cross-site scripting and path traversal. The generated AI evaluation artifacts are used together with runtime log exports to demonstrate both model behavior and operational IDS/IPS behavior.
