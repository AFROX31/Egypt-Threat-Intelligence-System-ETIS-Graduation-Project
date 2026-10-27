# Retired evaluation scripts (2026-10-26)

Kept for the audit trail only. Do not run them and do not quote their numbers.

| Retired | Why | Use instead |
|---|---|---|
| `calibrate_thresholds.py` (+ `threshold_calibration_*`) | Calibrated thresholds for the old additive score. The scorer now uses decision tiers, and each model's thresholds are chosen on the VALIDATION split inside `ml/export_models.py` and stored in the model artifact. | `ml/export_models.py` |
| `evaluate_test_configurations.py` (+ `test_configuration_*`, `test_confusion_matrices.png`, `test_roc_curves.png`) | Compared engine configurations under the old additive scorer, with a binary threshold of 50 and the old (leaky) split. Its "Figure 5.5" chart must not go into Chapter 5. | `evaluation/evaluate_final_system.py` (headline, per-engine and per-group results) |

`evaluation/diagnose_allowlist_recall_impact.py` was a one-off check written for `evaluate_test_configurations.py`; the allowlist question it raised is now measured by `evaluation/measure_allowlist_override.py`. It was left in place.

If the folder is the git repo: from the project root (Command Prompt), so the move is recorded as a rename:

    git mv evaluation/calibrate_thresholds.py evaluation/retired/
    git mv evaluation/evaluate_test_configurations.py evaluation/retired/
