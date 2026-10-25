# Model Diagnostics - Malicious URL Detection

## 1. XGB-F1: Root Path Artifact

- Baseline XGB-F1 prediction flip rate: 97.89%
- XGB-F1-V2 prediction flip rate: 0.00%
- XGB-F1-V3 prediction flip rate: 0.17%
- Root path formatting strongly affects baseline predictions.
- V2 and V3 improve root-slash stability but reduce recall.

## 2. LR-F2: WWW Dataset Artifact

WWW frequency:

| Dataset | Benign | Malicious |
|---|---:|---:|
| Train | 2.86% | 31.19% |
| Validation A | 2.22% | 34.78% |
| Source B | 80.29% | 0.45% |

Strong positive LR-F2 coefficients:
- www: +12.9331
- www.: +10.1772
- ww.: +9.9663

## 3. LR-F2 vs LR-F2-NoWWW

| Metric | Original LR-F2 | LR-F2-NoWWW |
|---|---:|---:|
| Validation A Recall | 61.82% | 47.34% |
| Validation A F1 | 74.02% | 62.06% |
| Source B Recall | 92.69% | 92.63% |
| Source B FPR | 30.88% | 3.39% |

## 4. Ensemble Exploration

| Original LR-F2 Weight | Validation Recall | Source B Recall | Source B FPR |
|---|---:|---:|---:|
| 25% | 52.41% | 93.84% | 5.91% |
| 50% | 56.46% | 94.15% | 8.99% |

Both ensemble configurations still flag official GitHub and Google URLs.

## 5. Research Conclusion

- Dataset formatting artifacts can strongly affect URL classification.
- Improving robustness to one formatting artifact may reduce recall.
- No investigated model is clearly superior across all datasets.
- Source B and Test A have been inspected during model development.
- Results on these datasets are exploratory for new variants.
- A fresh, independently labeled, domain-disjoint holdout is
  necessary before final model selection.
- Keep baseline and defended models unchanged for comparison.
