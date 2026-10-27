# AIC211 - Attack & Defend Research Findings

Date: 2026-10-27
Research branch: research/attack-defense

## 1. Summary

| Experiment | Metric | Eligible URLs | Before | After |
|---|---|---:|---:|---:|
| T1 vs D1 | Evasion proxy | 667 | 31.18% | 21.14% |
| T7 vs D2 | Flip-down rate | 504 | 9.33% | 0.00% |

## 2. D1 and D2 - Detailed Results

| Experiment | Model | Metric | Eligible | Before | After |
|---|---|---|---:|---:|---:|
| T1_D1 | LR-F2-PhishingAware | evasion_proxy | 502 | 27.89% | 21.51% |
| T1_D1 | XGB-F1-D3 | evasion_proxy | 503 | 25.25% | 19.88% |
| T1_D1 | XGB-F1 Baseline | evasion_proxy | 513 | 39.96% | 25.15% |
| T1_D1 | LR-F2-MultiSource | evasion_proxy | 428 | 27.80% | 19.16% |
| T1_D1 | LR-F1F2-Robust | evasion_proxy | 428 | 28.97% | 21.96% |
| T1_D1 | VOTING 2/5 | evasion_proxy | 667 | 31.18% | 21.14% |
| T7_D2 | LR-F2-PhishingAware | flip_down | 348 | 18.97% | 0.00% |
| T7_D2 | XGB-F1-D3 | flip_down | 354 | 28.53% | 0.00% |
| T7_D2 | XGB-F1 Baseline | flip_down | 359 | 32.87% | 0.00% |
| T7_D2 | LR-F2-MultiSource | flip_down | 283 | 2.47% | 0.00% |
| T7_D2 | LR-F1F2-Robust | flip_down | 283 | 6.71% | 0.00% |
| T7_D2 | VOTING 2/5 | flip_down | 504 | 9.33% | 0.00% |

## 3. D3 - Paired XGBoost Comparison

| Model | Common detected | Lost alerts | Flip-down | Paired wins |
|---|---:|---:|---:|---:|
| XGB-F1 Baseline | 499 | 190 | 38.08% | 6 |
| XGB-F1-D3 | 499 | 124 | 24.85% | 72 |

## 4. Experimental Method

- Data: test_A.csv, 1,000 sampled malicious URLs, random seed 42.
- T1/D1: Compare original and T1-transformed URLs with and without canonicalization.
- T7/D2: Compare original and homoglyph/Punycode-transformed URLs using IDNA decoding and homoglyph normalization.
- D3: Compare XGB-F1 Baseline and XGB-F1-D3 on the same 499 initially detected URLs.
- Website voting rule: suspicious when at least 2 of 5 models flag the URL.

## 5. FPR Observations

- Earlier terminal tests on 1,000 benign URLs reported voting FPR = 2.60% before and after D1.
- The same benign sample reported voting FPR = 2.60% before and after D2.
- D2 changed 0 of those 1,000 benign URLs.
- These FPR observations need reproducible row-level logs before final reporting.

## 6. Limitations

- T1 evasion results assume the modified URL retains the malicious behavior of the original.
- T7 can change the actual registered domain; a changed domain does not automatically retain its original label.
- IDNA + D2 restored 814/814 evaluated T7 URLs exactly. This explains the 0% flip-down result but does not establish real-world protection effectiveness.
- The provenance and training data of xgb_f1_d3.joblib have not been independently verified.
- D1, D2 and D3 results use different eligible samples and must not be directly ranked as equivalent metrics.
- The experiments do not establish that the five-model website can safely classify every URL.

## 7. Next Steps

1. Verify model D3 training provenance.
2. Evaluate benign Unicode/Punycode URLs for D2 false positives.
3. Save reproducible per-URL evaluation outputs.
4. Prepare final charts and presentation tables.

## 8. Research Figures

### Figure 1. T1 Attack vs D1 Defense

![T1 Attack vs D1 Defense](figures/t1_d1_comparison.png)

*Figure 1. Evasion proxy before and after D1 canonicalization.*

### Figure 2. T7 Attack vs D2 Defense

![T7 Attack vs D2 Defense](figures/t7_d2_comparison.png)

*Figure 2. Flip-down rate before and after IDNA decoding and D2 normalization. Restoring URL strings does not establish real-world attack prevention.*

### Figure 3. XGBoost Baseline vs D3

![XGBoost Baseline vs D3](figures/d3_xgboost_comparison.png)

*Figure 3. Paired T1 evaluation on 499 commonly detected URLs. D3 training provenance remains unverified.*

