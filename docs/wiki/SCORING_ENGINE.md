# Scoring Engine (High Level)

This project uses a deterministic, weighted scoring matrix to convert evidence into a reproducible risk score (0–100) and classification.

## Core Equation

```
RiskScore = SUM(weight * confidence)
FinalScore = normalize(RiskScore, 0..100)
```

- `weight`: static value from the matrix (severity of the indicator).
- `confidence`: 0.0–1.0 based on evidence certainty.
- `FinalScore`: normalized to a 0–100 range.

## Classification Thresholds

| Classification | Score Range |
|----------------|-------------|
| Benign | 0–20 |
| Suspicious | 21–60 |
| Malicious | 61–100 |

## Evidence Dimensions (Inputs)

- Threat Intelligence (TI)
- Behavioral Baseline Deviation
- MITRE ATT&CK Alignment
- Process & Execution Context
- Identity & Privilege Context
- Network Context
- Detection Logic Confidence

Each evidence item is mapped to one dimension and scored as:
- **Contribution = weight * confidence**
- Contributions are summed for the final score.

## Determinism Guarantees

- No speculative scoring.
- Every score contribution maps to a specific evidence item.
- The same evidence yields the same score.

## Output Format (Decision Agent)

The final decision response includes:
- Summary paragraph (4–6 sentences)
- Evidence table (category, evidence, weight, confidence, contribution)
- Final score (0–100)
- Final classification (Benign/Suspicious/Malicious)
- Recommended action (Close/Escalate/Contain)
