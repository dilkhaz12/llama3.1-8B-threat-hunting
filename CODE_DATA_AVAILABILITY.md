# Code/Data Availability

## Implementation Code
The implementation code, including fine-tuning scripts and evaluation pipelines, is available at: https://github.com/dilkhaz12

## Dataset Availability
The synthesized TTP dataset used for training will be released under a research-use license, subject to responsible disclosure guidelines. The base MITRE ATT&CK data is publicly available at https://attack.mitre.org/

## Hyperparameters

| Parameter | Value |
|-----------|-------|
| Base Model | LLaMA-3.1-8B |
| LoRA Rank (r) | 64 |
| LoRA Alpha | 128 |
| LoRA Dropout | 0.05 |
| Learning Rate | 2e-5 |
| Batch Size | 4 |
| Gradient Accumulation Steps | 8 |
| Effective Batch Size | 32 |
| Max Sequence Length | 2048 |
| Training Epochs | 3 |
| Warmup Ratio | 0.1 |
| Weight Decay | 0.01 |
| Optimizer | AdamW |
| LR Scheduler | Cosine |
| Precision | bfloat16 |

## GRPO Training Details

### Group Relative Policy Optimization (GRPO)

GRPO extends standard policy optimization by incorporating group-based reward normalization:

| GRPO Parameter | Value |
|----------------|-------|
| Group Size | 8 |
| KL Coefficient (β) | 0.1 |
| Clip Range | 0.2 |
| Value Function Coefficient | 0.5 |
| Entropy Coefficient | 0.01 |
| Max Grad Norm | 1.0 |
| GRPO Iterations | 1000 |
| Reward Baseline | Group Mean |

### Multi-Dimensional Reward Function

The reward function combines four components:

```
R_total = w1·R_semantic + w2·R_tactical + w3·R_novelty + w4·R_coherence
```

| Reward Component | Weight | Description |
|------------------|--------|-------------|
| Semantic Similarity (R_semantic) | 0.3 | Cosine similarity to known TTP embeddings |
| Tactical Alignment (R_tactical) | 0.3 | Alignment with MITRE ATT&CK tactics |
| Novelty Score (R_novelty) | 0.2 | Divergence from existing techniques |
| Coherence Score (R_coherence) | 0.2 | Linguistic and structural quality |

### Adversarial Training Configuration

| Parameter | Value |
|-----------|-------|
| Perturbation Epsilon (ε) | 0.01 |
| Adversarial Steps | 3 |
| Perturbation Type | FGSM + PGD |
| Adversarial Training Ratio | 0.3 |
