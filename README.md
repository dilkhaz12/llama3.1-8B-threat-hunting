# LLAMA 3.1 8B-based Threat Hunting Framework with GRPO

A novel framework for automated cyber threat hunting using fine-tuned Large Language Models (LLMs) with Group Relative Policy Optimization (GRPO) for discovering novel Tactics, Techniques, and Procedures (TTPs).

## Overview

This repository contains the implementation code for fine-tuning LLAMA 3.1 8B model on cybersecurity threat intelligence data using:
- **QLoRA** (Quantized Low-Rank Adaptation) for efficient fine-tuning
- **GRPO** (Group Relative Policy Optimization) for reward-based learning
- **Adversarial Training** for model robustness
- **Evol-Instruct** methodology for synthetic data generation

## Repository Structure

```
llama3.1-8B-threat-hunting/
├── code/
│   ├── 01_data_preprocessing.py      # MITRE ATT&CK data preprocessing
│   ├── 02_synthetic_data_generation.py # Evol-Instruct data synthesis
│   ├── 03_reward_function.py          # Multi-dimensional reward function
│   ├── 04_adversarial_perturbations.py # Adversarial training module
│   ├── 05_model_training.py           # Main training pipeline
│   ├── 06_evaluation.py               # Evaluation metrics
│   └── main_runner.py                 # Complete pipeline runner
├── data/
│   ├── mitre_attack_v18.json          # MITRE ATT&CK v18 data
│   └── final_datasets/                # Processed training datasets
├── results/
│   └── *.json                         # Evaluation results
├── CODE_DATA_AVAILABILITY.md          # Hyperparameters & GRPO details
└── README.md
```

## Requirements

```bash
pip install torch transformers peft bitsandbytes accelerate datasets trl
```

## Quick Start

```python
# Run the complete pipeline
python code/main_runner.py

# Or run individual steps:
python code/01_data_preprocessing.py
python code/02_synthetic_data_generation.py
python code/05_model_training.py
python code/06_evaluation.py
```

## Hyperparameters

| Parameter | Value |
|-----------|-------|
| Base Model | LLAMA-3.1-8B Instruct|
| LoRA Rank (r) | 64 |
| LoRA Alpha | 128 |
| Learning Rate | 2e-5 |
| Batch Size | 32 (effective) |
| Max Sequence Length | 2048 |
| Training Epochs | 3 |
| Precision | bfloat16 |

## GRPO Configuration

| Parameter | Value |
|-----------|-------|
| Group Size | 8 |
| KL Coefficient (β) | 0.1 |
| Clip Range | 0.2 |
| GRPO Iterations | 1000 |

## Data Sources

- **MITRE ATT&CK**: https://attack.mitre.org/
- **Synthetic TTP Dataset**: Generated using Evol-Instruct methodology

## Citation

If you use this code in your research, please cite:

```bibtex
@article{llama3_threat_hunting,
  title={LLAMA 3.1 8B-based Threat Hunting Framework with GRPO},
  year={2026}
}
```

## License

This project is released under a research-use license, subject to responsible disclosure guidelines.
