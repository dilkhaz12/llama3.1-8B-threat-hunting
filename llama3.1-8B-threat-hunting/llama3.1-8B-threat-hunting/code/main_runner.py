"""
Main Runner Script for PhD Research
A Domain-Specific LLM for Cyber Threat Hunting Based on LLAMA-3 and MITRE TTPs

Author: PhD Candidate
Date: November 2025

This script orchestrates the complete research pipeline:
1. Data preprocessing (MITRE ATT&CK v18.0)
2. Synthetic data generation (5x expansion)
3. Model fine-tuning with GRPO + QLoRA
4. Comprehensive evaluation
5. Visualization and reporting
"""

import os
import sys
import argparse
from pathlib import Path

# Add code directory to path
sys.path.append('/workspace/code')

# Import modules
from data_preprocessing import MITREDataProcessor
from synthetic_data_generation import SyntheticTTPGenerator
from reward_function import CustomRewardFunction
from adversarial_perturbations import AdversarialPerturbationGenerator
from model_training import TTPModelTrainer
from evaluation import ModelEvaluator


class ResearchPipeline:
    """Complete research pipeline orchestrator."""
    
    def __init__(self, config: dict):
        """Initialize pipeline with configuration."""
        self.config = config
        self.results_dir = Path(config.get('results_dir', '/workspace/results'))
        self.results_dir.mkdir(parents=True, exist_ok=True)
    
    def run_data_preprocessing(self):
        """Step 1: Preprocess MITRE ATT&CK data."""
        print("\n" + "="*100)
        print("STEP 1: DATA PREPROCESSING")
        print("="*100)
        
        processor = MITREDataProcessor(
            mitre_json_path=self.config['mitre_json_path'],
            output_dir=self.config['processed_data_dir'],
            seed=self.config.get('seed', 42)
        )
        
        train_data, test_data = processor.process_all()
        
        print(f"\n✓ Preprocessing complete:")
        print(f"  - Training samples: {len(train_data)}")
        print(f"  - Test samples: {len(test_data)}")
        
        return train_data, test_data
    
    def run_synthetic_generation(self):
        """Step 2: Generate synthetic data (5x expansion)."""
        print("\n" + "="*100)
        print("STEP 2: SYNTHETIC DATA GENERATION")
        print("="*100)
        
        generator = SyntheticTTPGenerator(
            train_data_path=f"{self.config['processed_data_dir']}/train_data.json",
            metadata_path=f"{self.config['processed_data_dir']}/metadata.json",
            output_dir=self.config['processed_data_dir'],
            expansion_factor=self.config.get('expansion_factor', 5),
            use_api=self.config.get('use_llm_api', False)
        )
        
        expanded_data = generator.process_all()
        
        print(f"\n✓ Synthetic generation complete:")
        print(f"  - Expanded dataset: {len(expanded_data)} samples")
        
        return expanded_data
    
    def run_model_training(self):
        """Step 3: Fine-tune model with GRPO."""
        print("\n" + "="*100)
        print("STEP 3: MODEL FINE-TUNING")
        print("="*100)
        
        training_config = {
            'model_name': 'unsloth/llama-3-8b-instruct-bnb-4bit',
            'max_seq_length': 2048,
            'lora_rank': 64,
            'num_epochs': 3,
            'batch_size': 4,
            'grad_accum_steps': 4,
            'learning_rate': 2e-4,
            'seed': self.config.get('seed', 42),
            'adversarial_lambda_init': 0.1,
            'perturbation_ratio_init': 0.05,
            'output_dir': self.config.get('model_output_dir', '/workspace/models/llama3_ttp'),
            'train_data_path': f"{self.config['processed_data_dir']}/train_data_synthetic_5x.json",
            'metadata_path': f"{self.config['processed_data_dir']}/metadata.json",
        }
        
        trainer = TTPModelTrainer(training_config)
        trainer.run_full_pipeline()
        
        print(f"\n✓ Training complete:")
        print(f"  - Model saved to: {training_config['output_dir']}")
    
    def run_evaluation(self):
        """Step 4: Comprehensive evaluation."""
        print("\n" + "="*100)
        print("STEP 4: COMPREHENSIVE EVALUATION")
        print("="*100)
        
        evaluator = ModelEvaluator(
            test_data_path=f"{self.config['processed_data_dir']}/test_data.json",
            metadata_path=f"{self.config['processed_data_dir']}/metadata.json",
            output_dir=self.results_dir,
            model=None  # Load fine-tuned model here
        )
        
        original_stats, robustness_metrics = evaluator.run_full_evaluation()
        
        print(f"\n✓ Evaluation complete:")
        print(f"  - Results saved to: {self.results_dir}")
        
        return original_stats, robustness_metrics
    
    def run_complete_pipeline(self, skip_steps=None):
        """
        Execute complete research pipeline.
        
        Args:
            skip_steps: List of steps to skip (e.g., ['preprocessing', 'synthetic'])
        """
        skip_steps = skip_steps or []
        
        print("\n" + "="*100)
        print("PhD RESEARCH: DOMAIN-SPECIFIC LLM FOR CYBER THREAT HUNTING")
        print("Complete Pipeline Execution")
        print("="*100)
        
        # Step 1: Data Preprocessing
        if 'preprocessing' not in skip_steps:
            self.run_data_preprocessing()
        else:
            print("\n[SKIPPED] Step 1: Data Preprocessing")
        
        # Step 2: Synthetic Data Generation
        if 'synthetic' not in skip_steps:
            self.run_synthetic_generation()
        else:
            print("\n[SKIPPED] Step 2: Synthetic Data Generation")
        
        # Step 3: Model Training
        if 'training' not in skip_steps:
            self.run_model_training()
        else:
            print("\n[SKIPPED] Step 3: Model Training (requires GPU)")
        
        # Step 4: Evaluation
        if 'evaluation' not in skip_steps:
            self.run_evaluation()
        else:
            print("\n[SKIPPED] Step 4: Evaluation")
        
        print("\n" + "="*100)
        print("PIPELINE EXECUTION COMPLETE")
        print("="*100)
        print(f"\nResults available in: {self.results_dir}")


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description='PhD Research: Domain-Specific LLM for Cyber Threat Hunting'
    )
    
    parser.add_argument('--skip', nargs='*', default=[],
                       help='Steps to skip (preprocessing, synthetic, training, evaluation)')
    parser.add_argument('--config', type=str, default=None,
                       help='Path to custom configuration JSON')
    
    args = parser.parse_args()
    
    # Default configuration
    config = {
        'mitre_json_path': '/workspace/data/mitre_attack_v18.json',
        'processed_data_dir': '/workspace/data/processed',
        'model_output_dir': '/workspace/models/llama3_ttp',
        'results_dir': '/workspace/results',
        'expansion_factor': 5,
        'seed': 42,
        'use_llm_api': False,  # Set to True if you have API access
    }
    
    # Load custom config if provided
    if args.config:
        import json
        with open(args.config, 'r') as f:
            custom_config = json.load(f)
        config.update(custom_config)
    
    # Initialize and run pipeline
    pipeline = ResearchPipeline(config)
    pipeline.run_complete_pipeline(skip_steps=args.skip)


if __name__ == "__main__":
    main()
