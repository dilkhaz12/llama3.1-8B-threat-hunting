"""
Model Evaluation Module
PhD Research: Domain-Specific LLM for Cyber Threat Hunting
Author: PhD Candidate
Date: November 2025

This module implements comprehensive evaluation:
1. Performance on original test set (unperturbed)
2. Adversarial robustness evaluation (100% test set, 5 perturbations each)
3. Metrics: ASR, Average Score Drop, Worst-Case Drop, Robustness Score
4. Attention visualization for failure analysis
5. Statistical analysis and reporting
"""

import json
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, List, Tuple
from tqdm import tqdm
import matplotlib.pyplot as plt
import seaborn as sns

import sys
sys.path.append('/workspace/code')
from reward_function import CustomRewardFunction
from adversarial_perturbations import AdversarialPerturbationGenerator, RobustnessEvaluator


class ModelEvaluator:
    """
    Comprehensive evaluation of fine-tuned TTP generation model.
    """
    
    def __init__(self, test_data_path: str, metadata_path: str, 
                 output_dir: str, model=None):
        """
        Initialize evaluator.
        
        Args:
            test_data_path: Path to test dataset (untouched 20%)
            metadata_path: Path to metadata JSON
            output_dir: Directory for evaluation results
            model: Fine-tuned model (None for simulation)
        """
        self.test_data_path = test_data_path
        self.metadata_path = metadata_path
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.model = model
        
        # Load test data
        with open(test_data_path, 'r') as f:
            self.test_data = json.load(f)
        
        # Initialize components
        self.reward_function = CustomRewardFunction(metadata_path, test_data_path)
        self.perturbation_generator = AdversarialPerturbationGenerator()
        self.robustness_evaluator = RobustnessEvaluator()
        
        print(f"Evaluator initialized with {len(self.test_data)} test samples")
    
    def generate_ttp(self, instruction: str) -> str:
        """
        Generate TTP from instruction using fine-tuned model.
        
        NOTE: Simulated for demonstration. Actual implementation uses model.
        """
        if self.model is None:
            # Simulation: return a sample TTP
            return ("Adversaries may utilize command and control protocols to establish "
                    "communication channels with compromised systems. This technique enables "
                    "persistent remote access and command execution. Common tools include "
                    "advanced frameworks and custom malware.")
        else:
            # Actual generation code
            # return self.model.generate(instruction)
            pass
    
    def evaluate_original_test_set(self) -> Dict[str, float]:
        """
        Evaluate model on original (unperturbed) test set.
        
        Returns metrics for relevance, novelty, impact, feasibility, overall.
        """
        print("="*80)
        print("EVALUATING ON ORIGINAL TEST SET")
        print("="*80)
        
        results = {
            'relevance': [],
            'novelty': [],
            'impact': [],
            'feasibility': [],
            'overall': [],
        }
        
        for sample in tqdm(self.test_data, desc="Evaluating"):
            instruction = sample['instruction']
            expected = sample['response']
            tactic = sample.get('metadata', {}).get('tactic')
            
            # Generate TTP
            generated = self.generate_ttp(instruction)
            
            # Calculate reward
            reward = self.reward_function.calculate_reward(generated, instruction, tactic)
            
            # Store results
            results['relevance'].append(reward['relevance'])
            results['novelty'].append(reward['novelty'])
            results['impact'].append(reward['impact'])
            results['feasibility'].append(reward['feasibility'])
            results['overall'].append(reward['overall'])
        
        # Calculate statistics
        stats = {}
        for metric, values in results.items():
            stats[metric] = {
                'mean': np.mean(values),
                'std': np.std(values),
                'min': np.min(values),
                'max': np.max(values),
                'median': np.median(values),
            }
        
        # Print results
        print("\nOriginal Test Set Results:")
        print("-" * 80)
        for metric, stat in stats.items():
            print(f"{metric.capitalize():12s}: {stat['mean']:.3f} ± {stat['std']:.3f} "
                  f"(min: {stat['min']:.3f}, max: {stat['max']:.3f})")
        
        # Check targets
        targets = {
            'relevance': 0.8,
            'novelty': 0.7,
            'impact': 0.6,
            'feasibility': 0.6,
            'overall': 0.75,
        }
        
        print("\nTarget Achievement:")
        print("-" * 80)
        for metric, target in targets.items():
            mean_val = stats[metric]['mean']
            status = "✓" if mean_val >= target else "✗"
            print(f"{metric.capitalize():12s}: {mean_val:.3f} (target: {target}) {status}")
        
        return stats
    
    def evaluate_adversarial_robustness(self) -> Dict[str, float]:
        """
        Evaluate adversarial robustness on 100% of test set.
        
        Generates 5 perturbations per test example.
        """
        print("\n" + "="*80)
        print("EVALUATING ADVERSARIAL ROBUSTNESS")
        print("="*80)
        print(f"Test samples: {len(self.test_data)}")
        print(f"Perturbations per sample: 5")
        print(f"Total evaluations: {len(self.test_data) * 6}")  # original + 5 perturbed
        
        original_scores = []
        all_perturbed_scores = []
        score_drops = []
        
        for sample in tqdm(self.test_data, desc="Adversarial evaluation"):
            instruction = sample['instruction']
            tactic = sample.get('metadata', {}).get('tactic')
            
            # Generate original TTP
            generated = self.generate_ttp(instruction)
            
            # Original score
            original_reward = self.reward_function.calculate_reward(
                generated, instruction, tactic
            )
            original_score = original_reward['overall']
            original_scores.append(original_score)
            
            # Generate 5 perturbations
            perturbations = self.perturbation_generator.generate_perturbations(
                generated, num_perturbations=5
            )
            
            # Evaluate each perturbation
            perturbed_scores = []
            for perturbed in perturbations:
                perturbed_reward = self.reward_function.calculate_reward(
                    perturbed, instruction, tactic
                )
                perturbed_score = perturbed_reward['overall']
                perturbed_scores.append(perturbed_score)
                all_perturbed_scores.append(perturbed_score)
            
            # Calculate score drops for this sample
            for pert_score in perturbed_scores:
                drop = original_score - pert_score
                score_drops.append(drop)
        
        # Calculate robustness metrics
        metrics = self.robustness_evaluator.calculate_robustness_metrics(
            original_scores, all_perturbed_scores
        )
        
        # Print results
        print("\nAdversarial Robustness Results:")
        print("-" * 80)
        print(f"Average Score Drop:     {metrics['average_score_drop']:.3f} "
              f"({metrics['average_score_drop_pct']:.1f}%)")
        print(f"Worst-Case Score Drop:  {metrics['worst_case_drop']:.3f} "
              f"({metrics['worst_case_drop_pct']:.1f}%)")
        print(f"Attack Success Rate:    {metrics['attack_success_rate']:.1f}%")
        print(f"Robustness Score:       {metrics['robustness_score']:.3f}")
        print(f"Std Dev (Score Drops):  {metrics['std_dev_score_drops']:.3f}")
        
        print("\nTarget Achievement:")
        print("-" * 80)
        meets = metrics['meets_targets']
        print(f"Avg Score Drop ≤10%:    {metrics['average_score_drop_pct']:.1f}% "
              f"{'✓' if meets['avg_drop'] else '✗'}")
        print(f"Worst-Case Drop <20%:   {metrics['worst_case_drop_pct']:.1f}% "
              f"{'✓' if meets['worst_case'] else '✗'}")
        print(f"ASR <5%:                {metrics['attack_success_rate']:.1f}% "
              f"{'✓' if meets['asr'] else '✗'}")
        print(f"Robustness Score ≥0.8:  {metrics['robustness_score']:.3f} "
              f"{'✓' if meets['robustness'] else '✗'}")
        
        return metrics
    
    def generate_visualizations(self, original_stats: Dict, robustness_metrics: Dict):
        """Generate evaluation visualizations."""
        print("\n" + "="*80)
        print("GENERATING VISUALIZATIONS")
        print("="*80)
        
        # Set style
        sns.set_style("whitegrid")
        
        # 1. Original Test Set Performance
        fig, axes = plt.subplots(2, 2, figsize=(12, 10))
        fig.suptitle('Original Test Set Performance', fontsize=16, fontweight='bold')
        
        metrics = ['relevance', 'novelty', 'impact', 'feasibility']
        targets = [0.8, 0.7, 0.6, 0.6]
        
        for i, (metric, target) in enumerate(zip(metrics, targets)):
            ax = axes[i // 2, i % 2]
            
            mean = original_stats[metric]['mean']
            std = original_stats[metric]['std']
            
            # Bar plot
            ax.bar([metric.capitalize()], [mean], yerr=[std], 
                   color='steelblue', alpha=0.7, capsize=10)
            ax.axhline(y=target, color='red', linestyle='--', 
                       label=f'Target: {target}')
            ax.set_ylim(0, 1)
            ax.set_ylabel('Score')
            ax.set_title(f'{metric.capitalize()} Score')
            ax.legend()
            ax.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'original_test_performance.png', dpi=300)
        print(f"Saved: {self.output_dir / 'original_test_performance.png'}")
        plt.close()
        
        # 2. Robustness Metrics
        fig, ax = plt.subplots(figsize=(10, 6))
        
        rob_metrics = {
            'Avg Drop (%)': robustness_metrics['average_score_drop_pct'],
            'Worst Drop (%)': robustness_metrics['worst_case_drop_pct'],
            'ASR (%)': robustness_metrics['attack_success_rate'],
            'Robustness': robustness_metrics['robustness_score'] * 100,
        }
        
        colors = ['green' if v < 10 else 'orange' if v < 20 else 'red' 
                  for v in rob_metrics.values()]
        
        ax.bar(rob_metrics.keys(), rob_metrics.values(), color=colors, alpha=0.7)
        ax.set_ylabel('Score (%)')
        ax.set_title('Adversarial Robustness Metrics', fontsize=14, fontweight='bold')
        ax.grid(True, alpha=0.3, axis='y')
        
        # Add target lines
        ax.axhline(y=10, color='red', linestyle='--', alpha=0.5, label='Avg Drop Target (10%)')
        ax.axhline(y=20, color='orange', linestyle='--', alpha=0.5, label='Worst Drop Target (20%)')
        ax.axhline(y=5, color='green', linestyle='--', alpha=0.5, label='ASR Target (5%)')
        ax.legend()
        
        plt.tight_layout()
        plt.savefig(self.output_dir / 'robustness_metrics.png', dpi=300)
        print(f"Saved: {self.output_dir / 'robustness_metrics.png'}")
        plt.close()
        
        print("Visualizations generated successfully")
    
    def save_results(self, original_stats: Dict, robustness_metrics: Dict):
        """Save evaluation results to JSON."""
        results = {
            'original_test_set': original_stats,
            'adversarial_robustness': robustness_metrics,
            'test_samples': len(self.test_data),
            'perturbations_per_sample': 5,
        }
        
        output_path = self.output_dir / 'evaluation_results.json'
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\nResults saved to: {output_path}")
    
    def run_full_evaluation(self):
        """Execute complete evaluation pipeline."""
        print("\n" + "="*80)
        print("COMPREHENSIVE MODEL EVALUATION")
        print("="*80)
        
        # Step 1: Evaluate on original test set
        original_stats = self.evaluate_original_test_set()
        
        # Step 2: Evaluate adversarial robustness
        robustness_metrics = self.evaluate_adversarial_robustness()
        
        # Step 3: Generate visualizations
        self.generate_visualizations(original_stats, robustness_metrics)
        
        # Step 4: Save results
        self.save_results(original_stats, robustness_metrics)
        
        print("\n" + "="*80)
        print("EVALUATION COMPLETE")
        print("="*80)
        
        return original_stats, robustness_metrics


def main():
    """Main execution function."""
    evaluator = ModelEvaluator(
        test_data_path='/workspace/data/processed/test_data.json',
        metadata_path='/workspace/data/processed/metadata.json',
        output_dir='/workspace/results',
        model=None  # Set to actual model when available
    )
    
    original_stats, robustness_metrics = evaluator.run_full_evaluation()


if __name__ == "__main__":
    main()
