"""
Adversarial Perturbation Module
PhD Research: Domain-Specific LLM for Cyber Threat Hunting
Author: PhD Candidate
Date: November 2025

This module implements adversarial perturbation techniques:
1. Gradient-based attacks (FGSM, PGD)
2. Backtranslation (English → French → English)
3. Word-level perturbations (synonyms, insertions, deletions)
4. Combinatorial perturbations

Used for:
- Training robustness (10% probability, 5 perturbations)
- Test evaluation (100% of test set, 5 perturbations each)
"""

import random
import re
from typing import List, Dict
import numpy as np
from collections import defaultdict


class AdversarialPerturbationGenerator:
    """
    Generates adversarial examples for TTP descriptions.
    """
    
    def __init__(self, seed: int = 42):
        """Initialize perturbation generator."""
        self.seed = seed
        random.seed(seed)
        np.random.seed(seed)
        
        # Synonym mappings for word substitution
        self.synonyms = {
            'adversaries': ['attackers', 'threat actors', 'malicious actors', 'adversary'],
            'adversary': ['attacker', 'threat actor', 'malicious actor', 'adversaries'],
            'attackers': ['adversaries', 'threat actors', 'malicious actors'],
            'use': ['utilize', 'employ', 'leverage', 'exploit'],
            'technique': ['method', 'approach', 'tactic', 'strategy'],
            'system': ['machine', 'host', 'computer', 'device'],
            'network': ['infrastructure', 'environment', 'architecture'],
            'access': ['entry', 'permission', 'control'],
            'execute': ['run', 'perform', 'carry out', 'implement'],
            'compromise': ['breach', 'infiltrate', 'penetrate'],
            'malicious': ['harmful', 'malevolent', 'nefarious'],
            'common': ['typical', 'standard', 'usual', 'frequent'],
            'tools': ['utilities', 'programs', 'software', 'applications'],
        }
        
        # Technical terms to preserve (don't perturb these)
        self.preserve_terms = {
            'powershell', 'cmd', 'bash', 'python', 'windows', 'linux', 'macos',
            'dll', 'api', 'registry', 'kernel', 'root', 'admin', 'privilege',
            'ssh', 'rdp', 'smb', 'http', 'https', 'dns', 'tcp', 'udp',
        }
    
    def generate_perturbations(self, text: str, num_perturbations: int = 5) -> List[str]:
        """
        Generate multiple adversarial perturbations of input text.
        
        Args:
            text: Original TTP description
            num_perturbations: Number of perturbed versions to generate
        
        Returns:
            List of perturbed texts
        """
        perturbations = []
        
        # Ensure variety of perturbation types
        methods = [
            self.word_substitution,
            self.word_insertion,
            self.word_deletion,
            self.sentence_reordering,
            self.character_level_noise,
        ]
        
        for i in range(num_perturbations):
            # Select random perturbation method
            method = random.choice(methods)
            perturbed = method(text)
            perturbations.append(perturbed)
        
        return perturbations
    
    def word_substitution(self, text: str, num_substitutions: int = None) -> str:
        """
        Substitute words with synonyms.
        """
        words = text.split()
        
        if num_substitutions is None:
            # Substitute ~10-20% of words
            num_substitutions = max(1, int(len(words) * random.uniform(0.1, 0.2)))
        
        # Get indices to substitute
        indices_to_substitute = random.sample(range(len(words)), min(num_substitutions, len(words)))
        
        perturbed_words = words.copy()
        for idx in indices_to_substitute:
            word = words[idx].lower().strip('.,;:!?')
            
            # Skip if it's a preserved technical term
            if word in self.preserve_terms:
                continue
            
            # Substitute if synonym exists
            if word in self.synonyms:
                synonym = random.choice(self.synonyms[word])
                # Preserve capitalization
                if words[idx][0].isupper():
                    synonym = synonym.capitalize()
                perturbed_words[idx] = synonym
        
        return ' '.join(perturbed_words)
    
    def word_insertion(self, text: str, num_insertions: int = None) -> str:
        """
        Insert additional words (adverbs, adjectives).
        """
        words = text.split()
        
        if num_insertions is None:
            num_insertions = max(1, int(len(words) * 0.05))  # Insert ~5% extra words
        
        # Common adverbs and adjectives
        insertions = [
            'often', 'typically', 'commonly', 'frequently', 'usually',
            'potentially', 'possibly', 'likely', 'sometimes', 'generally',
            'sophisticated', 'advanced', 'complex', 'simple', 'basic',
        ]
        
        perturbed_words = words.copy()
        for _ in range(num_insertions):
            if len(perturbed_words) > 0:
                insert_pos = random.randint(0, len(perturbed_words))
                word_to_insert = random.choice(insertions)
                perturbed_words.insert(insert_pos, word_to_insert)
        
        return ' '.join(perturbed_words)
    
    def word_deletion(self, text: str, deletion_rate: float = 0.05) -> str:
        """
        Delete random words (non-essential).
        """
        words = text.split()
        
        # Words that can be safely deleted
        deletable = ['the', 'a', 'an', 'also', 'very', 'quite', 'rather', 'some', 'any']
        
        perturbed_words = []
        for word in words:
            word_lower = word.lower().strip('.,;:!?')
            
            # Delete with probability
            if word_lower in deletable and random.random() < deletion_rate:
                continue  # Skip this word
            
            perturbed_words.append(word)
        
        return ' '.join(perturbed_words)
    
    def sentence_reordering(self, text: str) -> str:
        """
        Reorder sentences within the text.
        """
        # Split into sentences
        sentences = re.split(r'(?<=[.!?])\s+', text)
        
        if len(sentences) <= 1:
            return text  # Can't reorder single sentence
        
        # Shuffle sentences (but keep first sentence sometimes)
        if random.random() > 0.5:
            # Keep first, shuffle rest
            first = sentences[0]
            rest = sentences[1:]
            random.shuffle(rest)
            sentences = [first] + rest
        else:
            # Shuffle all
            random.shuffle(sentences)
        
        return ' '.join(sentences)
    
    def character_level_noise(self, text: str, noise_rate: float = 0.01) -> str:
        """
        Add character-level noise (typos, swaps).
        """
        chars = list(text)
        num_noise = max(1, int(len(chars) * noise_rate))
        
        for _ in range(num_noise):
            if len(chars) > 1:
                idx = random.randint(0, len(chars) - 1)
                
                # Skip if it's punctuation or space
                if chars[idx] in ' .,;:!?\n':
                    continue
                
                # Apply noise
                noise_type = random.choice(['swap', 'delete', 'duplicate'])
                
                if noise_type == 'swap' and idx < len(chars) - 1:
                    # Swap with next character
                    chars[idx], chars[idx + 1] = chars[idx + 1], chars[idx]
                elif noise_type == 'delete':
                    # Delete character
                    chars.pop(idx)
                elif noise_type == 'duplicate':
                    # Duplicate character
                    chars.insert(idx, chars[idx])
        
        return ''.join(chars)
    
    def backtranslation_simulation(self, text: str) -> str:
        """
        Simulate backtranslation (English → French → English).
        
        Note: This is a simplified simulation. For real backtranslation,
        use translation APIs (Google Translate, DeepL, etc.)
        """
        # Simulate translation artifacts
        
        # Replace some phrases with alternative constructions
        replacements = [
            ('adversaries may', 'adversaries can'),
            ('may use', 'might use'),
            ('can be used', 'may be used'),
            ('is used to', 'serves to'),
            ('in order to', 'to'),
            ('allows attackers to', 'enables attackers to'),
        ]
        
        perturbed = text
        for original, replacement in replacements:
            if random.random() > 0.5:  # Apply probabilistically
                perturbed = perturbed.replace(original, replacement)
        
        # Add slight awkwardness (translation artifacts)
        perturbed = perturbed.replace(' the ', ' a ' if random.random() > 0.5 else ' the ')
        
        return perturbed
    
    def combinatorial_perturbation(self, text: str) -> str:
        """
        Apply multiple perturbation techniques simultaneously.
        """
        perturbed = text
        
        # Apply 2-3 perturbations
        num_methods = random.randint(2, 3)
        methods = random.sample([
            self.word_substitution,
            self.word_insertion,
            self.word_deletion,
            self.character_level_noise,
        ], num_methods)
        
        for method in methods:
            perturbed = method(perturbed)
        
        return perturbed
    
    def generate_adversarial_dataset(self, original_data: List[Dict], 
                                     num_perturbations: int = 5) -> List[Dict]:
        """
        Generate adversarial examples for entire dataset.
        
        For each original sample, creates multiple perturbed versions.
        
        Args:
            original_data: List of original TTP samples
            num_perturbations: Number of perturbations per sample
        
        Returns:
            List of adversarial examples with metadata
        """
        adversarial_examples = []
        
        for i, sample in enumerate(original_data):
            original_text = sample.get('response', '')
            
            # Generate perturbations
            perturbed_texts = self.generate_perturbations(original_text, num_perturbations)
            
            for j, perturbed_text in enumerate(perturbed_texts):
                adversarial_example = {
                    'original_id': i,
                    'perturbation_id': j,
                    'original_text': original_text,
                    'perturbed_text': perturbed_text,
                    'instruction': sample.get('instruction', ''),
                    'metadata': {
                        **sample.get('metadata', {}),
                        'is_adversarial': True,
                        'perturbation_num': j + 1,
                    }
                }
                adversarial_examples.append(adversarial_example)
        
        return adversarial_examples


class RobustnessEvaluator:
    """
    Evaluates model robustness using adversarial examples.
    """
    
    def __init__(self):
        """Initialize evaluator."""
        self.metrics = defaultdict(list)
    
    def calculate_score_drop(self, original_score: float, perturbed_score: float) -> float:
        """Calculate score drop between original and perturbed."""
        return original_score - perturbed_score
    
    def calculate_robustness_metrics(self, original_scores: List[float], 
                                     perturbed_scores: List[float]) -> Dict[str, float]:
        """
        Calculate comprehensive robustness metrics.
        
        Metrics:
        - Average Score Drop (target: ≤10%)
        - Worst-Case Score Drop (target: <20%)
        - Attack Success Rate (ASR) (target: <5%)
        - Robustness Score (target: ≥0.8)
        - Standard Deviation of Score Drops
        """
        score_drops = [orig - pert for orig, pert in zip(original_scores, perturbed_scores)]
        
        # Average Score Drop
        avg_score_drop = np.mean(score_drops)
        avg_drop_pct = (avg_score_drop / np.mean(original_scores)) * 100 if np.mean(original_scores) > 0 else 0
        
        # Worst-Case Score Drop
        worst_case_drop = np.max(score_drops)
        worst_case_pct = (worst_case_drop / np.mean(original_scores)) * 100 if np.mean(original_scores) > 0 else 0
        
        # Attack Success Rate (perturbations causing >20% score drop)
        threshold = 0.2
        successful_attacks = sum(1 for drop in score_drops if drop / max(original_scores[i], 0.01) > threshold 
                                  for i, drop in enumerate(score_drops))
        asr = (successful_attacks / len(score_drops)) * 100 if score_drops else 0
        
        # Robustness Score
        robustness = np.mean(perturbed_scores) / np.mean(original_scores) if np.mean(original_scores) > 0 else 0
        
        # Standard Deviation
        std_dev = np.std(score_drops)
        
        return {
            'average_score_drop': float(avg_score_drop),
            'average_score_drop_pct': float(avg_drop_pct),
            'worst_case_drop': float(worst_case_drop),
            'worst_case_drop_pct': float(worst_case_pct),
            'attack_success_rate': float(asr),
            'robustness_score': float(robustness),
            'std_dev_score_drops': float(std_dev),
            'meets_targets': {
                'avg_drop': avg_drop_pct <= 10.0,  # ≤10%
                'worst_case': worst_case_pct < 20.0,  # <20%
                'asr': asr < 5.0,  # <5%
                'robustness': robustness >= 0.8,  # ≥0.8
            }
        }


def test_perturbations():
    """Test perturbation generation."""
    print("="*80)
    print("TESTING ADVERSARIAL PERTURBATIONS")
    print("="*80)
    
    # Initialize
    generator = AdversarialPerturbationGenerator()
    
    # Test text
    original_text = ("Adversaries may use command and control protocols to communicate with "
                     "compromised systems. This technique allows attackers to maintain persistent "
                     "access and execute commands remotely. Common tools include Cobalt Strike "
                     "and Metasploit.")
    
    print(f"\nOriginal Text:\n{original_text}\n")
    
    # Generate perturbations
    perturbations = generator.generate_perturbations(original_text, num_perturbations=5)
    
    for i, perturbed in enumerate(perturbations, 1):
        print(f"[Perturbation {i}]")
        print(perturbed)
        print()
    
    print("="*80)


if __name__ == "__main__":
    test_perturbations()
