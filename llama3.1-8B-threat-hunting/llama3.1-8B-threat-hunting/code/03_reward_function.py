"""
Custom Reward Function Module
PhD Research: Domain-Specific LLM for Cyber Threat Hunting
Author: PhD Candidate
Date: November 2025

This module implements a custom reward function with four key metrics:
1. Relevance (weight=0.3, target >0.8): Alignment with MITRE taxonomy
2. Novelty (weight=0.25, target >0.7): Uniqueness compared to known TTPs
3. Impact (weight=0.3, target >0.6): Security risk severity
4. Feasibility (weight=0.15, target >0.6): Operational practicality

Overall target score: >0.75
Robustness penalty: λ * std_dev(perturbed_scores)
"""

import re
import numpy as np
from typing import Dict, List, Tuple
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
import json


class CustomRewardFunction:
    """
    Custom reward function for evaluating generated TTPs.
    """
    
    def __init__(self, metadata_path: str, known_ttps_path: str = None):
        """
        Initialize reward function.
        
        Args:
            metadata_path: Path to metadata JSON with tactic/technique names
            known_ttps_path: Path to known TTPs for novelty calculation
        """
        # Load metadata
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        
        self.tactic_names = set([t.lower() for t in metadata.get('tactic_names', [])])
        self.technique_names = set([t.lower() for t in metadata.get('technique_names', [])])
        
        # Initialize Sentence-BERT for novelty detection
        print("Loading Sentence-BERT model for novelty detection...")
        self.sentence_model = SentenceTransformer('all-MiniLM-L6-v2')
        
        # Load known TTPs for novelty comparison
        self.known_ttps = []
        self.known_ttp_embeddings = None
        
        if known_ttps_path:
            self._load_known_ttps(known_ttps_path)
        
        # Predefined impact scores for tactics (normalized 0-1)
        self.tactic_impact_scores = {
            'reconnaissance': 0.08,
            'resource-development': 0.15,
            'initial-access': 0.54,
            'execution': 0.62,
            'persistence': 0.77,
            'privilege-escalation': 0.85,
            'defense-evasion': 0.69,
            'credential-access': 0.92,
            'discovery': 0.23,
            'lateral-movement': 0.77,
            'collection': 0.69,
            'command-and-control': 0.62,
            'exfiltration': 0.95,
            'impact': 1.0,
        }
        
        # Reward weights (sum = 1.0)
        self.weights = {
            'relevance': 0.3,
            'novelty': 0.25,
            'impact': 0.3,
            'feasibility': 0.15,
        }
        
        # Targets
        self.targets = {
            'relevance': 0.8,
            'novelty': 0.7,
            'impact': 0.6,
            'feasibility': 0.6,
            'overall': 0.75,
        }
        
        print(f"Reward function initialized with {len(self.tactic_names)} tactics, {len(self.technique_names)} techniques")
    
    def _load_known_ttps(self, path: str):
        """Load known TTPs for novelty comparison."""
        with open(path, 'r') as f:
            data = json.load(f)
        
        self.known_ttps = [item['response'] for item in data[:1000]]  # Limit for efficiency
        
        # Pre-compute embeddings
        print(f"Computing embeddings for {len(self.known_ttps)} known TTPs...")
        self.known_ttp_embeddings = self.sentence_model.encode(self.known_ttps, show_progress_bar=True)
        print("Known TTP embeddings computed")
    
    def calculate_relevance(self, generated_text: str, prompt: str = "") -> float:
        """
        Calculate relevance score (0-1).
        
        Measures alignment with MITRE taxonomy through keyword matching.
        Target: >0.8
        """
        text_lower = generated_text.lower()
        
        # Check for tactic mentions
        tactic_matches = sum(1 for tactic in self.tactic_names if tactic in text_lower)
        
        # Check for technique mentions
        technique_matches = sum(1 for tech in self.technique_names if tech in text_lower)
        
        # Check for cyber security keywords
        security_keywords = [
            'adversary', 'adversaries', 'attacker', 'threat', 'malicious',
            'compromise', 'exploit', 'vulnerability', 'persistence', 'privilege',
            'lateral movement', 'command and control', 'exfiltration', 'detection',
            'defense', 'evasion', 'credential', 'access', 'execution'
        ]
        keyword_matches = sum(1 for keyword in security_keywords if keyword in text_lower)
        
        # Normalize scores
        tactic_score = min(tactic_matches / 2, 1.0)  # At least 2 tactics = max score
        technique_score = min(technique_matches / 1, 1.0)  # At least 1 technique = max score
        keyword_score = min(keyword_matches / 5, 1.0)  # At least 5 keywords = max score
        
        # Weighted combination
        relevance = (0.4 * tactic_score + 0.3 * technique_score + 0.3 * keyword_score)
        
        return round(relevance, 3)
    
    def calculate_novelty(self, generated_text: str) -> float:
        """
        Calculate novelty score (0-1).
        
        Measures uniqueness using Sentence-BERT embeddings and cosine similarity.
        Lower similarity to known TTPs = higher novelty.
        Target: >0.7
        """
        if self.known_ttp_embeddings is None or len(self.known_ttps) == 0:
            # If no known TTPs loaded, use text length and uniqueness heuristics
            return self._heuristic_novelty(generated_text)
        
        # Compute embedding for generated text
        generated_embedding = self.sentence_model.encode([generated_text])
        
        # Compute cosine similarity with all known TTPs
        similarities = cosine_similarity(generated_embedding, self.known_ttp_embeddings)[0]
        
        # Get maximum similarity (most similar known TTP)
        max_similarity = np.max(similarities)
        
        # Novelty = 1 - max_similarity (lower similarity = higher novelty)
        novelty = 1 - max_similarity
        
        return round(float(novelty), 3)
    
    def _heuristic_novelty(self, text: str) -> float:
        """Heuristic novelty when embeddings not available."""
        # Factors: text length, complexity, unique terms
        words = text.split()
        unique_ratio = len(set(words)) / max(len(words), 1)
        length_factor = min(len(words) / 200, 1.0)  # Longer = more novel up to 200 words
        
        novelty = (unique_ratio * 0.6 + length_factor * 0.4)
        return round(novelty, 3)
    
    def calculate_impact(self, generated_text: str, tactic: str = None) -> float:
        """
        Calculate impact score (0-1).
        
        Based on predefined scores for tactics reflecting severity.
        Target: >0.6
        """
        text_lower = generated_text.lower()
        
        # Try to extract tactic from text or use provided tactic
        if tactic:
            tactic_key = tactic.lower().replace('_', '-')
        else:
            # Try to find tactic in text
            found_tactics = [t for t in self.tactic_impact_scores.keys() if t in text_lower]
            tactic_key = found_tactics[0] if found_tactics else 'discovery'  # Default
        
        # Get impact score
        impact = self.tactic_impact_scores.get(tactic_key, 0.5)  # Default 0.5
        
        # Adjust based on severity keywords
        high_impact_keywords = ['critical', 'severe', 'compromise', 'exfiltration', 'ransomware', 'data breach']
        severity_boost = sum(0.05 for keyword in high_impact_keywords if keyword in text_lower)
        
        impact = min(impact + severity_boost, 1.0)
        
        return round(impact, 3)
    
    def calculate_feasibility(self, generated_text: str) -> float:
        """
        Calculate feasibility score (0-1).
        
        Evaluates operational practicality through keyword counting.
        Target: >0.6
        """
        text_lower = generated_text.lower()
        words = text_lower.split()
        
        # Feasibility indicators
        feasibility_keywords = [
            'common', 'standard', 'widely', 'typical', 'readily', 'available',
            'simple', 'straightforward', 'easy', 'accessible', 'public',
            'well-known', 'documented', 'established', 'proven'
        ]
        
        # Count keywords
        keyword_count = sum(1 for keyword in feasibility_keywords if keyword in text_lower)
        
        # Normalize by text length
        feasibility = min(keyword_count / max(len(words) / 100, 1), 1.0)
        
        # Boost for technical details
        if any(term in text_lower for term in ['tool', 'script', 'command', 'api', 'protocol']):
            feasibility += 0.1
        
        feasibility = min(feasibility, 1.0)
        
        return round(feasibility, 3)
    
    def calculate_overall_score(self, relevance: float, novelty: float, 
                                 impact: float, feasibility: float) -> float:
        """
        Calculate weighted overall score.
        
        Score = 0.3*Relevance + 0.25*Novelty + 0.3*Impact + 0.15*Feasibility
        Target: >0.75
        """
        overall = (
            self.weights['relevance'] * relevance +
            self.weights['novelty'] * novelty +
            self.weights['impact'] * impact +
            self.weights['feasibility'] * feasibility
        )
        
        return round(overall, 3)
    
    def calculate_reward(self, generated_text: str, prompt: str = "", 
                         tactic: str = None) -> Dict[str, float]:
        """
        Calculate complete reward with all metrics.
        
        Returns:
            Dictionary with all scores and overall reward
        """
        # Calculate individual metrics
        relevance = self.calculate_relevance(generated_text, prompt)
        novelty = self.calculate_novelty(generated_text)
        impact = self.calculate_impact(generated_text, tactic)
        feasibility = self.calculate_feasibility(generated_text)
        
        # Calculate overall
        overall = self.calculate_overall_score(relevance, novelty, impact, feasibility)
        
        return {
            'relevance': relevance,
            'novelty': novelty,
            'impact': impact,
            'feasibility': feasibility,
            'overall': overall,
            'meets_targets': {
                'relevance': relevance >= self.targets['relevance'],
                'novelty': novelty >= self.targets['novelty'],
                'impact': impact >= self.targets['impact'],
                'feasibility': feasibility >= self.targets['feasibility'],
                'overall': overall >= self.targets['overall'],
            }
        }
    
    def calculate_adversarial_penalty(self, perturbed_scores: List[float], 
                                       lambda_penalty: float = 0.1) -> float:
        """
        Calculate adversarial robustness penalty.
        
        Penalty = λ * std_dev(perturbed_scores)
        
        Args:
            perturbed_scores: List of scores from perturbed versions
            lambda_penalty: Penalty weight (default 0.1)
        
        Returns:
            Penalty value (higher = less robust)
        """
        if not perturbed_scores or len(perturbed_scores) < 2:
            return 0.0
        
        std_dev = np.std(perturbed_scores)
        penalty = lambda_penalty * std_dev
        
        return round(float(penalty), 3)
    
    def calculate_robust_reward(self, generated_text: str, perturbed_texts: List[str],
                                prompt: str = "", tactic: str = None,
                                lambda_penalty: float = 0.1) -> Dict[str, float]:
        """
        Calculate reward with adversarial robustness penalty.
        
        reward = total_score - λ * std_dev(perturbed_scores)
        """
        # Original score
        original_reward = self.calculate_reward(generated_text, prompt, tactic)
        
        # Perturbed scores
        perturbed_scores = []
        for perturbed_text in perturbed_texts:
            perturbed_reward = self.calculate_reward(perturbed_text, prompt, tactic)
            perturbed_scores.append(perturbed_reward['overall'])
        
        # Calculate penalty
        penalty = self.calculate_adversarial_penalty(perturbed_scores, lambda_penalty)
        
        # Adjusted reward
        robust_overall = original_reward['overall'] - penalty
        
        return {
            **original_reward,
            'adversarial_penalty': penalty,
            'robust_overall': round(robust_overall, 3),
            'perturbed_scores': perturbed_scores,
            'score_std_dev': round(float(np.std(perturbed_scores)), 3) if perturbed_scores else 0.0,
        }


def test_reward_function():
    """Test the reward function with sample TTPs."""
    print("="*80)
    print("TESTING CUSTOM REWARD FUNCTION")
    print("="*80)
    
    # Initialize
    reward_fn = CustomRewardFunction(
        metadata_path='/workspace/data/processed/metadata.json',
        known_ttps_path='/workspace/data/processed/train_data.json'
    )
    
    # Test samples
    test_samples = [
        {
            'text': "Adversaries may use command and control protocols to communicate with compromised systems. This technique allows attackers to maintain persistent access and execute commands remotely. Common tools include Cobalt Strike and Metasploit.",
            'tactic': 'command-and-control',
            'description': 'High-quality TTP with relevant details'
        },
        {
            'text': "The cat sat on the mat.",
            'tactic': None,
            'description': 'Irrelevant text (low relevance)'
        },
        {
            'text': "Novel quantum-based attack vector leveraging blockchain AI to compromise neural networks in the metaverse using zero-day exploits in interdimensional firewalls.",
            'tactic': 'impact',
            'description': 'High novelty but low feasibility'
        }
    ]
    
    for i, sample in enumerate(test_samples, 1):
        print(f"\n[Test {i}] {sample['description']}")
        print(f"Text: {sample['text'][:100]}...")
        
        reward = reward_fn.calculate_reward(sample['text'], tactic=sample['tactic'])
        
        print(f"\nScores:")
        print(f"  Relevance:   {reward['relevance']:.3f} (target >0.8) {'✓' if reward['meets_targets']['relevance'] else '✗'}")
        print(f"  Novelty:     {reward['novelty']:.3f} (target >0.7) {'✓' if reward['meets_targets']['novelty'] else '✗'}")
        print(f"  Impact:      {reward['impact']:.3f} (target >0.6) {'✓' if reward['meets_targets']['impact'] else '✗'}")
        print(f"  Feasibility: {reward['feasibility']:.3f} (target >0.6) {'✓' if reward['meets_targets']['feasibility'] else '✗'}")
        print(f"  Overall:     {reward['overall']:.3f} (target >0.75) {'✓' if reward['meets_targets']['overall'] else '✗'}")
    
    print("\n" + "="*80)


if __name__ == "__main__":
    test_reward_function()
