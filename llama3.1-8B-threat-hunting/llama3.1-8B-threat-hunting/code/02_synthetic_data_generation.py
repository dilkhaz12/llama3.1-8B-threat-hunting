"""
Synthetic Data Generation Module
PhD Research: Domain-Specific LLM for Cyber Threat Hunting
Author: PhD Candidate
Date: November 2025

This module generates synthetic TTP data to expand the training set 5x using:
1. Stylistic variations of existing TTPs
2. Combination of related techniques
3. Parameter variation and contextual augmentation
4. LLM-based generation (Llama 3.3 70B Instruct or GPT-4)

IMPORTANT: Only the training set is synthesized. Test set remains UNTOUCHED.
"""

import json
import random
import pickle
from pathlib import Path
from typing import List, Dict
from tqdm import tqdm
import time


class SyntheticTTPGenerator:
    """
    Generates synthetic TTP data using LLM-based augmentation.
    """
    
    def __init__(self, train_data_path: str, metadata_path: str, output_dir: str, 
                 expansion_factor: int = 5, use_api: bool = False):
        """
        Initialize synthetic data generator.
        
        Args:
            train_data_path: Path to training data JSON
            metadata_path: Path to metadata JSON
            output_dir: Directory to save synthetic data
            expansion_factor: How many times to expand the dataset (default: 5x)
            use_api: Whether to use external API (Llama 3.3 70B) or rule-based
        """
        self.train_data_path = train_data_path
        self.metadata_path = metadata_path
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.expansion_factor = expansion_factor
        self.use_api = use_api
        
        # Load data
        self.train_data = self._load_json(train_data_path)
        self.metadata = self._load_json(metadata_path)
        
        # Extract tactics and techniques
        self.tactics = self.metadata.get('tactic_names', [])
        self.techniques = self.metadata.get('technique_names', [])
        
        print(f"Loaded {len(self.train_data)} training samples")
        print(f"Target synthetic samples: {len(self.train_data) * expansion_factor}")
    
    def _load_json(self, path: str) -> Dict:
        """Load JSON file."""
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def generate_stylistic_variation(self, original: Dict) -> Dict:
        """
        Generate stylistic variation of a TTP.
        Modifies language style while preserving semantic meaning.
        """
        instruction = original['instruction']
        response = original['response']
        metadata = original['metadata'].copy()
        
        # Variation strategies
        strategies = [
            self._paraphrase_instruction,
            self._expand_description,
            self._add_technical_details,
            self._add_scenario_context,
        ]
        
        strategy = random.choice(strategies)
        varied_response = strategy(response, metadata)
        
        return {
            'instruction': instruction,
            'response': varied_response,
            'metadata': {**metadata, 'synthetic_type': 'stylistic_variation'},
            'original_id': original.get('metadata', {}).get('technique_id', 'unknown')
        }
    
    def _paraphrase_instruction(self, response: str, metadata: Dict) -> str:
        """Paraphrase the response while maintaining key information."""
        # Simple rule-based paraphrasing
        variations = [
            response.replace('Adversaries may', 'Attackers can'),
            response.replace('may use', 'might utilize'),
            response.replace('can be used', 'is often employed'),
            response.replace('This technique', 'This attack method'),
        ]
        return random.choice([response] + variations)
    
    def _expand_description(self, response: str, metadata: Dict) -> str:
        """Add expanded context to the description."""
        platforms = metadata.get('platforms', [])
        technique = metadata.get('technique_name', '')
        
        expansion = f"\n\nThis technique, {technique}, is particularly relevant in environments "
        if platforms:
            expansion += f"running {', '.join(platforms[:2])} systems. "
        expansion += "Security teams should monitor for anomalous activities that may indicate this TTP."
        
        return response + expansion
    
    def _add_technical_details(self, response: str, metadata: Dict) -> str:
        """Add technical implementation details."""
        details = [
            "\n\nTechnical Implementation: Adversaries typically leverage scripting languages or system utilities to execute this technique.",
            "\n\nAttack Vector: This technique can be deployed through multiple attack vectors including phishing, drive-by compromise, or supply chain attacks.",
            "\n\nPersistence Mechanism: Once established, this technique may provide adversaries with persistent access to the compromised environment.",
        ]
        return response + random.choice(details)
    
    def _add_scenario_context(self, response: str, metadata: Dict) -> str:
        """Add realistic attack scenario context."""
        scenarios = [
            "\n\nReal-World Scenario: In a recent APT campaign, threat actors utilized this technique to maintain presence in the target network for several months undetected.",
            "\n\nThreat Actor Usage: This technique has been observed in campaigns attributed to nation-state actors and sophisticated cybercriminal groups.",
            "\n\nDefense Evasion: Adversaries employing this technique often combine it with obfuscation and anti-forensics methods to avoid detection.",
        ]
        return response + random.choice(scenarios)
    
    def generate_technique_combination(self, samples: List[Dict]) -> Dict:
        """
        Combine multiple related techniques into a novel attack chain.
        """
        # Select 2-3 related techniques
        num_techniques = random.randint(2, 3)
        selected = random.sample(samples, min(num_techniques, len(samples)))
        
        # Get common tactic
        common_tactics = set(selected[0]['metadata']['tactic'])
        for sample in selected[1:]:
            common_tactics &= set([sample['metadata']['tactic']])
        
        if not common_tactics:
            common_tactics = {selected[0]['metadata']['tactic']}
        
        tactic = list(common_tactics)[0]
        
        # Combine technique names
        technique_names = [s['metadata']['technique_name'] for s in selected]
        combined_name = f"Combined: {' + '.join(technique_names[:2])}"
        
        # Create combined description
        instruction = f"Generate a detailed TTP description for a multi-stage attack combining {' and '.join(technique_names)} in the '{tactic}' phase."
        
        response = f"This advanced attack chain combines multiple techniques: {', '.join(technique_names)}.\n\n"
        for i, sample in enumerate(selected, 1):
            response += f"Stage {i} - {sample['metadata']['technique_name']}: {sample['response'][:200]}...\n\n"
        
        response += "By chaining these techniques, adversaries can achieve more sophisticated attack objectives while evading detection."
        
        return {
            'instruction': instruction,
            'response': response,
            'metadata': {
                'technique_name': combined_name,
                'tactic': tactic,
                'is_subtechnique': False,
                'synthetic_type': 'technique_combination',
                'source_techniques': [s['metadata']['technique_id'] for s in selected],
            }
        }
    
    def generate_parameter_variation(self, original: Dict) -> Dict:
        """
        Generate variations with different parameters (platforms, tools, etc.).
        """
        response = original['response']
        metadata = original['metadata'].copy()
        
        # Vary platforms
        alternative_platforms = ['Windows', 'Linux', 'macOS', 'Cloud', 'Containers', 'Network']
        original_platforms = metadata.get('platforms', [])
        
        if original_platforms:
            # Substitute platform
            new_platforms = random.sample(alternative_platforms, min(2, len(alternative_platforms)))
            varied_response = response
            for old_platform in original_platforms[:1]:
                if old_platform in response:
                    varied_response = varied_response.replace(old_platform, new_platforms[0])
            
            metadata['platforms'] = new_platforms
            metadata['synthetic_type'] = 'parameter_variation'
            
            return {
                'instruction': original['instruction'],
                'response': varied_response,
                'metadata': metadata,
            }
        
        return original
    
    def generate_contextual_augmentation(self, original: Dict) -> Dict:
        """
        Add contextual information about threat actors, tools, or environments.
        """
        response = original['response']
        metadata = original['metadata'].copy()
        
        contexts = [
            "\n\nThreat Intelligence: This technique has been observed in campaigns by APT28, APT29, and other sophisticated threat actors.",
            "\n\nTooling: Common tools used for this technique include PowerShell, Cobalt Strike, Metasploit, and custom malware frameworks.",
            "\n\nEnvironmental Factors: This technique is particularly effective in environments with insufficient logging and monitoring capabilities.",
            "\n\nMitigation: Organizations can defend against this technique through network segmentation, endpoint detection and response (EDR) solutions, and user awareness training.",
        ]
        
        augmented_response = response + random.choice(contexts)
        metadata['synthetic_type'] = 'contextual_augmentation'
        
        return {
            'instruction': original['instruction'],
            'response': augmented_response,
            'metadata': metadata,
        }
    
    def generate_llm_based_variation(self, original: Dict) -> Dict:
        """
        Use LLM API (Llama 3.3 70B) to generate high-quality variations.
        
        NOTE: This requires API access. Falls back to rule-based if not available.
        """
        if not self.use_api:
            # Fall back to rule-based
            return random.choice([
                self.generate_stylistic_variation(original),
                self.generate_parameter_variation(original),
                self.generate_contextual_augmentation(original),
            ])
        
        # TODO: Implement API call to Llama 3.3 70B
        # For now, use advanced rule-based generation
        return self.generate_stylistic_variation(original)
    
    def generate_synthetic_dataset(self) -> List[Dict]:
        """
        Generate synthetic dataset (5x expansion of training data).
        """
        print("="*80)
        print("GENERATING SYNTHETIC DATASET")
        print("="*80)
        print(f"Original training samples: {len(self.train_data)}")
        print(f"Target synthetic samples: {len(self.train_data) * (self.expansion_factor - 1)}")
        print(f"Total target: {len(self.train_data) * self.expansion_factor}")
        
        synthetic_data = []
        target_synthetic = len(self.train_data) * (self.expansion_factor - 1)
        
        # Generation strategies with weights
        strategies = [
            (self.generate_stylistic_variation, 0.4),  # 40%
            (self.generate_parameter_variation, 0.2),   # 20%
            (self.generate_contextual_augmentation, 0.3),  # 30%
            (self.generate_technique_combination, 0.1),  # 10%
        ]
        
        with tqdm(total=target_synthetic, desc="Generating synthetic data") as pbar:
            while len(synthetic_data) < target_synthetic:
                # Select strategy based on weights
                strategy = random.choices(
                    [s[0] for s in strategies],
                    weights=[s[1] for s in strategies]
                )[0]
                
                # Generate synthetic sample
                if strategy == self.generate_technique_combination:
                    # Need multiple samples
                    sample = strategy(random.sample(self.train_data, min(3, len(self.train_data))))
                else:
                    # Single sample variation
                    original = random.choice(self.train_data)
                    sample = strategy(original)
                
                synthetic_data.append(sample)
                pbar.update(1)
        
        print(f"\nGenerated {len(synthetic_data)} synthetic samples")
        return synthetic_data
    
    def create_expanded_dataset(self) -> List[Dict]:
        """
        Combine original training data with synthetic data.
        """
        synthetic_data = self.generate_synthetic_dataset()
        
        # Combine original + synthetic
        expanded_data = self.train_data + synthetic_data
        random.shuffle(expanded_data)
        
        print(f"\nExpanded dataset size: {len(expanded_data)}")
        print(f"  Original: {len(self.train_data)} ({len(self.train_data)/len(expanded_data)*100:.1f}%)")
        print(f"  Synthetic: {len(synthetic_data)} ({len(synthetic_data)/len(expanded_data)*100:.1f}%)")
        
        return expanded_data
    
    def save_synthetic_data(self, expanded_data: List[Dict]):
        """Save expanded training dataset."""
        output_path = self.output_dir / 'train_data_synthetic_5x.json'
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(expanded_data, f, indent=2, ensure_ascii=False)
        
        # Also save as pickle
        with open(self.output_dir / 'train_data_synthetic_5x.pkl', 'wb') as f:
            pickle.dump(expanded_data, f)
        
        print(f"\nSaved expanded dataset to {output_path}")
        
        # Save statistics
        stats = {
            'total_samples': len(expanded_data),
            'original_samples': len(self.train_data),
            'synthetic_samples': len(expanded_data) - len(self.train_data),
            'expansion_factor': len(expanded_data) / len(self.train_data),
            'synthetic_types': self._count_synthetic_types(expanded_data),
        }
        
        with open(self.output_dir / 'synthetic_stats.json', 'w') as f:
            json.dump(stats, f, indent=2)
        
        print(f"Synthetic data statistics: {stats}")
    
    def _count_synthetic_types(self, data: List[Dict]) -> Dict[str, int]:
        """Count occurrences of each synthetic type."""
        counts = {}
        for sample in data:
            syn_type = sample.get('metadata', {}).get('synthetic_type', 'original')
            counts[syn_type] = counts.get(syn_type, 0) + 1
        return counts
    
    def process_all(self):
        """Execute complete synthetic data generation pipeline."""
        expanded_data = self.create_expanded_dataset()
        self.save_synthetic_data(expanded_data)
        
        print("\n" + "="*80)
        print("SYNTHETIC DATA GENERATION COMPLETE")
        print("="*80)
        
        return expanded_data


def main():
    """Main execution function."""
    # Configuration
    TRAIN_DATA_PATH = '/workspace/data/processed/train_data.json'
    METADATA_PATH = '/workspace/data/processed/metadata.json'
    OUTPUT_DIR = '/workspace/data/processed'
    EXPANSION_FACTOR = 5
    
    # Generate synthetic data
    generator = SyntheticTTPGenerator(
        train_data_path=TRAIN_DATA_PATH,
        metadata_path=METADATA_PATH,
        output_dir=OUTPUT_DIR,
        expansion_factor=EXPANSION_FACTOR,
        use_api=False  # Set to True if you have API access
    )
    
    expanded_data = generator.process_all()
    
    # Display samples
    print("\n" + "="*80)
    print("SAMPLE SYNTHETIC DATA")
    print("="*80)
    
    for i, sample_type in enumerate(['original', 'stylistic_variation', 'technique_combination']):
        samples = [s for s in expanded_data if s.get('metadata', {}).get('synthetic_type', 'original') == sample_type]
        if samples:
            sample = random.choice(samples)
            print(f"\n[{i+1}] Type: {sample_type}")
            print(f"Instruction: {sample['instruction'][:100]}...")
            print(f"Response: {sample['response'][:200]}...")


if __name__ == "__main__":
    main()
