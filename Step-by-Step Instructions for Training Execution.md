Step-by-Step Instructions for Training Execution

### 1. Access Google Colab
1. Go to [Google Colab](https://colab.research.google.com/)
2. Sign in with your Google account
3. You should see the Colab dashboard

### 2. Upgrade to Colab Pro (Recommended)
1. Click on "Upgrade to Colab Pro" in the top right
2. Choose the plan that includes T4 GPU access
3. Complete the payment process
4. Why Colab Pro? Access to T4 GPU is crucial for LLAMA-3.1 8B training

### 3. Configure Hardware and Notebook Settings
1. Click "Runtime" → "Change runtime type"
2. Set:
   - Hardware accelerator: GPU
   - Runtime shape: High-RAM (recommended)
3. Click "Save"

### 4. Execute Notebook Step by Step

#### Step 1: Environment Setup
- Action: Run all cells in the first section
- Verify: All dependencies installed successfully

#### Step 2: MITRE Data Processing
- Action: Load and process MITRE ATT&CK data
- Verify: 871 base techniques + 4,355 synthetic techniques

#### Step 3: Model Configuration
- Action: Load LLAMA-3.1 8B model with QLoRA configuration
- Verify: Model loaded successfully with 4-bit quantization

#### Step 4: Reward Functions
- Action: Initialize multi-dimensional reward function
- Verify: Test evaluation returns meaningful scores

#### Step 5: Training Execution
- Action: Execute 3-epoch QLoRA fine-tuning
- Monitor: Watch loss progression and GPU utilization

#### Step 6: Discovery Pipeline
- Action: Generate and validate novel TTP techniques
- Monitor: Novelty validation against MITRE database

#### Step 7: Expert Evaluation
- Action: Simulate expert panel evaluation
- Metrics: Technical accuracy, innovation, feasibility

#### Step 8: Statistical Analysis
- Action: Comprehensive statistical significance testing
- Verify: Effect sizes and improvement percentages

### 5. Monitoring Progress
Key Metrics to Watch:
1. Training Loss
2. GPU Utilization 
3. Discovery Rate
4. Expert Scores

### 6. Expected Timeline

| Phase | Duration | Description |
|-------|----------|-------------|
| Setup | 30 minutes | Environment configuration |
| Data Processing | 10 minutes | MITRE data loading and preprocessing |
| Model Loading | 15 minutes | LLAMA-3.1 + QLoRA setup |
| Training | 2-3 hours | Main fine-tuning phase |
| Discovery | 30 minutes | Novel TTP generation |
| Evaluation | 20 minutes | Expert panel simulation |
| Analysis | 15 minutes | Statistical testing |
| Total | 3.5-4 hours | Complete execution |

### 7. Results Export

After completion, your notebook will contain:
- Training loss curves and convergence metrics
- Novel TTP discoveries with validation scores
- Statistical significance testing
- Performance comparisons with baselines
- Take screenshots of key figures and tables

## Cost Considerations

### Google Colab Free Tier
- Cost: Free (within limits)
- GPU: T4 (16GB VRAM)
- Runtime: 12 hours max per session
- Storage: ~77GB temporary
- Model Download: ~20GB from Hugging Face
- Colab Pro: $10/month for faster GPUs and longer runtimes
- Other Options: AWS, GCP, Azure (additional costs)




