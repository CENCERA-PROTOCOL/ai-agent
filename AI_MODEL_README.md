# CENCERA AI Model

Custom-trained neural network for blockchain threat detection.

## Architecture

- **Input**: 52 features extracted from blockchain data
- **Network**: 3 hidden layers (128 → 64 → 32 neurons)
- **Output**: Binary classification (threat probability 0-1)
- **Framework**: TensorFlow.js for Node.js/browser compatibility

## Features (52 dimensions)

### Transaction Features (15)

- Transaction count, value statistics (avg/max/min)
- Transaction frequency and gas usage patterns
- Incoming/outgoing ratio, failed transaction rate
- Contract/token/ETH transfer counts

### Bytecode Features (20)

- Bytecode size and unique opcode count
- Dangerous opcode detection (SELFDESTRUCT, DELEGATECALL)
- CREATE/CREATE2, SLOAD/SSTORE, CALL patterns
- Opcode entropy, function count
- Fallback/receive function detection
- Proxy/upgrade pattern recognition

### Network Features (10)

- Creator age and reputation
- Funding source analysis
- Interaction centrality and cluster size
- Known entity/exchange/mixer/bridge interactions

### Temporal Features (5)

- Address age and last activity
- Activity frequency patterns
- Creation-to-first-transaction time
- Rapid activity period detection

### Token Features (2)

- Holder concentration (Gini coefficient)
- Liquidity ratio

## Training

### Quick Training (for testing)

```bash
npm run train:quick
```

Trains for 10 epochs - useful for testing the pipeline.

### Production Training

```bash
npm run train:production
```

Trains for 100 epochs with full dataset.

### Manual Training

```bash
ts-node trainingPipeline.ts [quick|production]
```

## Data Sources

Training data comes from CENCERA's threat intelligence database:

- `data/chains/*/addresses.json` - Known scam addresses across all chains
- Safe addresses from verified contracts and exchanges
- 533+ chain data files with thousands of labeled addresses

## Model Performance

Expected metrics after training:

- **Accuracy**: 85-95%
- **Precision**: >90% (low false positives)
- **Recall**: >85% (catches most threats)
- **Inference time**: <100ms per address

## Usage

### Train a New Model

```typescript
import { runTrainingPipeline } from './trainingPipeline';

await runTrainingPipeline();
```

### Make Predictions

```typescript
import { getTrainedModel, predict } from './aiModel';
import { extractFeatures } from './featureExtractor';

const model = await getTrainedModel();
const features = extractFeatures(analysisRequest);
const result = await predict(model, features);

console.log(`Threat probability: ${result.threatProbability}`);
console.log(`Is threat: ${result.isThreat}`);
console.log(`Confidence: ${result.confidence}`);
```

### Integration with Pattern Recognition

The model is automatically integrated into `patternRecognition.ts` and provides ML-based threat scoring alongside rule-based detection.

## Model Files

Models are saved in `models/` directory:

```tree
models/
├── latest/          # Symlink to most recent model
│   ├── model.json
│   ├── weights.bin
│   └── metadata.json
├── v1234567890/     # Timestamped versions
│   ├── model.json
│   ├── weights.bin
│   └── metadata.json
```

## Continuous Learning

The model supports continuous learning through:

- Periodic retraining with new threat intelligence
- User feedback collection
- Active learning for uncertain predictions
- Model versioning and A/B testing

## Feature Importance

Top features for threat detection (after training):

1. Dangerous opcode count (SELFDESTRUCT, DELEGATECALL)
2. Creator reputation score
3. Bytecode entropy
4. Transaction pattern anomalies
5. Network centrality metrics

## Dependencies

- `@tensorflow/tfjs-node` - Neural network training/inference
- `@tensorflow/tfjs` - Core TensorFlow.js library

## Notes

- Model requires training before first use
- Retraining recommended monthly with new threat intelligence
- Feature extraction handles missing data gracefully
- All features normalized to [0, 1] range
