/**
 * CENCERA AI Model
 * Neural network for blockchain threat detection
 * Trained on threat intelligence data
 */

import * as tf from '@tensorflow/tfjs';
import * as fs from 'fs';
import * as path from 'path';

// ============================================================================
// Model Architecture Configuration
// ============================================================================

export interface ModelConfig {
    inputDim: number;           // Number of input features
    hiddenLayers: number[];     // Neurons in each hidden layer
    outputDim: number;          // Number of output classes (1 for binary)
    learningRate: number;
    epochs: number;
    batchSize: number;
    validationSplit: number;
}

export const DEFAULT_MODEL_CONFIG: ModelConfig = {
    inputDim: 52,              // 52 features from blockchain data
    hiddenLayers: [128, 64, 32], // 3 hidden layers
    outputDim: 1,              // Binary classification: threat or safe
    learningRate: 0.001,
    epochs: 100,
    batchSize: 32,
    validationSplit: 0.2,
};

// ============================================================================
// Feature Names (for explainability)
// ============================================================================

export const FEATURE_NAMES = [
    // Transaction features (15)
    'tx_count', 'avg_tx_value', 'max_tx_value', 'min_tx_value',
    'tx_frequency', 'avg_gas_used', 'max_gas_price', 'unique_interactions',
    'incoming_tx_count', 'outgoing_tx_count', 'failed_tx_ratio',
    'contract_interactions', 'token_transfers', 'eth_transfers', 'tx_stddev',

    // Bytecode features (20)
    'bytecode_size', 'unique_opcodes', 'selfdestruct_count', 'delegatecall_count',
    'create_count', 'create2_count', 'sload_count', 'sstore_count',
    'call_count', 'staticcall_count', 'log_count', 'revert_count',
    'opcode_entropy', 'function_count', 'has_fallback', 'has_receive',
    'dangerous_pattern_count', 'known_selector_count', 'proxy_pattern',
    'upgrade_pattern',

    // Network features (10)
    'creator_age_days', 'creator_tx_count', 'creator_reputation',
    'funding_source_reputation', 'interaction_centrality', 'cluster_size',
    'known_entity_interactions', 'exchange_interactions', 'mixer_interactions',
    'bridge_interactions',

    // Temporal features (5)
    'age_days', 'last_activity_days', 'activity_frequency',
    'creation_to_first_tx', 'rapid_activity_periods',

    // Token features (2 - only for token contracts)
    'holder_concentration', 'liquidity_ratio',
];

// ============================================================================
// Model Building
// ============================================================================

export function buildModel(config: ModelConfig = DEFAULT_MODEL_CONFIG): tf.Sequential {
    const model = tf.sequential();

    // Input layer
    model.add(tf.layers.dense({
        inputShape: [config.inputDim],
        units: config.hiddenLayers[0],
        activation: 'relu',
        kernelInitializer: 'heNormal',
        name: 'input_dense',
    }));

    // Batch normalization for better training
    model.add(tf.layers.batchNormalization({ name: 'bn_1' }));

    // Dropout to prevent overfitting
    model.add(tf.layers.dropout({ rate: 0.3, name: 'dropout_1' }));

    // Hidden layers
    config.hiddenLayers.slice(1).forEach((units, idx) => {
        model.add(tf.layers.dense({
            units,
            activation: 'relu',
            kernelInitializer: 'heNormal',
            name: `hidden_${idx + 2}`,
        }));

        model.add(tf.layers.batchNormalization({ name: `bn_${idx + 2}` }));
        model.add(tf.layers.dropout({ rate: 0.2, name: `dropout_${idx + 2}` }));
    });

    // Output layer
    model.add(tf.layers.dense({
        units: config.outputDim,
        activation: 'sigmoid',  // Sigmoid for binary classification
        name: 'output',
    }));

    // Compile model
    model.compile({
        optimizer: tf.train.adam(config.learningRate),
        loss: 'binaryCrossentropy',
        metrics: ['accuracy'], // Browser TensorFlow only supports accuracy
    });

    console.log('[AI Model] Model architecture:');
    model.summary();

    return model;
}

// ============================================================================
// Model Training
// ============================================================================

export interface TrainingData {
    features: number[][];  // 2D array: [samples, features]
    labels: number[];      // 1D array: [samples]
}

export async function trainModel(
    model: tf.Sequential,
    data: TrainingData,
    config: ModelConfig = DEFAULT_MODEL_CONFIG
): Promise<tf.History> {
    console.log('[AI Model] Starting training...');
    console.log(`[AI Model] Training samples: ${data.features.length}`);

    // Convert to tensors
    const xs = tf.tensor2d(data.features);
    const ys = tf.tensor2d(data.labels, [data.labels.length, 1]);

    // Callbacks for training
    const callbacks: tf.CustomCallbackArgs = {
        onEpochEnd: async (epoch, logs) => {
            if (logs) {
                console.log(
                    `Epoch ${epoch + 1}/${config.epochs} - ` +
                    `loss: ${logs.loss.toFixed(4)} | ` +
                    `acc: ${logs.acc?.toFixed(4)} | ` +
                    `val_loss: ${logs.val_loss?.toFixed(4)} | ` +
                    `val_acc: ${logs.val_acc?.toFixed(4)}`
                );
            }
        },
        onTrainEnd: async () => {
            console.log('[AI Model] Training completed!');
        },
    };

    // Train the model
    const history = await model.fit(xs, ys, {
        epochs: config.epochs,
        batchSize: config.batchSize,
        validationSplit: config.validationSplit,
        callbacks,
        shuffle: true,
        verbose: 0,  // We handle logging in callbacks
    });

    // Cleanup tensors
    xs.dispose();
    ys.dispose();

    return history;
}

// ============================================================================
// Model Prediction
// ============================================================================

export async function predict(
    model: tf.Sequential,
    features: number[]
): Promise<{ threatProbability: number; isThreat: boolean; confidence: number }> {
    // Convert to tensor
    const input = tf.tensor2d([features], [1, features.length]);

    // Make prediction
    const prediction = model.predict(input) as tf.Tensor;
    const threatProbability = await prediction.data();

    // Cleanup
    input.dispose();
    prediction.dispose();

    const prob = threatProbability[0];
    const isThreat = prob > 0.5;
    const confidence = isThreat ? prob : (1 - prob);

    return {
        threatProbability: prob,
        isThreat,
        confidence,
    };
}

export async function predictBatch(
    model: tf.Sequential,
    featuresArray: number[][]
): Promise<number[]> {
    const input = tf.tensor2d(featuresArray);
    const predictions = model.predict(input) as tf.Tensor;
    const results = await predictions.data();

    input.dispose();
    predictions.dispose();

    return Array.from(results);
}

// ============================================================================
// Model Persistence
// ============================================================================

const MODELS_DIR = path.join(__dirname, 'models');

export async function saveModel(
    model: tf.Sequential,
    version: string = 'latest',
    metadata?: any
): Promise<void> {
    const modelDir = path.join(MODELS_DIR, version);

    // Create directory if it doesn't exist
    if (!fs.existsSync(modelDir)) {
        fs.mkdirSync(modelDir, { recursive: true });
    }

    // Get model weights
    const weights = model.getWeights();
    const weightData: any[] = [];

    for (let i = 0; i < weights.length; i++) {
        const w = weights[i];
        const values = await w.data();
        weightData.push({
            index: i,
            shape: w.shape,
            dtype: w.dtype,
            values: Array.from(values),
        });
    }

    // Save weights
    const weightsPath = path.join(modelDir, 'weights.json');
    fs.writeFileSync(weightsPath, JSON.stringify(weightData, null, 2));

    // Save model config
    const configPath = path.join(modelDir, 'model-config.json');
    const modelConfig = model.toJSON(null, false);
    fs.writeFileSync(configPath, JSON.stringify(modelConfig, null, 2));

    // Save metadata
    if (metadata) {
        const metadataPath = path.join(modelDir, 'metadata.json');
        fs.writeFileSync(metadataPath, JSON.stringify(metadata, null, 2));
    }

    console.log(`[AI Model] Model saved to ${modelDir}`);
}

export async function loadModel(version: string = 'latest'): Promise<tf.Sequential> {
    const modelDir = path.join(MODELS_DIR, version);
    const configPath = path.join(modelDir, 'model-config.json');
    const weightsPath = path.join(modelDir, 'weights.json');

    if (!fs.existsSync(configPath) || !fs.existsSync(weightsPath)) {
        throw new Error(`Model not found at ${modelDir}. Train a model first with 'npm run train:quick'`);
    }

    console.log(`[AI Model] Loading model from ${modelDir}`);

    // Load model config and recreate model
    const configData = fs.readFileSync(configPath, 'utf-8');
    const modelConfig = JSON.parse(configData);
    const model = await tf.models.modelFromJSON(modelConfig) as tf.Sequential;

    // Load weights
    const weightsData = fs.readFileSync(weightsPath, 'utf-8');
    const weightSpecs = JSON.parse(weightsData);

    const weightValues = weightSpecs.map((spec: any) => {
        return tf.tensor(spec.values, spec.shape, spec.dtype);
    });

    model.setWeights(weightValues);

    return model;
}

export function getModelMetadata(version: string = 'latest'): any {
    const metadataPath = path.join(MODELS_DIR, version, 'metadata.json');

    if (!fs.existsSync(metadataPath)) {
        return null;
    }

    const data = fs.readFileSync(metadataPath, 'utf-8');
    return JSON.parse(data);
}

// ============================================================================
// Model Evaluation
// ============================================================================

export interface EvaluationMetrics {
    accuracy: number;
    precision: number;
    recall: number;
    f1Score: number;
    confusion: {
        truePositive: number;
        trueNegative: number;
        falsePositive: number;
        falseNegative: number;
    };
}

export async function evaluateModel(
    model: tf.Sequential,
    testData: TrainingData
): Promise<EvaluationMetrics> {
    console.log('[AI Model] Evaluating model...');

    const predictions = await predictBatch(model, testData.features);

    let tp = 0, tn = 0, fp = 0, fn = 0;

    predictions.forEach((pred, idx) => {
        const predictedLabel = pred > 0.5 ? 1 : 0;
        const actualLabel = testData.labels[idx];

        if (predictedLabel === 1 && actualLabel === 1) tp++;
        else if (predictedLabel === 0 && actualLabel === 0) tn++;
        else if (predictedLabel === 1 && actualLabel === 0) fp++;
        else if (predictedLabel === 0 && actualLabel === 1) fn++;
    });

    const accuracy = (tp + tn) / predictions.length;
    const precision = tp / (tp + fp) || 0;
    const recall = tp / (tp + fn) || 0;
    const f1Score = 2 * (precision * recall) / (precision + recall) || 0;

    console.log('[AI Model] Evaluation metrics:');
    console.log(`  Accuracy:  ${(accuracy * 100).toFixed(2)}%`);
    console.log(`  Precision: ${(precision * 100).toFixed(2)}%`);
    console.log(`  Recall:    ${(recall * 100).toFixed(2)}%`);
    console.log(`  F1 Score:  ${(f1Score * 100).toFixed(2)}%`);

    return {
        accuracy,
        precision,
        recall,
        f1Score,
        confusion: {
            truePositive: tp,
            trueNegative: tn,
            falsePositive: fp,
            falseNegative: fn,
        },
    };
}

// ============================================================================
// Model Singleton (for inference)
// ============================================================================

let cachedModel: tf.Sequential | null = null;

export async function getTrainedModel(): Promise<tf.Sequential> {
    if (!cachedModel) {
        try {
            cachedModel = await loadModel('latest');
            console.log('[AI Model] Loaded trained model from cache');
        } catch (error) {
            console.log('[AI Model] No trained model found, building new model');
            cachedModel = buildModel();
        }
    }
    return cachedModel;
}

export function clearModelCache(): void {
    if (cachedModel) {
        cachedModel.dispose();
        cachedModel = null;
    }
}
