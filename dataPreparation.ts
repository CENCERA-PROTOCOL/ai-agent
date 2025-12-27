/**
 * Data Preparation for CENCERA AI Model
 * Prepares training data from threat intelligence database
 */

import * as fs from 'fs';
import * as path from 'path';
import { loadAllScamAddresses, loadAllSafeAddresses } from './knowledgeBase';
import { extractFeatures } from './featureExtractor';
import { AIAnalysisRequest } from './types';
import { TrainingData } from './aiModel';

// ============================================================================
// Data Loading
// ============================================================================

export async function prepareTrainingDataset(): Promise<{
    training: TrainingData;
    test: TrainingData;
}> {
    console.log('[Data Prep] Loading threat intelligence...');

    // Load known scam and safe addresses
    const scamAddresses = Array.from(loadAllScamAddresses());
    const safeAddresses = Array.from(loadAllSafeAddresses());

    console.log(`[Data Prep] Loaded ${scamAddresses.length} scam addresses`);
    console.log(`[Data Prep] Loaded ${safeAddresses.length} safe addresses`);

    // Create labeled dataset
    const scamSamples = scamAddresses.map(addr => ({
        address: addr,
        label: 1, // Scam = 1
    }));

    const safeSamples = safeAddresses.map(addr => ({
        address: addr,
        label: 0, // Safe = 0
    }));

    // Combine and shuffle
    const allSamples = [...scamSamples, ...safeSamples];
    shuffleArray(allSamples);

    console.log(`[Data Prep] Total samples: ${allSamples.length}`);

    // Extract features for all samples
    const features: number[][] = [];
    const labels: number[] = [];

    for (const sample of allSamples) {
        try {
            // Create minimal request object for feature extraction
            const request: AIAnalysisRequest = {
                address: sample.address,
                balance: '0',
                txCount: 0,
                isContract: sample.address.startsWith('0x') && sample.address.length === 42,
                codeSize: 0,
            };

            const featureVector = extractFeatures(request);
            features.push(featureVector);
            labels.push(sample.label);
        } catch (error) {
            console.warn(`[Data Prep] Failed to extract features for ${sample.address}:`, error);
        }
    }

    console.log(`[Data Prep] Extracted features for ${features.length} samples`);

    // Split into training (80%) and test (20%)
    const splitIndex = Math.floor(features.length * 0.8);

    const trainingData: TrainingData = {
        features: features.slice(0, splitIndex),
        labels: labels.slice(0, splitIndex),
    };

    const testData: TrainingData = {
        features: features.slice(splitIndex),
        labels: labels.slice(splitIndex),
    };

    console.log(`[Data Prep] Training samples: ${trainingData.features.length}`);
    console.log(`[Data Prep] Test samples: ${testData.features.length}`);

    // Save prepared data
    await saveDataset(trainingData, 'training');
    await saveDataset(testData, 'test');

    return { training: trainingData, test: testData };
}

// ============================================================================
// Data Balancing
// ============================================================================

export function balanceDataset(data: TrainingData): TrainingData {
    // Count positive and negative samples
    const positiveIndices: number[] = [];
    const negativeIndices: number[] = [];

    data.labels.forEach((label, idx) => {
        if (label === 1) positiveIndices.push(idx);
        else negativeIndices.push(idx);
    });

    console.log(`[Data Prep] Positive samples: ${positiveIndices.length}`);
    console.log(`[Data Prep] Negative samples: ${negativeIndices.length}`);

    // Determine minority class
    const minSize = Math.min(positiveIndices.length, negativeIndices.length);

    // Undersample majority class
    const selectedPositive = positiveIndices.slice(0, minSize);
    const selectedNegative = negativeIndices.slice(0, minSize);

    const selectedIndices = [...selectedPositive, ...selectedNegative];
    shuffleArray(selectedIndices);

    // Create balanced dataset
    const balancedFeatures = selectedIndices.map(idx => data.features[idx]);
    const balancedLabels = selectedIndices.map(idx => data.labels[idx]);

    console.log(`[Data Prep] Balanced dataset size: ${balancedFeatures.length}`);

    return {
        features: balancedFeatures,
        labels: balancedLabels,
    };
}

// ============================================================================
// Data Augmentation
// ============================================================================

export function augmentData(data: TrainingData, augmentationFactor: number = 1.5): TrainingData {
    const augmentedFeatures: number[][] = [...data.features];
    const augmentedLabels: number[] = [...data.labels];

    const samplesToAdd = Math.floor(data.features.length * (augmentationFactor - 1));

    for (let i = 0; i < samplesToAdd; i++) {
        // Randomly select a sample
        const idx = Math.floor(Math.random() * data.features.length);
        const baseFeatures = data.features[idx];
        const label = data.labels[idx];

        // Add small random noise to features
        const noisyFeatures = baseFeatures.map(f => {
            const noise = (Math.random() - 0.5) * 0.1; // ±5% noise
            return Math.max(0, Math.min(1, f + noise));
        });

        augmentedFeatures.push(noisyFeatures);
        augmentedLabels.push(label);
    }

    console.log(`[Data Prep] Augmented dataset from ${data.features.length} to ${augmentedFeatures.length}`);

    return {
        features: augmentedFeatures,
        labels: augmentedLabels,
    };
}

// ============================================================================
// Data Persistence
// ============================================================================

const DATA_DIR = path.join(__dirname, 'data', 'training');

async function saveDataset(data: TrainingData, name: string): Promise<void> {
    if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
    }

    const filePath = path.join(DATA_DIR, `${name}.json`);
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));

    console.log(`[Data Prep] Saved ${name} dataset to ${filePath}`);
}

export function loadDataset(name: string): TrainingData | null {
    const filePath = path.join(DATA_DIR, `${name}.json`);

    if (!fs.existsSync(filePath)) {
        return null;
    }

    const data = fs.readFileSync(filePath, 'utf-8');
    return JSON.parse(data);
}

// ============================================================================
// Utility Functions
// ============================================================================

function shuffleArray<T>(array: T[]): void {
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
    }
}

// ============================================================================
// Data Statistics
// ============================================================================

export function getDatasetStats(data: TrainingData): {
    totalSamples: number;
    positiveSamples: number;
    negativeSamples: number;
    featureDimensions: number;
    classBalance: number;
} {
    const positiveSamples = data.labels.filter(l => l === 1).length;
    const negativeSamples = data.labels.filter(l => l === 0).length;

    return {
        totalSamples: data.labels.length,
        positiveSamples,
        negativeSamples,
        featureDimensions: data.features[0]?.length || 0,
        classBalance: positiveSamples / (positiveSamples + negativeSamples),
    };
}
