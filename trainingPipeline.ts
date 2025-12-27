/**
 * Training Pipeline for CENCERA AI Model
 * Complete workflow for training the threat detection model
 */

import { buildModel, trainModel, evaluateModel, saveModel, ModelConfig, DEFAULT_MODEL_CONFIG } from './aiModel';
import { prepareTrainingDataset, balanceDataset, augmentData, getDatasetStats } from './dataPreparation';
import { TrainingData } from './aiModel';
import * as tf from '@tensorflow/tfjs';

// ============================================================================
// Main Training Pipeline
// ============================================================================

export async function runTrainingPipeline(config: ModelConfig = DEFAULT_MODEL_CONFIG): Promise<void> {
    console.log('='.repeat(60));
    console.log('CENCERA AI MODEL TRAINING PIPELINE');
    console.log('='.repeat(60));

    try {
        // Step 1: Prepare data
        console.log('\n[Step 1/5] Preparing training data...');
        const { training: rawTraining, test: testData } = await prepareTrainingDataset();

        // Step 2: Balance and augment data
        console.log('\n[Step 2/5] Balancing and augmenting data...');
        const balancedData = balanceDataset(rawTraining);
        const trainingData = augmentData(balancedData, 1.5);

        // Print dataset statistics
        console.log('\n--- Dataset Statistics ---');
        const trainStats = getDatasetStats(trainingData);
        const testStats = getDatasetStats(testData);
        console.log(`Training: ${trainStats.totalSamples} samples (${trainStats.positiveSamples} threats, ${trainStats.negativeSamples} safe)`);
        console.log(`Test: ${testStats.totalSamples} samples (${testStats.positiveSamples} threats, ${testStats.negativeSamples} safe)`);
        console.log(`Class balance: ${(trainStats.classBalance * 100).toFixed(1)}%`);

        // Step 3: Build model
        console.log('\n[Step 3/5] Building neural network...');
        const model = buildModel(config);

        // Step 4: Train model
        console.log('\n[Step 4/5] Training model...');
        const startTime = Date.now();
        const history = await trainModel(model, trainingData, config);
        const trainingTime = (Date.now() - startTime) / 1000;

        console.log(`\nTraining completed in ${trainingTime.toFixed(1)}s`);

        // Step 5: Evaluate model
        console.log('\n[Step 5/5] Evaluating model on test set...');
        const metrics = await evaluateModel(model, testData);

        // Save model
        console.log('\nSaving trained model...');
        const version = `v${Date.now()}`;
        const metadata = {
            version,
            trainedAt: new Date().toISOString(),
            trainingTime: `${trainingTime.toFixed(1)}s`,
            config,
            datasetStats: {
                training: trainStats,
                test: testStats,
            },
            metrics,
        };

        await saveModel(model, version, metadata);
        await saveModel(model, 'latest', metadata);

        // Print final summary
        console.log('\n' + '='.repeat(60));
        console.log('TRAINING COMPLETE');
        console.log('='.repeat(60));
        console.log(`Model version: ${version}`);
        console.log(`Accuracy: ${(metrics.accuracy * 100).toFixed(2)}%`);
        console.log(`Precision: ${(metrics.precision * 100).toFixed(2)}%`);
        console.log(`Recall: ${(metrics.recall * 100).toFixed(2)}%`);
        console.log(`F1 Score: ${(metrics.f1Score * 100).toFixed(2)}%`);
        console.log('='.repeat(60));

    } catch (error) {
        console.error('\n❌ Training failed:', error);
        throw error;
    }
}

// ============================================================================
// Quick Train (for testing)
// ============================================================================

export async function quickTrain(): Promise<void> {
    console.log('Starting quick training (10 epochs)...\n');

    const quickConfig: ModelConfig = {
        ...DEFAULT_MODEL_CONFIG,
        epochs: 10,
        batchSize: 16,
    };

    await runTrainingPipeline(quickConfig);
}

// ============================================================================
// Production Train
// ============================================================================

export async function productionTrain(): Promise<void> {
    console.log('Starting production training (100 epochs)...\n');

    await runTrainingPipeline(DEFAULT_MODEL_CONFIG);
}

// ============================================================================
// CLI Entry Point
// ============================================================================

if (require.main === module) {
    const args = process.argv.slice(2);
    const mode = args[0] || 'quick';

    if (mode === 'quick') {
        quickTrain().catch(console.error);
    } else if (mode === 'production') {
        productionTrain().catch(console.error);
    } else {
        console.log('Usage: ts-node trainingPipeline.ts [quick|production]');
    }
}
