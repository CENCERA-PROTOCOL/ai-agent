/**
 * Feature Extractor for CENCERA AI Model
 * Converts raw blockchain data into 52-dimensional feature vectors
 */

import { AIAnalysisRequest, TokenMetadata } from './types';
import { mean, stdDev, median } from './aiUtils';
import { FEATURE_NAMES } from './aiModel';

// ============================================================================
// Main Feature Extraction
// ============================================================================

export function extractFeatures(request: AIAnalysisRequest): number[] {
    const features: number[] = [];

    // Transaction features (15)
    features.push(...extractTransactionFeatures(request));

    // Bytecode features (20)
    features.push(...extractBytecodeFeatures(request));

    // Network features (10)
    features.push(...extractNetworkFeatures(request));

    // Temporal features (5)
    features.push(...extractTemporalFeatures(request));

    // Token features (2)
    features.push(...extractTokenFeatures(request));

    // Verify we have exactly 52 features
    if (features.length !== 52) {
        throw new Error(`Expected 52 features, got ${features.length}`);
    }

    return features;
}

// ============================================================================
// Transaction Features (15 features)
// ============================================================================

function extractTransactionFeatures(request: AIAnalysisRequest): number[] {
    const features: number[] = [];

    // Basic transaction stats
    features.push(normalizeLog(request.txCount)); // tx_count

    // Parse balance
    const balance = parseFloat(request.balance) || 0;
    features.push(normalizeLog(balance + 1)); // avg_tx_value (estimate)
    features.push(normalizeLog(balance * 2)); // max_tx_value (estimate)
    features.push(normalizeLog(balance * 0.1)); // min_tx_value (estimate)

    // Transaction frequency (txs per day estimate)
    const txFrequency = request.txCount / Math.max(1, features[0]);
    features.push(normalizeTo01(txFrequency, 0, 100)); // tx_frequency

    // Gas estimates (we don't have real data, so estimate)
    features.push(0.5); // avg_gas_used (normalized)
    features.push(0.5); // max_gas_price

    // Unique interactions (estimate based on contract type)
    const uniqueInteractions = request.isContract ? request.txCount * 0.3 : request.txCount * 0.7;
    features.push(normalizeLog(uniqueInteractions)); // unique_interactions

    // Direction split (estimate 50/50)
    features.push(normalizeLog(request.txCount * 0.5)); // incoming_tx_count
    features.push(normalizeLog(request.txCount * 0.5)); // outgoing_tx_count

    // Failed transaction ratio (estimate 5% default)
    features.push(0.05); // failed_tx_ratio

    // Interaction types (estimates)
    features.push(request.isContract ? 0.8 : 0.2); // contract_interactions
    features.push(request.isContract ? 0.6 : 0.4); // token_transfers
    features.push(request.isContract ? 0.3 : 0.7); // eth_transfers

    // Transaction standard deviation (estimate)
    features.push(0.3); // tx_stddev

    return features;
}

// ============================================================================
// Bytecode Features (20 features)
// ============================================================================

function extractBytecodeFeatures(request: AIAnalysisRequest): number[] {
    const features: number[] = [];

    if (!request.isContract || !request.bytecode) {
        // Not a contract - return zeros
        return new Array(20).fill(0);
    }

    const bytecode = request.bytecode.toLowerCase().replace('0x', '');

    // bytecode_size
    features.push(normalizeLog(bytecode.length / 2)); // Divide by 2 for byte count

    // Count specific opcodes
    const opcodes = {
        selfdestruct: countPattern(bytecode, 'ff'),      // SELFDESTRUCT
        delegatecall: countPattern(bytecode, 'f4'),     // DELEGATECALL
        create: countPattern(bytecode, 'f0'),           // CREATE
        create2: countPattern(bytecode, 'f5'),          // CREATE2
        sload: countPattern(bytecode, '54'),            // SLOAD
        sstore: countPattern(bytecode, '55'),           // SSTORE
        call: countPattern(bytecode, 'f1'),             // CALL
        staticcall: countPattern(bytecode, 'fa'),       // STATICCALL
        log: countPattern(bytecode, ['a0', 'a1', 'a2', 'a3', 'a4']), // LOG0-4
        revert: countPattern(bytecode, 'fd'),           // REVERT
    };

    // Unique opcodes (estimate from bytecode diversity)
    const uniqueOpcodes = new Set(bytecode.match(/.{1,2}/g) || []).size;
    features.push(normalizeTo01(uniqueOpcodes, 0, 256)); // unique_opcodes

    features.push(normalizeTo01(opcodes.selfdestruct, 0, 10)); // selfdestruct_count
    features.push(normalizeTo01(opcodes.delegatecall, 0, 10)); // delegatecall_count
    features.push(normalizeTo01(opcodes.create, 0, 10)); // create_count
    features.push(normalizeTo01(opcodes.create2, 0, 10)); // create2_count
    features.push(normalizeLog(opcodes.sload)); // sload_count
    features.push(normalizeLog(opcodes.sstore)); // sstore_count
    features.push(normalizeLog(opcodes.call)); // call_count
    features.push(normalizeLog(opcodes.staticcall)); // staticcall_count
    features.push(normalizeLog(opcodes.log)); // log_count
    features.push(normalizeLog(opcodes.revert)); // revert_count

    // Opcode entropy (diversity measure)
    const entropy = calculateEntropy(bytecode);
    features.push(normalizeTo01(entropy, 0, 8)); // opcode_entropy

    // Function count (estimate from PUSH4 patterns)
    const functionCount = countPattern(bytecode, '63'); // PUSH4 opcode
    features.push(normalizeLog(functionCount)); // function_count

    // Has fallback/receive (heuristic detection)
    const hasFallback = bytecode.includes('33600055') ? 1 : 0; // Common fallback pattern
    const hasReceive = bytecode.includes('00') ? 0.5 : 0; // Estimate
    features.push(hasFallback); // has_fallback
    features.push(hasReceive); // has_receive

    // Dangerous patterns
    const dangerousCount = opcodes.selfdestruct + opcodes.delegatecall;
    features.push(normalizeTo01(dangerousCount, 0, 5)); // dangerous_pattern_count

    // Known selectors (estimate from PUSH4)
    features.push(normalizeTo01(functionCount, 0, 50)); // known_selector_count

    // Proxy/upgrade patterns (heuristic)
    const isProxy = bytecode.includes('3d3d3d3d') ? 1 : 0; // Minimal proxy pattern
    const hasUpgrade = opcodes.delegatecall > 0 ? 0.7 : 0;
    features.push(isProxy); // proxy_pattern
    features.push(hasUpgrade); // upgrade_pattern

    return features;
}

// ============================================================================
// Network Features (10 features)
// ============================================================================

function extractNetworkFeatures(request: AIAnalysisRequest): number[] {
    // These would come from external data sources in production
    // For now, return neutral estimates

    return [
        0.5, // creator_age_days (normalized, unknown)
        0.5, // creator_tx_count
        0.5, // creator_reputation
        0.5, // funding_source_reputation
        0.5, // interaction_centrality
        0.5, // cluster_size
        0.5, // known_entity_interactions
        0.5, // exchange_interactions
        0.5, // mixer_interactions
        0.5, // bridge_interactions
    ];
}

// ============================================================================
// Temporal Features (5 features)
// ============================================================================

function extractTemporalFeatures(request: AIAnalysisRequest): number[] {
    // These would require historical data
    // Return estimates for now

    return [
        0.5, // age_days (normalized)
        0.5, // last_activity_days
        0.5, // activity_frequency
        0.5, // creation_to_first_tx
        0.5, // rapid_activity_periods
    ];
}

// ============================================================================
// Token Features (2 features)
// ============================================================================

function extractTokenFeatures(request: AIAnalysisRequest): number[] {
    if (!request.tokenMetadata) {
        return [0, 0];
    }

    // These would come from market data APIs
    return [
        0.5, // holder_concentration (would need DEX/holder data)
        0.5, // liquidity_ratio (would need liquidity pool data)
    ];
}

// ============================================================================
// Helper Functions
// ============================================================================

function normalizeLog(value: number): number {
    // Logarithmic normalization for values with large range
    return Math.log10(Math.max(value, 1)) / 10; // / 10 to keep in 0-1 range roughly
}

function normalizeTo01(value: number, min: number, max: number): number {
    // Linear normalization to [0, 1]
    return Math.max(0, Math.min(1, (value - min) / (max - min)));
}

function countPattern(bytecode: string, pattern: string | string[]): number {
    const patterns = Array.isArray(pattern) ? pattern : [pattern];
    let count = 0;

    for (const p of patterns) {
        const matches = bytecode.match(new RegExp(p, 'g'));
        count += matches ? matches.length : 0;
    }

    return count;
}

function calculateEntropy(bytecode: string): number {
    const bytes = bytecode.match(/.{1,2}/g) || [];
    const freq: { [key: string]: number } = {};

    // Count frequency of each byte
    bytes.forEach(byte => {
        freq[byte] = (freq[byte] || 0) + 1;
    });

    // Calculate Shannon entropy
    const total = bytes.length;
    let entropy = 0;

    Object.values(freq).forEach(count => {
        const p = count / total;
        entropy -= p * Math.log2(p);
    });

    return entropy;
}

// ============================================================================
// Batch Feature Extraction
// ============================================================================

export function extractFeaturessBatch(requests: AIAnalysisRequest[]): number[][] {
    return requests.map(req => extractFeatures(req));
}

// ============================================================================
// Feature Importance (for explainability)
// ============================================================================

export interface FeatureImportance {
    name: string;
    value: number;
    importance: number; // 0-1, higher = more important
}

export function getTopFeatures(
    features: number[],
    importanceWeights?: number[]
): FeatureImportance[] {
    const weights = importanceWeights || getDefaultImportanceWeights();

    const featureImportance: FeatureImportance[] = features.map((value, idx) => ({
        name: FEATURE_NAMES[idx],
        value,
        importance: weights[idx],
    }));

    // Sort by importance
    return featureImportance.sort((a, b) => b.importance - a.importance);
}

function getDefaultImportanceWeights(): number[] {
    // Default importance based on feature category
    // These would be updated after training with actual feature importance
    const weights = new Array(52);

    // Transaction features: moderate importance
    for (let i = 0; i < 15; i++) weights[i] = 0.6;

    // Bytecode features: high importance for contracts
    for (let i = 15; i < 35; i++) weights[i] = 0.9;

    // Network features: high importance
    for (let i = 35; i < 45; i++) weights[i] = 0.8;

    // Temporal features: moderate importance
    for (let i = 45; i < 50; i++) weights[i] = 0.5;

    // Token features: moderate importance
    for (let i = 50; i < 52; i++) weights[i] = 0.6;

    return weights;
}

// ============================================================================
// Feature Validation
// ============================================================================

export function validateFeatures(features: number[]): boolean {
    if (features.length !== 52) {
        console.error(`Invalid feature count: ${features.length}`);
        return false;
    }

    // Check for NaN or Infinity
    for (let i = 0; i < features.length; i++) {
        if (!isFinite(features[i])) {
            console.error(`Invalid feature at index ${i}: ${features[i]}`);
            return false;
        }
    }

    return true;
}
