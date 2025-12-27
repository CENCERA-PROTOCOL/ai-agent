/**
 * Utility Functions for AI Analysis
 * Statistical functions, pattern matching helpers, and caching utilities
 */

import { CacheEntry, StatisticalMetrics, ConfidenceScore } from './types';

// ============================================================================
// Statistical Functions
// ============================================================================

/**
 * Calculate mean (average) of an array of numbers
 */
export function mean(values: number[]): number {
    if (values.length === 0) return 0;
    return values.reduce((sum, val) => sum + val, 0) / values.length;
}

/**
 * Calculate standard deviation
 */
export function stdDev(values: number[]): number {
    if (values.length === 0) return 0;
    const avg = mean(values);
    const squareDiffs = values.map(value => Math.pow(value - avg, 2));
    const avgSquareDiff = mean(squareDiffs);
    return Math.sqrt(avgSquareDiff);
}

/**
 * Calculate z-score (number of standard deviations from mean)
 */
export function zScore(value: number, values: number[]): number {
    const avg = mean(values);
    const std = stdDev(values);
    if (std === 0) return 0;
    return (value - avg) / std;
}

/**
 * Calculate median
 */
export function median(values: number[]): number {
    if (values.length === 0) return 0;
    const sorted = [...values].sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);

    if (sorted.length % 2 === 0) {
        return (sorted[mid - 1] + sorted[mid]) / 2;
    }
    return sorted[mid];
}

/**
 * Calculate full statistical metrics
 */
export function calculateStatistics(values: number[]): StatisticalMetrics {
    return {
        mean: mean(values),
        stdDev: stdDev(values),
        min: Math.min(...values),
        max: Math.max(...values),
        median: median(values),
    };
}

/**
 * Detect outliers using IQR method
 */
export function detectOutliers(values: number[]): number[] {
    if (values.length < 4) return [];

    const sorted = [...values].sort((a, b) => a - b);
    const q1Index = Math.floor(sorted.length * 0.25);
    const q3Index = Math.floor(sorted.length * 0.75);

    const q1 = sorted[q1Index];
    const q3 = sorted[q3Index];
    const iqr = q3 - q1;

    const lowerBound = q1 - 1.5 * iqr;
    const upperBound = q3 + 1.5 * iqr;

    return values.filter(v => v < lowerBound || v > upperBound);
}

// ============================================================================
// Risk Score Normalization
// ============================================================================

/**
 * Normalize risk score to 0-100 range
 */
export function normalizeRiskScore(score: number, min = 0, max = 100): number {
    return Math.max(min, Math.min(max, Math.round(score)));
}

/**
 * Map risk score to risk level
 */
export function scoreToRiskLevel(
    score: number
): "Critical" | "High" | "Medium" | "Low" | "Safe" {
    if (score >= 80) return "Critical";
    if (score >= 60) return "High";
    if (score >= 40) return "Medium";
    if (score >= 20) return "Low";
    return "Safe";
}

/**
 * Convert 0-100 risk score to 0-100 trust score (inverse)
 */
export function riskToTrustScore(riskScore: number): number {
    return 100 - normalizeRiskScore(riskScore);
}

/**
 * Weighted average of multiple scores
 */
export function weightedAverage(
    scores: number[],
    weights: number[]
): number {
    if (scores.length !== weights.length) {
        throw new Error('Scores and weights arrays must have same length');
    }

    const weightSum = weights.reduce((sum, w) => sum + w, 0);
    if (weightSum === 0) return 0;

    const weightedSum = scores.reduce(
        (sum, score, i) => sum + score * weights[i],
        0
    );

    return weightedSum / weightSum;
}

// ============================================================================
// Confidence Score Calculation
// ============================================================================

/**
 * Calculate confidence score based on data quality factors
 */
export function calculateConfidence(params: {
    dataPoints: number;
    minDataPoints: number;
    patternClarity: number; // 0-1
    isVerified?: boolean;
}): ConfidenceScore {
    const { dataPoints, minDataPoints, patternClarity, isVerified = false } = params;

    // Sample size confidence (0-1)
    const sampleSize = Math.min(1, dataPoints / minDataPoints);

    // Data quality confidence (0-1)
    const dataQuality = isVerified ? 1.0 : 0.7;

    // Overall confidence (weighted average)
    const overall = weightedAverage(
        [dataQuality, sampleSize, patternClarity],
        [0.3, 0.3, 0.4]
    );

    return {
        overall,
        factors: {
            dataQuality,
            sampleSize,
            patternClarity,
        },
    };
}

// ============================================================================
// Pattern Matching Helpers
// ============================================================================

/**
 * Calculate similarity between two strings (Levenshtein distance)
 */
export function stringSimilarity(str1: string, str2: string): number {
    const len1 = str1.length;
    const len2 = str2.length;
    const matrix: number[][] = Array.from({ length: len1 + 1 }, () =>
        Array(len2 + 1).fill(0)
    );

    for (let i = 0; i <= len1; i++) matrix[i][0] = i;
    for (let j = 0; j <= len2; j++) matrix[0][j] = j;

    for (let i = 1; i <= len1; i++) {
        for (let j = 1; j <= len2; j++) {
            const cost = str1[i - 1] === str2[j - 1] ? 0 : 1;
            matrix[i][j] = Math.min(
                matrix[i - 1][j] + 1,
                matrix[i][j - 1] + 1,
                matrix[i - 1][j - 1] + cost
            );
        }
    }

    const distance = matrix[len1][len2];
    const maxLen = Math.max(len1, len2);
    return maxLen === 0 ? 1 : 1 - distance / maxLen;
}

/**
 * Check if bytecode contains specific pattern
 */
export function containsBytecodePattern(
    bytecode: string,
    pattern: string
): boolean {
    return bytecode.toLowerCase().includes(pattern.toLowerCase());
}

/**
 * Extract function selectors from bytecode (first 4 bytes of keccak256)
 */
export function extractFunctionSelectors(bytecode: string): string[] {
    const selectors: string[] = [];
    const hex = bytecode.toLowerCase().replace('0x', '');

    // Look for PUSH4 opcode (0x63) followed by 4 bytes (8 hex chars)
    for (let i = 0; i < hex.length - 8; i += 2) {
        if (hex.substring(i, i + 2) === '63') {
            const selector = '0x' + hex.substring(i + 2, i + 10);
            selectors.push(selector);
        }
    }

    return [...new Set(selectors)]; // Remove duplicates
}

/**
 * Check for dangerous opcodes in bytecode
 */
export function detectDangerousOpcodes(bytecode: string): string[] {
    const dangerous: string[] = [];
    const hex = bytecode.toLowerCase().replace('0x', '');

    const opcodes = {
        'ff': 'SELFDESTRUCT',
        'f4': 'DELEGATECALL',
        'f0': 'CREATE',
        'f5': 'CREATE2',
    };

    for (let i = 0; i < hex.length; i += 2) {
        const opcode = hex.substring(i, i + 2);
        if (opcodes[opcode as keyof typeof opcodes]) {
            dangerous.push(opcodes[opcode as keyof typeof opcodes]);
        }
    }

    return [...new Set(dangerous)];
}

// ============================================================================
// Caching Utilities
// ============================================================================

const cache = new Map<string, CacheEntry<any>>();

/**
 * Generate cache key from multiple parameters
 */
export function generateCacheKey(...params: any[]): string {
    return params.map(p => String(p)).join(':');
}

/**
 * Get cached value if not expired
 */
export function getCached<T>(key: string): T | null {
    const entry = cache.get(key);
    if (!entry) return null;

    const now = Date.now();
    if (now - entry.timestamp > entry.ttl) {
        cache.delete(key);
        return null;
    }

    return entry.data as T;
}

/**
 * Set cached value with TTL
 */
export function setCached<T>(key: string, data: T, ttl: number): void {
    cache.set(key, {
        data,
        timestamp: Date.now(),
        ttl,
    });
}

/**
 * Clear cache (optionally by key pattern)
 */
export function clearCache(keyPattern?: string): void {
    if (!keyPattern) {
        cache.clear();
        return;
    }

    const keys = Array.from(cache.keys());
    keys.forEach(key => {
        if (key.includes(keyPattern)) {
            cache.delete(key);
        }
    });
}

// ============================================================================
// Hash Functions
// ============================================================================

/**
 * Simple hash function for config objects (for cache keys)
 */
export function hashConfig(config: any): string {
    const str = JSON.stringify(config);
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = (hash << 5) - hash + char;
        hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(36);
}

// ============================================================================
// Address Utilities
// ============================================================================

/**
 * Normalize address based on format
 * - EVM (0x...): Lowercase
 * - Non-EVM (Solana, Cosmos, etc.): Preserve case
 */
export function normalizeAddress(address: string): string {
    // Check for EVM format (0x followed by hex)
    if (address.startsWith('0x')) {
        return address.toLowerCase();
    }
    // For non-EVM (Base58, Bech32), preserve case as it carries information
    return address;
}

/**
 * Check if address is valid Ethereum address format
 */
export function isValidAddress(address: string): boolean {
    return /^0x[a-fA-F0-9]{40}$/.test(address);
}

/**
 * Truncate address for display (0x1234...5678)
 */
export function truncateAddress(address: string, chars = 4): string {
    if (!isValidAddress(address)) return address;
    return `${address.substring(0, chars + 2)}...${address.substring(address.length - chars)}`;
}
