/**
 * Reputation History Tracker
 * Maintains historical snapshots of trust scores for trend analysis
 */

import * as fs from 'fs';
import * as path from 'path';
import {
    ReputationHistory,
    ReputationSnapshot,
    HistoryAnomaly,
    AIAnalysisResult,
} from './types';
import { normalizeAddress } from './aiUtils';

// ============================================================================
// Configuration
// ============================================================================

const HISTORY_DIR = path.join(__dirname, 'data', 'history');
const MAX_SNAPSHOTS = 100; // Keep last 100 snapshots per address
const ANOMALY_THRESHOLD = 20; // Score change >= 20 points = anomaly

// Ensure history directory exists
if (!fs.existsSync(HISTORY_DIR)) {
    fs.mkdirSync(HISTORY_DIR, { recursive: true });
}

// ============================================================================
// Main Functions
// ============================================================================

export async function saveReputationSnapshot(
    address: string,
    analysisResult: AIAnalysisResult,
    chainId: string = '1'
): Promise<void> {
    const normalized = normalizeAddress(address);
    const history = await loadHistory(normalized, chainId);

    // Create new snapshot
    const snapshot: ReputationSnapshot = {
        timestamp: Date.now(),
        trustScore: 100 - analysisResult.aiRiskScore,
        riskScore: analysisResult.aiRiskScore,
        riskLevel: analysisResult.riskLevel,
        confidence: calculateOverallConfidence(analysisResult),
        engineScores: {
            pattern: analysisResult.engineResults?.patternRecognition?.riskScore,
            behavioral: analysisResult.engineResults?.behavioral?.riskScore,
            security: analysisResult.engineResults?.contractSecurity?.riskScore,
            transaction: analysisResult.engineResults?.transactionRisk?.riskScore,
            osint: analysisResult.engineResults?.osint?.riskScore,
            social: analysisResult.engineResults?.social?.riskScore,
            market: analysisResult.engineResults?.market?.riskScore,
        },
    };

    // Add snapshot
    history.snapshots.push(snapshot);
    history.lastUpdated = Date.now();

    // Trim old snapshots if needed
    if (history.snapshots.length > MAX_SNAPSHOTS) {
        history.snapshots = history.snapshots.slice(-MAX_SNAPSHOTS);
    }

    // Update first seen if this is the first snapshot
    if (history.snapshots.length === 1) {
        history.firstSeen = snapshot.timestamp;
    }

    // Detect anomalies
    const newAnomalies = detectAnomalies(history.snapshots);
    history.anomalies = [...history.anomalies, ...newAnomalies];

    // Calculate trend
    history.trend = calculateTrend(history.snapshots);

    // Save to disk
    await saveHistory(normalized, chainId, history);

    console.log(`[History] Saved snapshot for ${normalized}`);
}

export async function getReputationHistory(
    address: string,
    chainId: string = '1'
): Promise<ReputationHistory | null> {
    const normalized = normalizeAddress(address);
    return await loadHistory(normalized, chainId);
}

// ============================================================================
// File Operations
// ============================================================================

async function loadHistory(
    address: string,
    chainId: string
): Promise<ReputationHistory> {
    const filePath = getHistoryFilePath(address, chainId);

    if (fs.existsSync(filePath)) {
        try {
            const data = fs.readFileSync(filePath, 'utf-8');
            return JSON.parse(data);
        } catch (error) {
            console.log(`[History] Failed to load history for ${address}:`, error);
        }
    }

    // Return empty history
    return {
        address,
        snapshots: [],
        trend: 'stable',
        anomalies: [],
        firstSeen: Date.now(),
        lastUpdated: Date.now(),
    };
}

async function saveHistory(
    address: string,
    chainId: string,
    history: ReputationHistory
): Promise<void> {
    const filePath = getHistoryFilePath(address, chainId);

    try {
        fs.writeFileSync(filePath, JSON.stringify(history, null, 2), 'utf-8');
    } catch (error) {
        console.error(`[History] Failed to save history for ${address}:`, error);
    }
}

function getHistoryFilePath(address: string, chainId: string): string {
    const filename = `${chainId}_${address.toLowerCase()}.json`;
    return path.join(HISTORY_DIR, filename);
}

// ============================================================================
// Trend Analysis
// ============================================================================

function calculateTrend(snapshots: ReputationSnapshot[]): 'improving' | 'stable' | 'declining' {
    if (snapshots.length < 2) {
        return 'stable';
    }

    // Compare recent snapshots (last 5 or all if less)
    const recentCount = Math.min(5, snapshots.length);
    const recent = snapshots.slice(-recentCount);

    const scores = recent.map(s => s.trustScore);
    const firstScore = scores[0];
    const lastScore = scores[scores.length - 1];

    const change = lastScore - firstScore;

    if (change > 10) {
        return 'improving';
    } else if (change < -10) {
        return 'declining';
    } else {
        return 'stable';
    }
}

// ============================================================================
// Anomaly Detection
// ============================================================================

function detectAnomalies(snapshots: ReputationSnapshot[]): HistoryAnomaly[] {
    const anomalies: HistoryAnomaly[] = [];

    if (snapshots.length < 2) {
        return anomalies;
    }

    // Check last two snapshots for sudden changes
    const current = snapshots[snapshots.length - 1];
    const previous = snapshots[snapshots.length - 2];

    const scoreChange = current.trustScore - previous.trustScore;

    // Sudden drop in trust score
    if (scoreChange < -ANOMALY_THRESHOLD) {
        anomalies.push({
            timestamp: current.timestamp,
            type: 'sudden_drop',
            description: `Trust score dropped by ${Math.abs(scoreChange).toFixed(1)} points`,
            scoreChange,
        });
    }

    // Sudden rise in trust score
    if (scoreChange > ANOMALY_THRESHOLD) {
        anomalies.push({
            timestamp: current.timestamp,
            type: 'sudden_rise',
            description: `Trust score increased by ${scoreChange.toFixed(1)} points`,
            scoreChange,
        });
    }

    // Risk level changed dramatically
    if (previous.riskLevel !== current.riskLevel) {
        const riskLevels = ['Safe', 'Low', 'Medium', 'High', 'Critical'];
        const prevIndex = riskLevels.indexOf(previous.riskLevel);
        const currIndex = riskLevels.indexOf(current.riskLevel);

        if (Math.abs(currIndex - prevIndex) >= 2) {
            anomalies.push({
                timestamp: current.timestamp,
                type: currIndex > prevIndex ? 'new_threat' : 'sudden_rise',
                description: `Risk level changed from ${previous.riskLevel} to ${current.riskLevel}`,
                scoreChange,
            });
        }
    }

    // Volatility detection (multiple large changes)
    if (snapshots.length >= 5) {
        const recentChanges = [];
        for (let i = snapshots.length - 5; i < snapshots.length - 1; i++) {
            const change = Math.abs(snapshots[i + 1].trustScore - snapshots[i].trustScore);
            recentChanges.push(change);
        }

        const avgChange = recentChanges.reduce((a, b) => a + b, 0) / recentChanges.length;
        if (avgChange > 15) {
            anomalies.push({
                timestamp: current.timestamp,
                type: 'volatility',
                description: `High volatility detected (avg change: ${avgChange.toFixed(1)})`,
                scoreChange: avgChange,
            });
        }
    }

    return anomalies;
}

// ============================================================================
// Utility Functions
// ============================================================================

function calculateOverallConfidence(result: AIAnalysisResult): number {
    const confidences: number[] = [];

    if (result.engineResults?.patternRecognition) {
        confidences.push(result.engineResults.patternRecognition.confidence);
    }
    if (result.engineResults?.behavioral) {
        confidences.push(result.engineResults.behavioral.confidence);
    }
    if (result.engineResults?.contractSecurity) {
        confidences.push(result.engineResults.contractSecurity.confidence);
    }
    if (result.engineResults?.transactionRisk) {
        confidences.push(result.engineResults.transactionRisk.confidence);
    }
    if (result.engineResults?.osint) {
        confidences.push(result.engineResults.osint.confidence);
    }
    if (result.engineResults?.social) {
        confidences.push(result.engineResults.social.confidence);
    }
    if (result.engineResults?.market) {
        confidences.push(result.engineResults.market.confidence);
    }

    if (confidences.length === 0) {
        return 0.5;
    }

    return confidences.reduce((a, b) => a + b, 0) / confidences.length;
}

export function getHistorySummary(history: ReputationHistory): string {
    if (history.snapshots.length === 0) {
        return 'No historical data available.';
    }

    const latest = history.snapshots.slice(-1)[0];
    const daysTracked = Math.floor((Date.now() - history.firstSeen) / (1000 * 60 * 60 * 24));

    let summary = `Tracked for ${daysTracked} days with ${history.snapshots.length} snapshot(s). `;
    summary += `Current trust score: ${latest.trustScore.toFixed(0)}/100. `;
    summary += `Trend: ${history.trend}. `;

    if (history.anomalies.length > 0) {
        summary += `${history.anomalies.length} anomaly/ies detected.`;
    }

    return summary;
}
