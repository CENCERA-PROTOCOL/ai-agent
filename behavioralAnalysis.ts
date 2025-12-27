/**
 * Behavioral Analysis Engine
 * Analyzes transaction patterns and wallet behavior to identify anomalies
 */

import {
    AIAnalysisRequest,
    BehavioralAnalysisResult,
    BehavioralAnomaly,
} from './types';
import {
    zScore,
    normalizeRiskScore,
    calculateConfidence,
} from './aiUtils';
import { ENGINE_CONFIG } from './config';

const { behavioral: CONFIG } = ENGINE_CONFIG;

/**
 * Analyze wallet/contract behavioral patterns
 */
export async function analyzeBehavior(
    request: AIAnalysisRequest
): Promise<BehavioralAnalysisResult> {
    const anomalies: BehavioralAnomaly[] = [];

    // Classify activity pattern
    const activityPattern = classifyActivityPattern(request);

    // Detect various behavioral anomalies
    const txAnomalies = analyzeTransactionBehavior(request);
    const balanceAnomalies = analyzeBalanceBehavior(request);
    const contractAnomalies = request.isContract
        ? analyzeContractBehavior(request)
        : [];

    anomalies.push(...txAnomalies, ...balanceAnomalies, ...contractAnomalies);

    // Calculate risk score
    const riskScore = calculateBehavioralRiskScore(anomalies, activityPattern);

    // Calculate confidence based on available data
    const confidence = calculateConfidence({
        dataPoints: request.txCount,
        minDataPoints: CONFIG.minTxCountForAnalysis,
        patternClarity: anomalies.length > 0 ? 0.8 : 0.5,
        isVerified: false,
    });

    return {
        riskScore,
        anomalies,
        activityPattern,
        confidence: confidence.overall,
    };
}

/**
 * Classify activity pattern based on transaction history
 */
function classifyActivityPattern(
    request: AIAnalysisRequest
): "normal" | "suspicious" | "bot" | "dormant" | "new" {
    const { txCount, balance, isContract } = request;
    const balanceEth = parseFloat(balance);

    // New wallets (< 7 days old, estimated by low tx count)
    if (txCount <= 3) {
        return "new";
    }

    // Dormant wallets (no recent activity, but has history)
    // In real implementation, we would check last transaction timestamp
    // For now, we'll use low tx count with high balance as proxy
    if (txCount < 10 && balanceEth > 10) {
        return "dormant";
    }

    // Bot-like behavior (extremely high transaction count for contracts)
    if (isContract && txCount > 10000) {
        return "bot";
    }

    // Suspicious: new contract with high activity burst
    if (isContract && txCount > 100 && txCount < 1000) {
        return "suspicious";
    }

    // Normal pattern
    return "normal";
}

/**
 * Analyze transaction-related behavioral anomalies
 */
function analyzeTransactionBehavior(
    request: AIAnalysisRequest
): BehavioralAnomaly[] {
    const anomalies: BehavioralAnomaly[] = [];
    const { txCount, isContract } = request;

    // Statistical baselines for comparison
    // In production, these would be calculated from real blockchain data
    const txCounts = isContract
        ? [100, 200, 500, 1000, 2000] // Sample contract tx counts
        : [10, 50, 100, 200, 500];     // Sample wallet tx counts

    // Calculate z-score for transaction count
    const txZScore = zScore(txCount, txCounts);

    // Detect outliers (statistically abnormal transaction counts)
    if (Math.abs(txZScore) > CONFIG.anomalyZScoreThreshold) {
        const isLow = txZScore < 0;
        anomalies.push({
            type: isLow ? 'low_activity' : 'high_activity',
            description: isLow
                ? `Unusually low transaction count (${txCount}) for this entity type`
                : `Extremely high transaction count (${txCount}) - potential bot or high-frequency trading`,
            severity: Math.min(8, Math.abs(txZScore)),
            zScore: txZScore,
        });
    }

    // Zero transactions is always an anomaly
    if (txCount === 0) {
        anomalies.push({
            type: 'zero_activity',
            description: 'No transaction history found - newly created or never used address',
            severity: 7,
            zScore: 0,
        });
    }

    // Very low transaction count on contracts is suspicious
    if (isContract && txCount > 0 && txCount < 5) {
        anomalies.push({
            type: 'minimal_usage',
            description: 'Contract has very few interactions - possibly abandoned or failed deployment',
            severity: 6,
        });
    }

    return anomalies;
}

/**
 * Analyze balance-related behavioral anomalies
 */
function analyzeBalanceBehavior(
    request: AIAnalysisRequest
): BehavioralAnomaly[] {
    const anomalies: BehavioralAnomaly[] = [];
    const { balance, txCount, isContract } = request;
    const balanceEth = parseFloat(balance);

    // High balance with very low activity
    if (balanceEth > 100 && txCount < 10) {
        anomalies.push({
            type: 'dormant_whale',
            description: `Large balance (${balanceEth.toFixed(2)} ETH) with minimal activity - long-term holder or potential honeypot`,
            severity: 5,
        });
    }

    // High balance with zero transactions (very suspicious)
    if (balanceEth > 10 && txCount === 0) {
        anomalies.push({
            type: 'suspicious_funding',
            description: 'Significant balance with no outgoing transactions - may be locked or honeypot',
            severity: 8,
        });
    }

    // Near-zero balance on active contract
    if (isContract && balanceEth < 0.001 && txCount > 100) {
        anomalies.push({
            type: 'drained_contract',
            description: 'Active contract with near-zero balance - may have been drained or exploited',
            severity: 7,
        });
    }

    // Extremely high balance (outlier detection)
    if (balanceEth > 10000) {
        anomalies.push({
            type: 'whale_address',
            description: `Extremely high balance (${balanceEth.toFixed(2)} ETH) - whale address or exchange`,
            severity: 2, // Not necessarily risky, just notable
        });
    }

    return anomalies;
}

/**
 * Analyze contract-specific behavioral anomalies
 */
function analyzeContractBehavior(
    request: AIAnalysisRequest
): BehavioralAnomaly[] {
    const anomalies: BehavioralAnomaly[] = [];
    const { codeSize, txCount, tokenMetadata } = request;

    // Very small contract (potential proxy)
    if (codeSize < 200) {
        anomalies.push({
            type: 'minimal_contract',
            description: 'Extremely small contract bytecode - likely a proxy or minimal implementation',
            severity: 5,
        });
    }

    // Very large contract
    if (codeSize > 20000) {
        anomalies.push({
            type: 'complex_contract',
            description: 'Very large contract bytecode - complex logic with higher risk surface',
            severity: 4,
        });
    }

    // Token contract without proper metadata
    if (!tokenMetadata && codeSize > 500) {
        // Might be a contract that's not a token, but if it's large, worth noting
        anomalies.push({
            type: 'unidentified_contract',
            description: 'Contract does not implement standard token interface',
            severity: 3,
        });
    }

    // Recently deployed token with high transaction count (potential pump and dump)
    if (tokenMetadata && txCount > 500 && txCount < 2000) {
        anomalies.push({
            type: 'rapid_adoption',
            description: 'Token shows rapid adoption pattern - monitor for pump and dump activity',
            severity: 6,
        });
    }

    return anomalies;
}

/**
 * Calculate overall risk score from behavioral anomalies
 */
function calculateBehavioralRiskScore(
    anomalies: BehavioralAnomaly[],
    activityPattern: string
): number {
    if (anomalies.length === 0) {
        // Base risk based on activity pattern
        const patternRisk: Record<string, number> = {
            normal: 10,
            suspicious: 60,
            bot: 40,
            dormant: 30,
            new: 50,
        };
        return patternRisk[activityPattern] || 30;
    }

    // Weight anomalies by severity
    let totalRisk = 0;
    let totalWeight = 0;

    anomalies.forEach(anomaly => {
        const weight = anomaly.severity / 10; // Normalize severity to 0-1
        const risk = (anomaly.severity / 10) * 100; // Convert to 0-100 scale

        totalRisk += risk * weight;
        totalWeight += weight;
    });

    const anomalyRisk = totalWeight > 0 ? totalRisk / totalWeight : 0;

    // Combine with activity pattern risk
    const patternRisk: Record<string, number> = {
        normal: 0,
        suspicious: 30,
        bot: 20,
        dormant: 15,
        new: 25,
    };

    const baseRisk = patternRisk[activityPattern] || 20;
    const combinedRisk = (anomalyRisk * 0.7) + (baseRisk * 0.3);

    return normalizeRiskScore(combinedRisk);
}

/**
 * Get behavioral summary for reporting
 */
export function getBehavioralSummary(
    result: BehavioralAnalysisResult
): string {
    const { activityPattern, anomalies } = result;

    const patternDescriptions: Record<string, string> = {
        normal: 'normal activity pattern',
        suspicious: 'suspicious activity pattern detected',
        bot: 'bot-like automated behavior',
        dormant: 'dormant with minimal recent activity',
        new: 'newly created with limited history',
    };

    let summary = `Entity exhibits ${patternDescriptions[activityPattern] || 'unknown pattern'}. `;

    if (anomalies.length > 0) {
        const criticalAnomalies = anomalies.filter(a => a.severity >= 7);
        if (criticalAnomalies.length > 0) {
            summary += `${criticalAnomalies.length} critical anomaly detected: ${criticalAnomalies[0].description}. `;
        } else {
            summary += `${anomalies.length} behavioral anomaly(ies) detected. `;
        }
    } else {
        summary += 'No significant behavioral anomalies detected.';
    }

    return summary;
}
