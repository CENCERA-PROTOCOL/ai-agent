/**
 * Transaction Risk Engine
 * Evaluates transaction safety and identifies potential risks
 */

import {
    AIAnalysisRequest,
    TransactionRiskResult,
    TransactionRisk,
} from './types';
import {
    normalizeRiskScore,
    calculateConfidence,
} from './aiUtils';
import { isKnownScam, isWhitelisted } from './knowledgeBase';
import { ENGINE_CONFIG } from './config';

const { transactionRisk: CONFIG } = ENGINE_CONFIG;

/**
 * Analyze transaction risks
 */
export async function analyzeTransactionRisk(
    request: AIAnalysisRequest
): Promise<TransactionRiskResult> {
    const risks: TransactionRisk[] = [];

    // Analyze recipient address risks
    const recipientRisks = analyzeRecipientRisk(request);
    risks.push(...recipientRisks);

    // Analyze value transfer risks
    const valueRisks = analyzeValueRisk(request);
    risks.push(...valueRisks);

    // Analyze contract interaction risks
    if (request.isContract) {
        const contractRisks = analyzeContractInteractionRisk(request);
        risks.push(...contractRisks);
    }

    // Calculate overall risk score
    const riskScore = calculateTransactionRiskScore(risks);

    // Determine if transaction is safe
    const isSafe = riskScore < 30 && risks.filter(r => r.severity >= 8).length === 0;

    // Calculate confidence
    const confidence = calculateConfidence({
        dataPoints: risks.length + (request.isContract ? 1 : 0),
        minDataPoints: 1,
        patternClarity: risks.length > 0 ? 0.8 : 0.6,
        isVerified: false,
    });

    return {
        riskScore,
        risks,
        isSafe,
        confidence: confidence.overall,
    };
}

/**
 * Analyze recipient address risks
 */
function analyzeRecipientRisk(request: AIAnalysisRequest): TransactionRisk[] {
    const risks: TransactionRisk[] = [];
    const { address } = request;

    // Check if recipient is known scam
    if (isKnownScam(address)) {
        risks.push({
            type: 'known_scam_recipient',
            description: 'Recipient address is flagged as a known scam in threat database',
            severity: 10,
        });
    }

    // Check if recipient is whitelisted (good sign)
    if (isWhitelisted(address)) {
        risks.push({
            type: 'verified_recipient',
            description: 'Recipient is a verified, trusted address',
            severity: 0, // This is actually a positive indicator
        });
        return risks; // Skip other checks for whitelisted addresses
    }

    // New address with no history
    if (request.txCount === 0) {
        risks.push({
            type: 'new_recipient',
            description: 'Recipient has no transaction history - newly created address',
            severity: 6,
        });
    }

    // Very low activity address
    if (request.txCount > 0 && request.txCount < 5) {
        risks.push({
            type: 'low_activity_recipient',
            description: `Recipient has minimal transaction history (${request.txCount} transactions)`,
            severity: 4,
        });
    }

    return risks;
}

/**
 * Analyze value transfer risks
 */
function analyzeValueRisk(request: AIAnalysisRequest): TransactionRisk[] {
    const risks: TransactionRisk[] = [];
    const balance = parseFloat(request.balance);

    // High-value transfer to new address
    if (balance > 10 && request.txCount < 10) {
        risks.push({
            type: 'high_value_to_new',
            description: 'Large balance transfer to address with limited history',
            severity: 7,
        });
    }

    // Transfer to address with zero balance (might be a burner)
    if (balance === 0) {
        risks.push({
            type: 'zero_balance_recipient',
            description: 'Recipient has zero balance - possible burner address',
            severity: 5,
        });
    }

    return risks;
}

/**
 * Analyze contract interaction risks
 */
function analyzeContractInteractionRisk(
    request: AIAnalysisRequest
): TransactionRisk[] {
    const risks: TransactionRisk[] = [];
    const { codeSize, tokenMetadata } = request;

    // Interacting with unverified contract
    if (!tokenMetadata && codeSize > 1000) {
        risks.push({
            type: 'unverified_contract_interaction',
            description: 'Contract source code is not verified - cannot audit functionality',
            severity: 8,
        });
    }

    // Very small contract (possible proxy)
    if (codeSize < 200) {
        risks.push({
            type: 'proxy_contract_risk',
            description: 'Contract appears to be a proxy - actual logic may be in upgradeable implementation',
            severity: 6,
        });
    }

    // Very large contract (complex logic)
    if (codeSize > 15000) {
        risks.push({
            type: 'complex_contract_interaction',
            description: 'Contract is very large with complex logic - higher risk surface area',
            severity: 5,
        });
    }

    // New contract deployment
    if (request.txCount < 50) {
        risks.push({
            type: 'new_contract_risk',
            description: 'Contract is recently deployed with limited usage history',
            severity: 7,
        });
    }

    return risks;
}

/**
 * Calculate overall transaction risk score
 */
function calculateTransactionRiskScore(risks: TransactionRisk[]): number {
    if (risks.length === 0) return 5; // Base risk for any transaction

    // Filter out positive indicators (severity 0)
    const actualRisks = risks.filter(r => r.severity > 0);

    if (actualRisks.length === 0) return 0; // All positive indicators

    // Weight by severity
    let totalRisk = 0;
    let totalWeight = 0;

    actualRisks.forEach(risk => {
        const weight = risk.severity / 10;
        const riskValue = (risk.severity / 10) * 100;

        totalRisk += riskValue * weight;
        totalWeight += weight;
    });

    const avgRisk = totalWeight > 0 ? totalRisk / totalWeight : 0;

    // Critical risks should heavily influence score
    const hasCriticalRisk = actualRisks.some(r => r.severity >= 9);
    if (hasCriticalRisk) {
        return normalizeRiskScore(Math.max(avgRisk, 85));
    }

    return normalizeRiskScore(avgRisk);
}

/**
 * Get transaction risk summary
 */
export function getTransactionRiskSummary(result: TransactionRiskResult): string {
    const { risks, isSafe } = result;

    if (isSafe) {
        return 'Transaction appears safe to execute with minimal risks detected.';
    }

    const criticalRisks = risks.filter(r => r.severity >= 8);

    if (criticalRisks.length > 0) {
        return `DANGER: ${criticalRisks[0].description}. Transaction NOT recommended.`;
    }

    const highRisks = risks.filter(r => r.severity >= 6);

    if (highRisks.length > 0) {
        return `WARNING: ${highRisks.length} high-risk factor(s) detected. Proceed with caution.`;
    }

    return `${risks.length} potential risk(s) identified. Review before proceeding.`;
}

/**
 * Get transaction recommendations
 */
export function getTransactionRecommendations(
    result: TransactionRiskResult
): string[] {
    const recommendations: string[] = [];
    const { risks, isSafe } = result;

    if (isSafe) {
        recommendations.push('✓ Transaction appears safe');
        return recommendations;
    }

    risks.forEach(risk => {
        if (risk.severity >= 8) {
            recommendations.push(`⚠️ CRITICAL: ${risk.description}`);
        } else if (risk.severity >= 6) {
            recommendations.push(`⚠ WARNING: ${risk.description}`);
        } else if (risk.severity >= 4) {
            recommendations.push(`ℹ INFO: ${risk.description}`);
        }
    });

    // General recommendations
    if (risks.some(r => r.type === 'unverified_contract_interaction')) {
        recommendations.push('→ Verify contract source code before interacting');
    }

    if (risks.some(r => r.type === 'high_value_to_new')) {
        recommendations.push('→ Consider starting with a small test transaction');
    }

    if (risks.some(r => r.type === 'known_scam_recipient')) {
        recommendations.push('→ DO NOT PROCEED - Recipient is flagged as malicious');
    }

    return recommendations.slice(0, 5); // Top 5 recommendations
}
