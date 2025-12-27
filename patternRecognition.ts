/**
 * Pattern Recognition Engine
 * Detects known scam patterns, attack signatures, and malicious behavior
 */

import {
    AIAnalysisRequest,
    PatternRecognitionResult,
    ThreatPattern,
} from './types';
import {
    getKnowledgeBase,
    isKnownScam,
    isWhitelisted,
} from './knowledgeBase';
import {
    normalizeAddress,
    calculateConfidence,
} from './aiUtils';
import { ENGINE_CONFIG } from './config';

const { patternRecognition: CONFIG } = ENGINE_CONFIG;

/**
 * Analyze entity for known threat patterns
 */
export async function analyzePatterns(
    request: AIAnalysisRequest
): Promise<PatternRecognitionResult> {
    const threats: ThreatPattern[] = [];
    const address = normalizeAddress(request.address);

    // Check if address is whitelisted (skip analysis for known safe addresses)
    if (isWhitelisted(address)) {
        return {
            riskScore: 0,
            threats: [],
            isKnownThreat: false,
            confidence: 1.0,
        };
    }

    // Check if address is known scam
    const isKnown = isKnownScam(address);
    if (isKnown) {
        threats.push({
            type: 'suspicious_pattern',
            description: 'Address matches known scam database',
            severity: 10,
            confidence: 1.0,
        });
    }

    // Analyze contract bytecode if applicable
    if (request.isContract && request.codeSize > 0) {
        const contractThreats = await analyzeContractPatterns(request);
        threats.push(...contractThreats);
    }

    // Analyze token-specific patterns
    if (request.tokenMetadata) {
        const tokenThreats = await analyzeTokenPatterns(request);
        threats.push(...tokenThreats);
    }

    // Analyze behavioral patterns
    const behavioralThreats = analyzeBehavioralPatterns(request);
    threats.push(...behavioralThreats);

    // Calculate risk score
    const riskScore = calculatePatternRiskScore(threats);

    // Calculate confidence
    const confidence = calculateConfidence({
        dataPoints: threats.length,
        minDataPoints: 1,
        patternClarity: threats.length > 0 ? Math.max(...threats.map(t => t.confidence)) : 0,
        isVerified: false,
    });

    return {
        riskScore,
        threats,
        isKnownThreat: isKnown,
        confidence: confidence.overall,
    };
}

/**
 * Analyze contract for malicious patterns
 */
async function analyzeContractPatterns(
    request: AIAnalysisRequest
): Promise<ThreatPattern[]> {
    const threats: ThreatPattern[] = [];
    const kb = getKnowledgeBase();

    // Note: In real implementation, we would fetch actual bytecode from blockchain
    // For now, we'll use simulated analysis based on codeSize

    // Simulate bytecode analysis
    const hasDangerousOpcodes = request.codeSize > 1000; // Larger contracts more likely to have complex logic

    if (hasDangerousOpcodes) {
        // Check for dangerous opcodes (simulated)
        if (Math.random() < 0.3) { // 30% chance for demo purposes
            threats.push({
                type: 'drainer_contract',
                description: 'Contract contains DELEGATECALL opcode which can execute arbitrary code',
                severity: 9,
                confidence: 0.75,
            });
        }

        if (Math.random() < 0.2) { // 20% chance
            threats.push({
                type: 'honeypot',
                description: 'Contract may contain SELFDESTRUCT functionality',
                severity: 8,
                confidence: 0.7,
            });
        }
    }

    // Check for proxy patterns (upgradeable contracts have higher risk)
    if (request.codeSize < 500 && request.codeSize > 100) {
        threats.push({
            type: 'suspicious_pattern',
            description: 'Small contract size may indicate a proxy pattern with hidden implementation',
            severity: 5,
            confidence: 0.6,
        });
    }

    return threats;
}

/**
 * Analyze token-specific patterns
 */
async function analyzeTokenPatterns(
    request: AIAnalysisRequest
): Promise<ThreatPattern[]> {
    const threats: ThreatPattern[] = [];
    const { tokenMetadata } = request;

    if (!tokenMetadata) return threats;

    // Check for suspicious token names (common scam patterns)
    const suspiciousKeywords = ['test', 'scam', 'fake', 'ponzi', 'airdrop', 'free'];
    const tokenName = tokenMetadata.name?.toLowerCase() || '';
    const tokenSymbol = tokenMetadata.symbol?.toLowerCase() || '';

    suspiciousKeywords.forEach(keyword => {
        if (tokenName.includes(keyword) || tokenSymbol.includes(keyword)) {
            threats.push({
                type: 'fake_token',
                description: `Token name/symbol contains suspicious keyword: "${keyword}"`,
                severity: 7,
                confidence: 0.65,
            });
        }
    });

    // Check for impersonation (very short or very long names)
    if (tokenName.length <= 2) {
        threats.push({
            type: 'fake_token',
            description: 'Suspiciously short token name',
            severity: 5,
            confidence: 0.5,
        });
    }

    if (tokenName.length > 50) {
        threats.push({
            type: 'suspicious_pattern',
            description: 'Unusually long token name',
            severity: 4,
            confidence: 0.4,
        });
    }

    // Check for unusual total supply
    if (tokenMetadata.totalSupply) {
        const supply = parseFloat(tokenMetadata.totalSupply);

        // Extremely high supply might indicate inflationary token
        if (supply > 1_000_000_000_000) {
            threats.push({
                type: 'pump_and_dump',
                description: 'Extremely high total supply may indicate pump and dump scheme',
                severity: 6,
                confidence: 0.55,
            });
        }

        // Very low supply with no liquidity is suspicious
        if (supply < 100 && parseFloat(request.balance) < 0.01) {
            threats.push({
                type: 'suspicious_pattern',
                description: 'Very low supply combined with low liquidity',
                severity: 5,
                confidence: 0.5,
            });
        }
    }

    return threats;
}

/**
 * Analyze behavioral patterns
 */
function analyzeBehavioralPatterns(
    request: AIAnalysisRequest
): ThreatPattern[] {
    const threats: ThreatPattern[] = [];

    // New wallet with zero transactions
    if (request.txCount === 0) {
        threats.push({
            type: 'suspicious_pattern',
            description: 'Zero transaction history - potentially new or dormant address',
            severity: 6,
            confidence: 0.9,
        });
    }

    // New wallet with very few transactions but is a contract
    if (request.isContract && request.txCount < 10) {
        threats.push({
            type: 'suspicious_pattern',
            description: 'Recently deployed contract with limited activity',
            severity: 7,
            confidence: 0.75,
        });
    }

    // High balance with zero transactions (might be a honeypot)
    const balance = parseFloat(request.balance);
    if (balance > 100 && request.txCount === 0) {
        threats.push({
            type: 'honeypot',
            description: 'High balance with no transaction history - potential honeypot',
            severity: 8,
            confidence: 0.7,
        });
    }

    // Wallet with very low balance but is a contract (might be abandoned or malicious)
    if (request.isContract && balance < 0.001) {
        threats.push({
            type: 'suspicious_pattern',
            description: 'Contract with near-zero balance - may be abandoned or test contract',
            severity: 4,
            confidence: 0.55,
        });
    }

    return threats;
}

/**
 * Calculate overall risk score from detected threats
 */
function calculatePatternRiskScore(threats: ThreatPattern[]): number {
    if (threats.length === 0) return 0;

    // Weight threats by severity and confidence
    let totalRisk = 0;
    let totalWeight = 0;

    threats.forEach(threat => {
        const typeWeight = CONFIG.threatWeights[threat.type] || 0.5;
        const weight = typeWeight * threat.confidence;
        const risk = (threat.severity / 10) * 100; // Normalize to 0-100

        totalRisk += risk * weight;
        totalWeight += weight;
    });

    if (totalWeight === 0) return 0;

    // Normalize to 0-100 range
    const avgRisk = totalRisk / totalWeight;

    // Apply diminishing returns (multiple small threats shouldn't equal one critical threat)
    const threatCount = threats.length;
    const diminishingFactor = Math.min(1, Math.log10(threatCount + 1));

    return Math.min(100, Math.round(avgRisk * (0.7 + 0.3 * diminishingFactor)));
}

/**
 * Get threat summary for reporting
 */
export function getThreatSummary(threats: ThreatPattern[]): string {
    if (threats.length === 0) {
        return 'No significant threat patterns detected';
    }

    const criticalThreats = threats.filter(t => t.severity >= 8);
    const highThreats = threats.filter(t => t.severity >= 6 && t.severity < 8);

    let summary = `Detected ${threats.length} potential threat pattern(s). `;

    if (criticalThreats.length > 0) {
        summary += `${criticalThreats.length} CRITICAL: ${criticalThreats[0].description}. `;
    }

    if (highThreats.length > 0 && criticalThreats.length === 0) {
        summary += `${highThreats.length} HIGH RISK: ${highThreats[0].description}. `;
    }

    return summary;
}
