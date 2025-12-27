/**
 * Custom AI Explainer Engine
 * Generates natural language explanations using CENCERA's own AI logic
 * NO external LLM dependencies - fully custom implementation
 */

import {
    AIAnalysisRequest,
    AIAnalysisResult,
    LLMExplanation,
    RiskFactor,
    Evidence,
} from './types';

// ============================================================================
// Main Explanation Generation (CUSTOM AI)
// ============================================================================

export async function generateLLMExplanation(
    request: AIAnalysisRequest,
    analysisResult: Partial<AIAnalysisResult>
): Promise<LLMExplanation> {
    console.log(`[Custom AI] Generating intelligent explanation for ${request.address}...`);

    const riskFactors: RiskFactor[] = [];
    const evidence: Evidence[] = [];
    const recommendations: string[] = [];

    const riskScore = analysisResult.aiRiskScore || 50;
    const riskLevel = analysisResult.riskLevel || 'Medium';

    // ========================================================================
    // PATTERN RECOGNITION ANALYSIS
    // ========================================================================

    if (analysisResult.engineResults?.patternRecognition) {
        const pr = analysisResult.engineResults.patternRecognition;

        if (pr.isKnownThreat) {
            riskFactors.push({
                category: 'pattern',
                severity: 'critical',
                description: 'Address matches known threat database',
                impact: 'This entity has been previously identified as malicious by the blockchain security community',
            });
            evidence.push({
                type: 'Known Threat Match',
                description: 'Address found in CENCERA threat intelligence database',
                source: 'Pattern Recognition Engine',
                severity: 10,
            });
        }

        pr.threats.forEach(threat => {
            if (threat.severity >= 7) {
                const severityLabel = threat.severity >= 9 ? 'critical' : 'high';
                riskFactors.push({
                    category: 'pattern',
                    severity: severityLabel,
                    description: formatThreatType(threat.type),
                    impact: threat.description,
                });
                evidence.push({
                    type: threat.type,
                    description: threat.description,
                    source: 'Pattern Recognition Engine',
                    severity: threat.severity,
                });
            }
        });
    }

    // ========================================================================
    // BEHAVIORAL ANALYSIS
    // ========================================================================

    if (analysisResult.engineResults?.behavioral) {
        const ba = analysisResult.engineResults.behavioral;

        // Activity pattern insights
        const patternInsights = analyzeBehavioralPattern(ba.activityPattern, request);
        if (patternInsights) {
            riskFactors.push(patternInsights);
        }

        // Anomalies
        ba.anomalies.forEach(anomaly => {
            if (anomaly.severity >= 6) {
                riskFactors.push({
                    category: 'behavioral',
                    severity: anomaly.severity >= 8 ? 'critical' : anomaly.severity >= 6 ? 'high' : 'medium',
                    description: anomaly.type,
                    impact: anomaly.description,
                });
                evidence.push({
                    type: 'Behavioral Anomaly',
                    description: `${anomaly.type}: ${anomaly.description}${anomaly.zScore ? ` (z-score: ${anomaly.zScore.toFixed(2)})` : ''}`,
                    source: 'Behavioral Analysis Engine',
                    severity: anomaly.severity,
                });
            }
        });
    }

    // ========================================================================
    // CONTRACT SECURITY ANALYSIS
    // ========================================================================

    if (analysisResult.engineResults?.contractSecurity && request.isContract) {
        const cs = analysisResult.engineResults.contractSecurity;

        cs.vulnerabilities.forEach(vuln => {
            if (vuln.severity >= 6) {
                riskFactors.push({
                    category: 'contract',
                    severity: vuln.severity >= 8 ? 'critical' : 'high',
                    description: formatVulnerabilityType(vuln.type),
                    impact: vuln.description,
                });
                evidence.push({
                    type: 'Smart Contract Vulnerability',
                    description: `${vuln.type}: ${vuln.description}`,
                    source: 'Contract Security Engine',
                    severity: vuln.severity,
                });
            }
        });

        if (cs.dangerousFunctions.length > 0) {
            const hasCritical = cs.dangerousFunctions.some(f =>
                f === 'SELFDESTRUCT' || f === 'DELEGATECALL'
            );
            if (hasCritical) {
                riskFactors.push({
                    category: 'contract',
                    severity: 'high',
                    description: 'Dangerous opcodes detected',
                    impact: `Contract contains: ${cs.dangerousFunctions.join(', ')}`,
                });
            }
        }

        if (cs.isVerified === false) {
            riskFactors.push({
                category: 'contract',
                severity: 'medium',
                description: 'Unverified contract source code',
                impact: 'Contract source code is not verified on block explorer, making audit difficult',
            });
        }
    }

    // ========================================================================
    // OSINT DISCOVERY ANALYSIS
    // ========================================================================

    if (analysisResult.engineResults?.osint) {
        const osint = analysisResult.engineResults.osint;

        if (osint.isVerified) {
            // Positive signal
            evidence.push({
                type: 'External Verification',
                description: `Verified on ${osint.listings.join(', ')}`,
                source: 'OSINT Discovery Engine',
            });
        } else {
            riskFactors.push({
                category: 'social',
                severity: 'medium',
                description: 'No external verification found',
                impact: 'Entity not listed on major platforms like CoinGecko or CoinMarketCap',
            });
        }

        if (osint.marketData) {
            if (osint.marketData.marketCap && osint.marketData.marketCap > 100_000_000) {
                evidence.push({
                    type: 'Market Presence',
                    description: `Strong market cap: $${(osint.marketData.marketCap / 1_000_000).toFixed(1)}M`,
                    source: 'OSINT Discovery Engine',
                });
            }
        }
    }

    // ========================================================================
    // SOCIAL MEDIA ANALYSIS
    // ========================================================================

    if (analysisResult.engineResults?.social) {
        const social = analysisResult.engineResults.social;

        if (social.botProbability > 0.7) {
            riskFactors.push({
                category: 'social',
                severity: 'high',
                description: 'High bot probability in social presence',
                impact: `Social accounts show ${(social.botProbability * 100).toFixed(0)}% likelihood of being bot-operated`,
            });
        }

        social.redFlags.forEach(flag => {
            riskFactors.push({
                category: 'social',
                severity: 'medium',
                description: 'Social media red flag',
                impact: flag,
            });
        });

        if (social.authenticityScore > 70) {
            evidence.push({
                type: 'Social Authenticity',
                description: `Strong social presence (${social.authenticityScore}/100 authenticity score)`,
                source: 'Social Analysis Engine',
            });
        }
    }

    // ========================================================================
    // MARKET SIGNALS ANALYSIS
    // ========================================================================

    if (analysisResult.engineResults?.market) {
        const market = analysisResult.engineResults.market;

        if (market.honeypotRisk > 70) {
            riskFactors.push({
                category: 'market',
                severity: 'critical',
                description: 'Possible honeypot detected',
                impact: 'High slippage or sell restrictions may prevent token sale',
            });
        }

        if (market.liquidityScore < 30) {
            riskFactors.push({
                category: 'market',
                severity: 'high',
                description: 'Insufficient liquidity',
                impact: 'Very low liquidity increases price manipulation and rug pull risk',
            });
        }

        if (market.distributionFairness < 30) {
            riskFactors.push({
                category: 'market',
                severity: 'high',
                description: 'Concentrated token holdings',
                impact: 'Majority of tokens held by few addresses - dump risk',
            });
        }
    }

    // ========================================================================
    // GENERATE INTELLIGENT RECOMMENDATIONS
    // ========================================================================

    recommendations.push(...generateSmartRecommendations({
        riskScore,
        riskLevel,
        isContract: request.isContract,
        isVerified: analysisResult.engineResults?.osint?.isVerified || false,
        hasVulnerabilities: (analysisResult.engineResults?.contractSecurity?.vulnerabilities.length || 0) > 0,
        isKnownThreat: analysisResult.engineResults?.patternRecognition?.isKnownThreat || false,
        honeypotRisk: analysisResult.engineResults?.market?.honeypotRisk || 0,
    }));

    // ========================================================================
    // GENERATE INTELLIGENT SUMMARY
    // ========================================================================

    const summary = generateIntelligentSummary({
        request,
        riskScore,
        riskLevel,
        riskFactors,
        evidence,
        engineResults: analysisResult.engineResults,
    });

    // Calculate confidence based on evidence quality
    const confidence = calculateExplanationConfidence(evidence, riskFactors);

    return {
        summary,
        riskFactors: riskFactors.slice(0, 5), // Top 5 most critical
        recommendations,
        evidence: evidence.slice(0, 8), // Top 8 pieces of evidence
        confidence,
    };
}

// ============================================================================
// INTELLIGENT SUMMARY GENERATION
// ============================================================================

function generateIntelligentSummary(params: {
    request: AIAnalysisRequest;
    riskScore: number;
    riskLevel: string;
    riskFactors: RiskFactor[];
    evidence: Evidence[];
    engineResults?: any;
}): string {
    const { request, riskScore, riskLevel, riskFactors, evidence, engineResults } = params;

    const entityType = request.isContract
        ? (request.tokenMetadata ? 'token contract' : 'smart contract')
        : 'wallet address';

    let summary = '';

    // ======== Opening Statement ========
    if (riskLevel === 'Critical' || riskLevel === 'High') {
        summary += `⚠️ **HIGH RISK ALERT**: This ${entityType} exhibits significant security concerns. `;
    } else if (riskLevel === 'Safe' || riskLevel === 'Low') {
        summary += `✅ **LOW RISK**: This ${entityType} shows acceptable security characteristics. `;
    } else {
        summary += `⚡ **MODERATE RISK**: This ${entityType} requires careful evaluation before interaction. `;
    }

    // ======== Key Findings ========
    summary += `CENCERA's multi-engine analysis (risk score: ${riskScore}/100) `;

    if (riskFactors.length > 0) {
        const criticalCount = riskFactors.filter(rf => rf.severity === 'critical').length;
        const highCount = riskFactors.filter(rf => rf.severity === 'high').length;

        if (criticalCount > 0) {
            summary += `identified ${criticalCount} critical and ${highCount} high-severity risk factor(s). `;
        } else if (highCount > 0) {
            summary += `identified ${highCount} high-severity risk factor(s). `;
        } else {
            summary += `detected ${riskFactors.length} moderate concern(s). `;
        }

        // Mention top risk
        const topRisk = riskFactors[0];
        summary += `Primary concern: ${topRisk.description.toLowerCase()}. `;
    } else {
        summary += `found no critical security issues. `;
    }

    // ======== Verification Status ========
    if (engineResults?.osint) {
        if (engineResults.osint.isVerified) {
            summary += `Entity is verified on established platforms. `;
        } else {
            summary += `No external verification found. `;
        }
    }

    // ======== Market Context ========
    if (request.isContract && engineResults?.market) {
        const market = engineResults.market;
        if (market.liquidityScore > 70) {
            summary += `Healthy liquidity detected. `;
        } else if (market.liquidityScore < 40) {
            summary += `⚠️ Low liquidity warning. `;
        }
    }

    // ======== Final Assessment ========
    const trustScore = 100 - riskScore;
    if (trustScore >= 80) {
        summary += `**Assessment**: Suitable for interaction with standard precautions.`;
    } else if (trustScore >= 60) {
        summary += `**Assessment**: Proceed with caution and thorough due diligence.`;
    } else if (trustScore >= 40) {
        summary += `**Assessment**: High risk - significant concerns identified.`;
    } else {
        summary += `**Assessment**: CRITICAL RISK - strongly advise avoiding interaction.`;
    }

    return summary;
}

// ============================================================================
// SMART RECOMMENDATIONS ENGINE
// ============================================================================

function generateSmartRecommendations(params: {
    riskScore: number;
    riskLevel: string;
    isContract: boolean;
    isVerified: boolean;
    hasVulnerabilities: boolean;
    isKnownThreat: boolean;
    honeypotRisk: number;
}): string[] {
    const recs: string[] = [];

    // Critical threat recommendations
    if (params.isKnownThreat) {
        recs.push('🚨 DO NOT INTERACT - Address is flagged in CENCERA threat database');
        recs.push('Report this address to your wallet provider and relevant authorities');
        return recs;
    }

    // Honeypot recommendations
    if (params.honeypotRisk > 70) {
        recs.push('⛔ Suspected honeypot - do not purchase this token');
        recs.push('Tokens may not be sellable after purchase due to contract restrictions');
    }

    // Risk-level based recommendations
    if (params.riskScore >= 70) {
        recs.push('Avoid interaction unless absolutely necessary and fully verified through multiple sources');
        recs.push('If interaction required, use dedicated wallet with minimal funds');
        recs.push('Triple-check address on multiple block explorers before any transaction');
    } else if (params.riskScore >= 50) {
        recs.push('Exercise heightened caution when interacting with this entity');
        if (params.isContract) {
            recs.push('Review contract source code on block explorer before approving transactions');
        }
        recs.push('Start with small test transactions to verify functionality');
        recs.push('Monitor transaction carefully and revoke approvals immediately after use');
    } else if (params.riskScore >= 30) {
        recs.push('Standard security practices apply - verify transaction details carefully');
        if (!params.isVerified) {
            recs.push('Conduct additional research as entity lacks external verification');
        }
        recs.push('Keep approval amounts to minimum necessary for intended transaction');
    } else {
        recs.push('Entity shows acceptable security profile for normal interaction');
        recs.push('Continue practicing standard blockchain security measures');
        if (params.isContract) {
            recs.push('Review transaction simulation before signing if available in your wallet');
        }
    }

    // Contract-specific recommendations
    if (params.isContract && params.hasVulnerabilities) {
        if (!params.isVerified) {
            recs.push('⚠️ Contract is unverified - source code cannot be audited');
        }
        recs.push('Be aware of identified vulnerabilities before granting token approvals');
    }

    return recs.slice(0, 4); // Max 4 recommendations
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function formatThreatType(type: string): string {
    return type.split('_').map(word =>
        word.charAt(0).toUpperCase() + word.slice(1)
    ).join(' ');
}

function formatVulnerabilityType(type: string): string {
    return type.split('_').map(word =>
        word.charAt(0).toUpperCase() + word.slice(1)
    ).join(' ');
}

function analyzeBehavioralPattern(
    pattern: string,
    request: AIAnalysisRequest
): RiskFactor | null {
    switch (pattern) {
        case 'bot':
            return {
                category: 'behavioral',
                severity: 'medium',
                description: 'Bot-like activity pattern detected',
                impact: 'Automated behavior suggests possible bot or smart contract automation',
            };
        case 'suspicious':
            return {
                category: 'behavioral',
                severity: 'high',
                description: 'Suspicious transaction patterns',
                impact: 'Unusual activity deviates significantly from normal wallet behavior',
            };
        case 'dormant':
            return {
                category: 'behavioral',
                severity: 'low',
                description: 'Long-term dormant address',
                impact: 'Address has been inactive for extended period',
            };
        case 'new':
            return {
                category: 'behavioral',
                severity: 'medium',
                description: 'Recently created address',
                impact: 'New address with limited transaction history',
            };
        default:
            return null;
    }
}

function calculateExplanationConfidence(
    evidence: Evidence[],
    riskFactors: RiskFactor[]
): number {
    // Confidence based on amount and quality of evidence
    let confidence = 0.5; // Base confidence

    // More evidence = higher confidence
    confidence += Math.min(evidence.length * 0.05, 0.3);

    // Critical findings = higher confidence
    const hasCritical = riskFactors.some(rf => rf.severity === 'critical');
    if (hasCritical) {
        confidence += 0.2;
    }

    return Math.min(confidence, 1.0);
}

// ============================================================================
// Utility Functions
// ============================================================================

export function formatExplanation(explanation: LLMExplanation): string {
    let output = `\n=== CENCERA AI ANALYSIS ===\n\n`;
    output += `${explanation.summary}\n\n`;

    if (explanation.riskFactors.length > 0) {
        output += `🔍 RISK FACTORS:\n`;
        explanation.riskFactors.forEach((rf, i) => {
            const icon = rf.severity === 'critical' ? '🚨' : rf.severity === 'high' ? '⚠️' : 'ℹ️';
            output += `${i + 1}. ${icon} [${rf.severity.toUpperCase()}] ${rf.description}\n`;
            output += `   ${rf.impact}\n`;
        });
        output += `\n`;
    }

    if (explanation.recommendations.length > 0) {
        output += `💡 RECOMMENDATIONS:\n`;
        explanation.recommendations.forEach((rec, i) => {
            output += `${i + 1}. ${rec}\n`;
        });
    }

    return output;
}
