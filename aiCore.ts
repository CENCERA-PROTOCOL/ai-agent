/**
 * AI Core Orchestrator
 * Coordinates all analysis engines and produces final AI risk assessment
 */

import {
    AIAnalysisRequest,
    AIAnalysisResult,
    RiskConfig,
} from './types';
import { analyzePatterns, getThreatSummary } from './patternRecognition';
import { analyzeBehavior, getBehavioralSummary } from './behavioralAnalysis';
import { analyzeContractSecurity, getSecuritySummary } from './contractSecurity';
import { analyzeTransactionRisk } from './transactionRisk';
import { analyzeOSINT, getOSINTSummary } from './osintDiscovery';
import { analyzeSocial, getSocialSummary } from './socialAnalysis';
import { analyzeMarketSignals, getMarketSummary } from './marketSignals';
import { generateLLMExplanation } from './llmExplainer';
import { saveReputationSnapshot } from './reputationHistory';
import {
    scoreToRiskLevel,
    weightedAverage,
    normalizeRiskScore,
    getCached,
    setCached,
    generateCacheKey,
    hashConfig,
} from './aiUtils';
import {
    mergeRiskConfig,
    validateRiskConfig,
    DEFAULT_RISK_CONFIG,
} from './config';
import { PERFORMANCE_CONFIG, ENGINE_CONFIG } from './config';
import { BlockchainService } from './chainConnector';

/**
 * Service instance (lazy loaded)
 */
let blockchainService: BlockchainService | null = null;

function getBlockchainService(apiKey: string = ''): BlockchainService {
    if (!blockchainService) {
        blockchainService = new BlockchainService(apiKey);
    }
    return blockchainService;
}

/**
 * Analyze an address by fetching live data from blockchain
 */
export async function analyzeAddress(
    address: string,
    chainId: string = '1',
    apiKey: string = ''
): Promise<AIAnalysisResult> {
    const service = getBlockchainService(apiKey);

    // 1. Fetch on-chain identity data
    const identity = await service.getIdentitydata(address, chainId);

    // 2. Fetch contract source/abi if it's a contract
    let sourceCode: string | undefined;

    if (identity.isContract) {
        const source = await service.getContractSource(address, chainId);
        if (source) {
            sourceCode = source;
        }
    }

    // 3. Fetch transaction history from Etherscan for behavioral analysis
    const txHistory = await service.getTransactionHistory(address, chainId, 100);
    const tokenTransfers = await service.getTokenTransfers(address, chainId, 50);

    // Calculate more accurate transaction count from Etherscan if available
    const etherscanTxCount = txHistory ? txHistory.length : identity.txCount;

    // 4. Construct Analysis Request
    const request: AIAnalysisRequest = {
        address,
        chainId,
        balance: identity.balance,
        txCount: etherscanTxCount, // Use Etherscan count for better accuracy
        isContract: identity.isContract,
        codeSize: identity.codeSize,
        bytecode: identity.bytecode?.toString(), // Pass raw bytecode
        sourceCode: sourceCode,
        // We could also try to resolve ENS here if we added that to BlockchainService
    };

    // 4. Run AI Analysis
    return analyzeWithAI(request);
}

/**
 * Main AI analysis function
 * Orchestrates all engines and produces comprehensive risk assessment
 */
export async function analyzeWithAI(
    request: AIAnalysisRequest
): Promise<AIAnalysisResult> {
    // Merge and validate risk configuration
    const config = mergeRiskConfig(request.riskConfig);
    const validation = validateRiskConfig(config);

    if (!validation.isValid) {
        throw new Error(`Invalid risk config: ${validation.errors.join(', ')}`);
    }

    // Check cache
    const cacheKey = generateCacheKey(
        request.address,
        request.chainId || '1',
        hashConfig(config)
    );

    const cached = getCached<AIAnalysisResult>(cacheKey);
    if (cached) {
        console.log('[AICore] Returning cached analysis');
        return cached;
    }

    // Execute all enabled engines in parallel
    const enginePromises: Promise<any>[] = [];
    const enabledEngines = config.enabledEngines || DEFAULT_RISK_CONFIG.enabledEngines;

    // AI Pattern Recognition Engine
    if (enabledEngines.patternRecognition) {
        enginePromises.push(analyzePatterns(request));
    } else {
        enginePromises.push(Promise.resolve(null));
    }

    // On-chain Behavioral Analysis Engine
    if (enabledEngines.behavioral) {
        enginePromises.push(analyzeBehavior(request));
    } else {
        enginePromises.push(Promise.resolve(null));
    }

    // Contract Security Engine
    if (enabledEngines.contractSecurity && request.isContract) {
        enginePromises.push(analyzeContractSecurity(request));
    } else {
        enginePromises.push(Promise.resolve(null));
    }

    // Transaction Risk Engine
    if (enabledEngines.transactionRisk) {
        enginePromises.push(analyzeTransactionRisk(request));
    } else {
        enginePromises.push(Promise.resolve(null));
    }

    // OSINT Discovery Engine (NEW)
    let osintPromise: Promise<any>;
    if (enabledEngines.osint) {
        osintPromise = analyzeOSINT(request);
        enginePromises.push(osintPromise);
    } else {
        osintPromise = Promise.resolve(null);
        enginePromises.push(osintPromise);
    }

    // Social Analysis Engine (NEW) - depends on OSINT for links
    if (enabledEngines.social) {
        enginePromises.push(
            osintPromise.then(osintResult =>
                analyzeSocial(request, osintResult?.socialLinks)
            )
        );
    } else {
        enginePromises.push(Promise.resolve(null));
    }

    // Market Signals Engine (NEW) - depends on OSINT for market data
    if (enabledEngines.market) {
        enginePromises.push(
            osintPromise.then(osintResult =>
                analyzeMarketSignals(request, osintResult?.marketData)
            )
        );
    } else {
        enginePromises.push(Promise.resolve(null));
    }

    // Wait for all engines to complete (with timeout)
    const timeout = new Promise((_, reject) =>
        setTimeout(() => reject(new Error('AI analysis timeout')), PERFORMANCE_CONFIG.analysisTimeout)
    );

    let results;
    try {
        results = await Promise.race([
            Promise.all(enginePromises),
            timeout
        ]) as any[];
    } catch (error) {
        console.error('[AICore] Analysis timeout or error:', error);
        // Return degraded result
        return createDegradedResult(request, config);
    }

    const [
        patternResult,
        behavioralResult,
        securityResult,
        transactionResult,
        osintResult,
        socialResult,
        marketResult
    ] = results;

    // Calculate weighted AI risk score
    const aiRiskScore = calculateAIRiskScore({
        patternResult,
        behavioralResult,
        securityResult,
        transactionResult,
        osintResult,
        socialResult,
        marketResult,
    }, config);

    // Determine risk level from score
    const riskLevel = mapRiskScoreToLevel(aiRiskScore);

    // Generate comprehensive summary
    const summary = generateAISummary({
        riskLevel,
        patternResult,
        behavioralResult,
        securityResult,
        transactionResult,
        osintResult,
        socialResult,
        marketResult,
        config,
    });

    // Generate audit notes
    const auditNotes = generateAuditNotes({
        patternResult,
        behavioralResult,
        securityResult,
        transactionResult,
    });

    // Compile partial result for LLM explanation
    const partialResult: Partial<AIAnalysisResult> = {
        aiRiskScore,
        riskLevel,
        engineResults: {
            patternRecognition: patternResult,
            behavioral: behavioralResult,
            contractSecurity: securityResult,
            transactionRisk: transactionResult,
            osint: osintResult,
            social: socialResult,
            market: marketResult,
        },
    };

    // Generate LLM explanation if enabled
    let llmExplanation;
    if (ENGINE_CONFIG.customAI?.enabled) {
        try {
            llmExplanation = await generateLLMExplanation(request, partialResult);
        } catch (error) {
            console.log('[AICore] Custom AI explanation failed:', error);
        }
    }

    // Compile final result
    const result: AIAnalysisResult = {
        summary,
        riskLevel,
        auditNotes,
        aiRiskScore,
        engineResults: {
            patternRecognition: patternResult,
            behavioral: behavioralResult,
            contractSecurity: securityResult,
            transactionRisk: transactionResult,
            osint: osintResult,
            social: socialResult,
            market: marketResult,
        },
        llmExplanation,
        appliedConfig: config,
    };

    // Save reputation snapshot
    try {
        await saveReputationSnapshot(request.address, result, request.chainId || '1');
    } catch (error) {
        console.log('[AICore] Failed to save reputation snapshot:', error);
    }

    // Cache the result
    setCached(cacheKey, result, PERFORMANCE_CONFIG.cacheTTL.aiAnalysis);

    return result;
}

/**
 * Calculate weighted AI risk score from all 7 engines
 * Weights as per project.md: 45% on-chain, 30% market, 15% social, 10% AI patterns
 */
function calculateAIRiskScore(params: {
    patternResult: any;
    behavioralResult: any;
    securityResult: any;
    transactionResult: any;
    osintResult?: any;
    socialResult?: any;
    marketResult?: any;
}, config: RiskConfig): number {
    const {
        patternResult,
        behavioralResult,
        securityResult,
        transactionResult,
        osintResult,
        socialResult,
        marketResult,
    } = params;

    const scores: number[] = [];
    const weights: number[] = [];

    // On-chain behavior (45% total)
    // Pattern recognition (20%)
    if (patternResult) {
        scores.push(patternResult.riskScore);
        weights.push(0.20);
    }
    // Behavioral analysis (15%)
    if (behavioralResult) {
        scores.push(behavioralResult.riskScore);
        weights.push(0.15);
    }
    // Contract security (5%)
    if (securityResult) {
        scores.push(securityResult.riskScore);
        weights.push(0.05);
    }
    // Transaction risk (5%)
    if (transactionResult) {
        scores.push(transactionResult.riskScore);
        weights.push(0.05);
    }

    // Market signals (30%)
    if (marketResult) {
        scores.push(marketResult.riskScore);
        weights.push(0.30);
    }

    // Social & OSINT (15%)
    if (socialResult) {
        scores.push(socialResult.riskScore);
        weights.push(0.10);
    }
    if (osintResult) {
        scores.push(osintResult.riskScore);
        weights.push(0.05);
    }

    // AI pattern analysis (10%) - from pattern recognition
    // Already included above in pattern recognition

    if (scores.length === 0) return 50; // Default medium risk

    return normalizeRiskScore(weightedAverage(scores, weights));
}

/**
 * Map risk score to risk level
 */
function mapRiskScoreToLevel(score: number): 'Critical' | 'High' | 'Medium' | 'Low' | 'Safe' {
    if (score >= 80) return 'Critical';
    if (score >= 60) return 'High';
    if (score >= 40) return 'Medium';
    if (score >= 20) return 'Low';
    return 'Safe';
}

/**
 * Generate comprehensive AI summary
 */
function generateAISummary(params: {
    riskLevel: 'Critical' | 'High' | 'Medium' | 'Low' | 'Safe';
    patternResult: any;
    behavioralResult: any;
    securityResult: any;
    transactionResult: any;
    osintResult?: any;
    socialResult?: any;
    marketResult?: any;
    config: RiskConfig;
}): string {
    const { riskLevel, patternResult, behavioralResult, securityResult, transactionResult, osintResult, socialResult, marketResult, config } = params;

    let summary = '';

    // Risk level announcement
    if (riskLevel === 'Critical') {
        summary += '🚨 **CRITICAL SECURITY ALERT:** ';
    } else if (riskLevel === 'High') {
        summary += '⚠️ **HIGH RISK DETECTED:** ';
    } else if (riskLevel === 'Medium') {
        summary += '⚠ **CAUTION ADVISED:** ';
    } else if (riskLevel === 'Low') {
        summary += 'ℹ️ **LOW RISK:** ';
    } else {
        summary += '✓ **SAFE:** ';
    }

    // Add findings from each engine
    const findings: string[] = [];

    if (patternResult && patternResult.threats.length > 0) {
        findings.push(`${patternResult.threats.length} threat pattern(s) detected`);
    }

    if (behavioralResult && behavioralResult.anomalies.length > 0) {
        findings.push(`${behavioralResult.anomalies.length} behavioral anomaly(ies)`);
    }

    if (securityResult && securityResult.vulnerabilities.length > 0) {
        findings.push(`${securityResult.vulnerabilities.length} security vulnerability(ies)`);
    }

    if (osintResult && !osintResult.isVerified) {
        findings.push('no external verification found');
    }

    if (socialResult && socialResult.botProbability > 0.7) {
        findings.push('high bot probability in social accounts');
    }

    if (marketResult && marketResult.honeypotRisk > 70) {
        findings.push('possible honeypot detected');
    }

    if (findings.length > 0) {
        summary += findings.join(', ') + '. ';
    } else {
        summary += 'No critical issues detected. ';
    }

    // Final recommendation
    if (riskLevel === 'Critical' || riskLevel === 'High') {
        summary += '**RECOMMENDATION:** Avoid interaction unless verified through multiple sources.';
    } else if (riskLevel === 'Medium') {
        summary += '**RECOMMENDATION:** Exercise caution and conduct additional due diligence.';
    } else {
        summary += '**RECOMMENDATION:** Safe to interact with standard security practices.';
    }

    return summary;
}

/**
 * Generate audit notes from engine results
 */
function generateAuditNotes(params: {
    patternResult: any;
    behavioralResult: any;
    securityResult: any;
    transactionResult: any;
}): string[] {
    const notes: string[] = [];
    const { patternResult, behavioralResult, securityResult, transactionResult } = params;

    // Pattern recognition notes
    if (patternResult?.threats && patternResult.threats.length > 0) {
        patternResult.threats.forEach((threat: any) => {
            if (threat.severity >= 6) {
                notes.push(`[Pattern] ${threat.type}: ${threat.description}`);
            }
        });
    } else if (patternResult) {
        notes.push('[Pattern] No significant threat patterns detected');
    }

    // Behavioral analysis notes
    if (behavioralResult?.anomalies && behavioralResult.anomalies.length > 0) {
        behavioralResult.anomalies.slice(0, 3).forEach((anomaly: any) => {
            if (anomaly.severity >= 5) {
                notes.push(`[Behavioral] ${anomaly.type}: ${anomaly.description}`);
            }
        });
    } else if (behavioralResult) {
        notes.push(`[Behavioral] Activity pattern: ${behavioralResult.activityPattern}`);
    }

    // Security analysis notes
    if (securityResult?.vulnerabilities && securityResult.vulnerabilities.length > 0) {
        securityResult.vulnerabilities.slice(0, 3).forEach((vuln: any) => {
            if (vuln.severity >= 6) {
                notes.push(`[Security] ${vuln.type}: ${vuln.description}`);
            }
        });
    } else if (securityResult && securityResult.dangerousFunctions.length > 0) {
        notes.push(`[Security] Contains dangerous opcodes: ${securityResult.dangerousFunctions.join(', ')}`);
    }

    // Transaction risk notes
    if (transactionResult?.risks && transactionResult.risks.length > 0) {
        transactionResult.risks.slice(0, 2).forEach((risk: any) => {
            if (risk.severity >= 6) {
                notes.push(`[Transaction] ${risk.type}: ${risk.description}`);
            }
        });
    }

    // Add catch-all if no specific notes
    if (notes.length === 0) {
        notes.push('AI analysis completed with no critical findings');
    }

    return notes.slice(0, 8); // Limit to top 8 notes
}

/**
 * Create degraded result when analysis fails
 */
function createDegradedResult(
    request: AIAnalysisRequest,
    config: RiskConfig
): AIAnalysisResult {
    return {
        summary: 'AI analysis unavailable or timed out. Using conservative risk assessment.',
        riskLevel: 'Medium',
        auditNotes: [
            'Analysis timeout - unable to complete full AI scan',
            'Default medium risk level applied',
            'Manual review recommended',
        ],
        aiRiskScore: 50,
        appliedConfig: config,
    };
}
