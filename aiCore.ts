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
import { PERFORMANCE_CONFIG } from './config';
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

    if (enabledEngines.patternRecognition) {
        enginePromises.push(analyzePatterns(request));
    } else {
        enginePromises.push(Promise.resolve(null));
    }

    if (enabledEngines.behavioral) {
        enginePromises.push(analyzeBehavior(request));
    } else {
        enginePromises.push(Promise.resolve(null));
    }

    if (enabledEngines.contractSecurity && request.isContract) {
        enginePromises.push(analyzeContractSecurity(request));
    } else {
        enginePromises.push(Promise.resolve(null));
    }

    if (enabledEngines.transactionRisk) {
        enginePromises.push(analyzeTransactionRisk(request));
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

    const [patternResult, behavioralResult, securityResult, transactionResult] = results;

    // Calculate weighted AI risk score
    const aiRiskScore = calculateAIRiskScore({
        patternResult,
        behavioralResult,
        securityResult,
        transactionResult,
    });

    // Map to risk level
    const riskLevel = scoreToRiskLevel(aiRiskScore);

    // Generate comprehensive summary
    const summary = generateAISummary({
        request,
        aiRiskScore,
        riskLevel,
        patternResult,
        behavioralResult,
        securityResult,
        transactionResult,
        config,
    });

    // Generate audit notes
    const auditNotes = generateAuditNotes({
        patternResult,
        behavioralResult,
        securityResult,
        transactionResult,
    });

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
        },
        appliedConfig: config,
    };

    // Cache the result
    setCached(cacheKey, result, PERFORMANCE_CONFIG.cacheTTL.aiAnalysis);

    return result;
}

/**
 * Calculate weighted AI risk score from all engines
 */
function calculateAIRiskScore(params: {
    patternResult: any;
    behavioralResult: any;
    securityResult: any;
    transactionResult: any;
}): number {
    const { patternResult, behavioralResult, securityResult, transactionResult } = params;

    const scores: number[] = [];
    const weights: number[] = [];

    // Pattern recognition (40% of AI score)
    if (patternResult) {
        scores.push(patternResult.riskScore);
        weights.push(0.40);
    }

    // Behavioral analysis (30% of AI score)
    if (behavioralResult) {
        scores.push(behavioralResult.riskScore);
        weights.push(0.30);
    }

    // Contract security (20% of AI score)
    if (securityResult) {
        scores.push(securityResult.riskScore);
        weights.push(0.20);
    }

    // Transaction risk (10% of AI score)
    if (transactionResult) {
        scores.push(transactionResult.riskScore);
        weights.push(0.10);
    }

    if (scores.length === 0) return 50; // Default medium risk

    return normalizeRiskScore(weightedAverage(scores, weights));
}

/**
 * Generate comprehensive AI summary
 */
function generateAISummary(params: {
    request: AIAnalysisRequest;
    aiRiskScore: number;
    riskLevel: string;
    patternResult: any;
    behavioralResult: any;
    securityResult: any;
    transactionResult: any;
    config: RiskConfig;
}): string {
    const { request, aiRiskScore, riskLevel, patternResult, behavioralResult, securityResult, transactionResult, config } = params;

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

    // Main analysis summary
    const balance = parseFloat(request.balance);
    const entityType = request.isContract
        ? (request.tokenMetadata ? 'Token Contract' : 'Smart Contract')
        : 'Wallet Address';

    summary += `AI analysis of ${entityType} reveals risk score of ${aiRiskScore}/100. `;

    // Add specific findings
    if (patternResult && patternResult.threats.length > 0) {
        summary += getThreatSummary(patternResult.threats) + ' ';
    }

    if (behavioralResult) {
        summary += getBehavioralSummary(behavioralResult) + ' ';
    }

    if (securityResult && request.isContract) {
        summary += getSecuritySummary(securityResult) + ' ';
    }

    // Balance and activity summary
    summary += `Entity holds ${balance.toFixed(4)} ETH with ${request.txCount} transaction(s). `;

    // Final recommendation based on config thresholds
    const trustScore = 100 - aiRiskScore;
    if (trustScore >= config.safeZone) {
        summary += '**RECOMMENDATION:** Safe to interact with standard precautions.';
    } else if (trustScore < config.dangerZone) {
        summary += '**RECOMMENDATION:** HIGH RISK - Avoid interaction unless verified.';
    } else {
        summary += '**RECOMMENDATION:** CAUTION - Review risks before proceeding.';
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
