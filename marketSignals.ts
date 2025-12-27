/**
 * Market Signals Analysis Engine
 * Analyzes liquidity, volume patterns, and token distribution
 */

import {
    AIAnalysisRequest,
    MarketSignalsResult,
    MarketMetrics,
    MarketData,
} from './types';
import { normalizeRiskScore } from './aiUtils';

// ============================================================================
// Main Market Signals Analysis
// ============================================================================

export async function analyzeMarketSignals(
    request: AIAnalysisRequest,
    marketData?: MarketData
): Promise<MarketSignalsResult> {
    console.log(`[Market] Analyzing market signals for ${request.address}...`);

    // If not a token, return default
    if (!request.isContract || !request.tokenMetadata) {
        return createDefaultMarketResult();
    }

    const metrics: MarketMetrics = {};

    // Populate metrics from market data if available
    if (marketData) {
        metrics.volume24h = marketData.volume24h;
        metrics.totalLiquidity = marketData.marketCap;
    }

    // Additional analysis would require DEX APIs (Uniswap, PancakeSwap, etc.)
    // For now, we'll provide structure for future implementation

    const liquidityScore = calculateLiquidityScore(metrics);
    const volumeHealth = calculateVolumeHealth(metrics);
    const distributionFairness = calculateDistributionFairness(metrics);
    const honeypotRisk = calculateHoneypotRisk(metrics);

    const riskScore = calculateMarketRiskScore({
        liquidityScore,
        volumeHealth,
        distributionFairness,
        honeypotRisk,
    });

    const confidence = marketData ? 0.7 : 0.3;

    return {
        liquidityScore,
        volumeHealth,
        distributionFairness,
        honeypotRisk,
        metrics,
        riskScore,
        confidence,
    };
}

// ============================================================================
// Liquidity Analysis
// ============================================================================

function calculateLiquidityScore(metrics: MarketMetrics): number {
    let score = 50; // Start at medium

    // Total liquidity assessment
    if (metrics.totalLiquidity !== undefined) {
        if (metrics.totalLiquidity > 10_000_000) {
            score += 30; // Excellent liquidity
        } else if (metrics.totalLiquidity > 1_000_000) {
            score += 20; // Good liquidity
        } else if (metrics.totalLiquidity > 100_000) {
            score += 10; // Moderate liquidity
        } else if (metrics.totalLiquidity < 10_000) {
            score -= 20; // Very low liquidity - high risk
        }
    }

    // Liquidity lock status
    if (metrics.liquidityLocked) {
        score += 15; // Locked liquidity = safer

        if (metrics.lockDuration && metrics.lockDuration > 365) {
            score += 5; // Locked for > 1 year
        }
    } else {
        score -= 10; // Unlocked liquidity = rug pull risk
    }

    return normalizeRiskScore(score);
}

// ============================================================================
// Volume Analysis
// ============================================================================

function calculateVolumeHealth(metrics: MarketMetrics): number {
    let score = 50;

    if (metrics.volume24h === undefined) {
        return score; // No data
    }

    // 24h volume analysis
    if (metrics.volume24h > 1_000_000) {
        score += 25; // High volume
    } else if (metrics.volume24h > 100_000) {
        score += 15;
    } else if (metrics.volume24h < 10_000) {
        score -= 15; // Low volume
    }

    // Volume change analysis
    if (metrics.volumeChange !== undefined) {
        if (Math.abs(metrics.volumeChange) > 500) {
            score -= 20; // Extreme volume spike = pump/dump risk
        } else if (Math.abs(metrics.volumeChange) > 200) {
            score -= 10; // Large volume change
        }
    }

    // 7-day volume comparison
    if (metrics.volume7d && metrics.volume24h) {
        const avgDaily = metrics.volume7d / 7;
        const ratio = metrics.volume24h / avgDaily;

        if (ratio > 5) {
            score -= 15; // Unusual spike
        } else if (ratio < 0.2) {
            score -= 10; // Volume dying
        }
    }

    return normalizeRiskScore(score);
}

// ============================================================================
// Token Distribution Analysis
// ============================================================================

function calculateDistributionFairness(metrics: MarketMetrics): number {
    let score = 50;

    // Top holder concentration
    if (metrics.topHolderConcentration !== undefined) {
        if (metrics.topHolderConcentration > 50) {
            score -= 30; // >50% held by top holders = centralized
        } else if (metrics.topHolderConcentration > 30) {
            score -= 15;
        } else if (metrics.topHolderConcentration < 10) {
            score += 20; // Well distributed
        }
    }

    // Gini coefficient (0 = perfect equality, 1 = perfect inequality)
    if (metrics.giniCoefficient !== undefined) {
        if (metrics.giniCoefficient > 0.8) {
            score -= 25; // Very unequal distribution
        } else if (metrics.giniCoefficient < 0.5) {
            score += 15; // Fair distribution
        }
    }

    // Creator holdings
    if (metrics.creatorHoldings !== undefined) {
        if (metrics.creatorHoldings > 20) {
            score -= 20; // Creator holds >20% = dump risk
        } else if (metrics.creatorHoldings > 10) {
            score -= 10;
        } else if (metrics.creatorHoldings === 0) {
            score += 10; // Creator sold all/renounced
        }
    }

    // Burned tokens
    if (metrics.burnedTokens !== undefined) {
        if (metrics.burnedTokens > 50) {
            score += 15; // Significant burn = deflationary
        } else if (metrics.burnedTokens > 20) {
            score += 5;
        }
    }

    return normalizeRiskScore(score);
}

// ============================================================================
// Honeypot Detection
// ============================================================================

function calculateHoneypotRisk(metrics: MarketMetrics): number {
    let risk = 0;

    // Max slippage analysis
    if (metrics.maxSlippage !== undefined) {
        if (metrics.maxSlippage > 50) {
            risk = 90; // Cannot sell = honeypot
        } else if (metrics.maxSlippage > 20) {
            risk = 60; // High slippage
        } else if (metrics.maxSlippage > 10) {
            risk = 30; // Moderate slippage
        }
    }

    return normalizeRiskScore(risk);
}

// ============================================================================
// Composite Risk Score
// ============================================================================

function calculateMarketRiskScore(params: {
    liquidityScore: number;
    volumeHealth: number;
    distributionFairness: number;
    honeypotRisk: number;
}): number {
    const { liquidityScore, volumeHealth, distributionFairness, honeypotRisk } = params;

    // Calculate weighted risk
    // Lower liquidity/volume/distribution scores = higher risk
    // Higher honeypot risk = higher risk

    const liquidityRisk = 100 - liquidityScore;
    const volumeRisk = 100 - volumeHealth;
    const distributionRisk = 100 - distributionFairness;

    const weightedRisk =
        liquidityRisk * 0.3 +
        volumeRisk * 0.2 +
        distributionRisk * 0.3 +
        honeypotRisk * 0.2;

    return normalizeRiskScore(weightedRisk);
}

// ============================================================================
// Default Result
// ============================================================================

function createDefaultMarketResult(): MarketSignalsResult {
    return {
        liquidityScore: 50,
        volumeHealth: 50,
        distributionFairness: 50,
        honeypotRisk: 50,
        metrics: {},
        riskScore: 50,
        confidence: 0.2,
    };
}

// ============================================================================
// Utility Functions
// ============================================================================

export function getMarketSummary(result: MarketSignalsResult): string {
    const issues: string[] = [];

    if (result.liquidityScore < 40) {
        issues.push('low liquidity');
    }
    if (result.volumeHealth < 40) {
        issues.push('unhealthy volume');
    }
    if (result.distributionFairness < 40) {
        issues.push('concentrated holdings');
    }
    if (result.honeypotRisk > 60) {
        issues.push('possible honeypot');
    }

    if (issues.length > 0) {
        return `Market analysis reveals: ${issues.join(', ')}.`;
    }

    if (result.liquidityScore > 70 && result.volumeHealth > 70) {
        return 'Strong market indicators with healthy liquidity and volume.';
    }

    return 'Market metrics within normal range.';
}
