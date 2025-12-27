/**
 * Social Media Analysis Engine
 * Analyzes social media presence for authenticity and sentiment
 */

import axios from 'axios';
import Sentiment from 'sentiment';
import {
    AIAnalysisRequest,
    SocialAnalysisResult,
    SocialMetrics,
    SocialLinks,
} from './types';
import { normalizeRiskScore } from './aiUtils';

// ============================================================================
// Configuration
// ============================================================================

const sentiment = new Sentiment();
const TIMEOUT = 5000;

// ============================================================================
// Main Social Analysis
// ============================================================================

export async function analyzeSocial(
    request: AIAnalysisRequest,
    socialLinks?: SocialLinks
): Promise<SocialAnalysisResult> {
    console.log(`[Social] Analyzing social presence for ${request.address}...`);

    // If we have social links from OSINT, analyze them
    if (!socialLinks || Object.keys(socialLinks).length === 0) {
        return createDefaultSocialResult();
    }

    // Analyze Twitter if available (primary platform for crypto)
    if (socialLinks.twitter) {
        try {
            const twitterAnalysis = await analyzeTwitterAccount(socialLinks.twitter);
            return twitterAnalysis;
        } catch (error) {
            console.log('[Social] Twitter analysis failed:', error);
        }
    }

    // Fallback to basic analysis from available links
    return analyzeFromLinks(socialLinks);
}

// ============================================================================
// Twitter Analysis
// ============================================================================

async function analyzeTwitterAccount(twitterUrl: string): Promise<SocialAnalysisResult> {
    // Extract handle from URL
    const handle = extractTwitterHandle(twitterUrl);
    if (!handle) {
        return createDefaultSocialResult();
    }

    // Note: In production, this would use Twitter API v2
    // For now, we'll simulate the analysis

    console.log(`[Social] Twitter analysis for @${handle} requires API key`);

    // Simulated metrics (would come from Twitter API)
    const metrics: SocialMetrics = {
        accountAge: 730, // 2 years (simulated)
        followerCount: 0,
        followingCount: 0,
        tweetCount: 0,
        isVerified: false,
        engagementRate: 0,
        botLikelihood: 0.5, // Unknown
    };

    return analyzeSocialMetrics(metrics, 'twitter');
}

function extractTwitterHandle(url: string): string | null {
    const match = url.match(/twitter\.com\/([a-zA-Z0-9_]+)|x\.com\/([a-zA-Z0-9_]+)/);
    return match ? (match[1] || match[2]) : null;
}

// ============================================================================
// Social Metrics Analysis
// ============================================================================

function analyzeSocialMetrics(
    metrics: SocialMetrics,
    platform: 'twitter' | 'telegram' | 'discord' | 'none'
): SocialAnalysisResult {
    const redFlags: string[] = [];
    let authenticityScore = 50; // Start at medium
    let botProbability = 0.5;
    let sentiment: 'positive' | 'neutral' | 'negative' | 'warning' = 'neutral';

    // Account age analysis
    if (metrics.accountAge !== undefined) {
        if (metrics.accountAge < 30) {
            redFlags.push('Very new account (< 1 month)');
            authenticityScore -= 20;
        } else if (metrics.accountAge < 90) {
            redFlags.push('Recently created account (< 3 months)');
            authenticityScore -= 10;
        } else if (metrics.accountAge > 365) {
            authenticityScore += 15; // Established account
        }
    }

    // Verified status
    if (metrics.isVerified) {
        authenticityScore += 25;
        botProbability = 0.1; // Very unlikely to be bot
    }

    // Follower analysis
    if (metrics.followerCount !== undefined) {
        if (metrics.followerCount > 100000) {
            authenticityScore += 20; // Large following
        } else if (metrics.followerCount > 10000) {
            authenticityScore += 10;
        } else if (metrics.followerCount < 100) {
            redFlags.push('Very low follower count');
            authenticityScore -= 15;
        }

        // Follower/following ratio
        if (metrics.followingCount && metrics.followerCount) {
            const ratio = metrics.followingCount / metrics.followerCount;
            if (ratio > 5) {
                redFlags.push('Suspicious follower/following ratio');
                authenticityScore -= 10;
                botProbability += 0.2;
            }
        }
    }

    // Engagement analysis
    if (metrics.engagementRate !== undefined) {
        if (metrics.engagementRate > 0.05) {
            authenticityScore += 10; // Good engagement
        } else if (metrics.engagementRate < 0.001) {
            redFlags.push('Very low engagement rate');
            authenticityScore -= 15;
            botProbability += 0.2;
        }
    }

    // Bot likelihood
    if (metrics.botLikelihood !== undefined) {
        botProbability = metrics.botLikelihood;
        if (metrics.botLikelihood > 0.7) {
            redFlags.push('High bot probability detected');
            authenticityScore -= 25;
            sentiment = 'warning';
        }
    }

    // Overall sentiment
    if (authenticityScore > 70) {
        sentiment = 'positive';
    } else if (authenticityScore < 30) {
        sentiment = 'negative';
    }

    // Calculate risk score (inverse of authenticity)
    const riskScore = normalizeRiskScore(100 - authenticityScore);

    // Confidence based on data availability
    const dataPoints = [
        metrics.accountAge,
        metrics.followerCount,
        metrics.engagementRate,
        metrics.isVerified,
    ].filter(x => x !== undefined).length;
    const confidence = Math.max(0.3, dataPoints / 4);

    return {
        platform,
        authenticityScore: normalizeRiskScore(authenticityScore),
        botProbability: Math.max(0, Math.min(1, botProbability)),
        sentiment,
        metrics,
        redFlags,
        riskScore,
        confidence,
    };
}

// ============================================================================
// Fallback Analysis
// ============================================================================

function analyzeFromLinks(links: SocialLinks): SocialAnalysisResult {
    const linkCount = Object.keys(links).filter(k => k !== 'website').length;
    let authenticityScore = 50;

    if (linkCount >= 3) {
        authenticityScore += 20; // Multiple platforms = good
    } else if (linkCount === 0) {
        authenticityScore -= 30; // No social presence = suspicious
    }

    if (links.github) {
        authenticityScore += 10; // Open source = good
    }

    const riskScore = normalizeRiskScore(100 - authenticityScore);

    return {
        platform: 'none',
        authenticityScore: normalizeRiskScore(authenticityScore),
        botProbability: 0.5,
        sentiment: 'neutral',
        metrics: {},
        redFlags: linkCount === 0 ? ['No social media presence'] : [],
        riskScore,
        confidence: 0.3, // Low confidence without actual APIs
    };
}

function createDefaultSocialResult(): SocialAnalysisResult {
    return {
        platform: 'none',
        authenticityScore: 50,
        botProbability: 0.5,
        sentiment: 'neutral',
        metrics: {},
        redFlags: ['No social links available'],
        riskScore: 50,
        confidence: 0.2,
    };
}

// ============================================================================
// Utility Functions
// ============================================================================

export function getSocialSummary(result: SocialAnalysisResult): string {
    if (result.platform === 'none') {
        return 'No social media presence detected.';
    }

    if (result.authenticityScore > 70) {
        return `Strong ${result.platform} presence with high authenticity.`;
    }

    if (result.botProbability > 0.7) {
        return `Suspicious ${result.platform} account with high bot probability.`;
    }

    if (result.redFlags.length > 0) {
        return `${result.platform} account has concerning signals.`;
    }

    return `${result.platform} presence detected with moderate authenticity.`;
}

// ============================================================================
// Advanced Analysis (for future implementation with APIs)
// ============================================================================

/**
 * Analyze tweet content for sentiment and scam indicators
 * Requires Twitter API v2 access
 */
async function analyzeTweetContent(tweets: string[]): Promise<{
    sentiment: number;
    scamIndicators: string[];
}> {
    const scamKeywords = [
        'airdrop',
        'giveaway',
        'dm me',
        'send eth',
        'double your',
        'guaranteed profit',
        'risk free',
    ];

    const scamIndicators: string[] = [];
    let totalSentiment = 0;

    for (const tweet of tweets) {
        // Sentiment analysis
        const result = sentiment.analyze(tweet.toLowerCase());
        totalSentiment += result.score;

        // Scam keyword detection
        for (const keyword of scamKeywords) {
            if (tweet.toLowerCase().includes(keyword)) {
                scamIndicators.push(`Contains scam keyword: "${keyword}"`);
            }
        }
    }

    return {
        sentiment: tweets.length > 0 ? totalSentiment / tweets.length : 0,
        scamIndicators,
    };
}
