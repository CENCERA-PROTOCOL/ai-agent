/**
 * OSINT Discovery Engine
 * External entity discovery and verification
 */

import axios from 'axios';
import * as cheerio from 'cheerio';
import {
    AIAnalysisRequest,
    OSINTResult,
    MarketData,
    SocialLinks,
    WebsiteValidation,
} from './types';
import { normalizeRiskScore, calculateConfidence } from './aiUtils';

// ============================================================================
// Configuration
// ============================================================================

const TIMEOUT = 5000; // 5 seconds
const MAX_RETRIES = 2;

// API endpoints (can be configured via environment variables)
const COINGECKO_API = process.env.COINGECKO_API_URL || 'https://api.coingecko.com/api/v3';
const CMC_API = process.env.COINMARKETCAP_API_URL || 'https://pro-api.coinmarketcap.com/v1';

// ============================================================================
// Main OSINT Analysis
// ============================================================================

export async function analyzeOSINT(
    request: AIAnalysisRequest
): Promise<OSINTResult> {
    console.log(`[OSINT] Analyzing ${request.address}...`);

    const results = await Promise.allSettled([
        fetchMarketData(request.address, request.chainId || '1'),
        fetchSocialLinks(request.address, request.tokenMetadata?.symbol),
        validateWebsite(request.address, request.tokenMetadata?.symbol),
    ]);

    const marketData = results[0].status === 'fulfilled' ? results[0].value : undefined;
    const socialLinks = results[1].status === 'fulfilled' ? results[1].value : {};
    const websiteStatus = results[2].status === 'fulfilled' ? results[2].value : createDefaultWebsiteStatus();

    // Determine verification status
    const isVerified = !!marketData?.verified || hasVerifiedSocials(socialLinks);
    const listings: string[] = [];
    if (marketData) {
        listings.push(marketData.source);
    }

    // Calculate risk score based on OSINT findings
    const riskScore = calculateOSINTRiskScore({
        isVerified,
        marketData,
        socialLinks,
        websiteStatus,
    });

    // Calculate confidence based on data availability
    const confidence = calculateOSINTConfidence({
        hasMarketData: !!marketData,
        hasSocialLinks: Object.keys(socialLinks).length > 0,
        hasWebsite: websiteStatus.exists,
    });

    return {
        isVerified,
        marketData,
        socialLinks,
        websiteStatus,
        listings,
        riskScore,
        confidence,
    };
}

// ============================================================================
// Market Data Fetching
// ============================================================================

async function fetchMarketData(
    address: string,
    chainId: string
): Promise<MarketData | undefined> {
    // Try CoinGecko first (free tier available)
    try {
        const cgData = await fetchCoinGeckoData(address, chainId);
        if (cgData) return cgData;
    } catch (error) {
        console.log('[OSINT] CoinGecko fetch failed:', error);
    }

    // Fallback to CoinMarketCap if API key is available
    if (process.env.COINMARKETCAP_API_KEY) {
        try {
            const cmcData = await fetchCoinMarketCapData(address);
            if (cmcData) return cmcData;
        } catch (error) {
            console.log('[OSINT] CoinMarketCap fetch failed:', error);
        }
    }

    return undefined;
}

async function fetchCoinGeckoData(
    address: string,
    chainId: string
): Promise<MarketData | undefined> {
    const platformId = getPlatformId(chainId);
    if (!platformId) return undefined;

    try {
        const response = await axios.get(
            `${COINGECKO_API}/coins/${platformId}/contract/${address.toLowerCase()}`,
            {
                timeout: TIMEOUT,
                headers: {
                    'Accept': 'application/json',
                    ...(process.env.COINGECKO_API_KEY && {
                        'x-cg-pro-api-key': process.env.COINGECKO_API_KEY
                    })
                }
            }
        );

        const data = response.data;

        return {
            source: 'coingecko',
            rank: data.market_cap_rank,
            marketCap: data.market_data?.market_cap?.usd,
            volume24h: data.market_data?.total_volume?.usd,
            priceUsd: data.market_data?.current_price?.usd,
            priceChange24h: data.market_data?.price_change_percentage_24h,
            circulatingSupply: data.market_data?.circulating_supply,
            totalSupply: data.market_data?.total_supply,
            verified: true,
        };
    } catch (error: any) {
        if (error.response?.status === 404) {
            // Token not found on CoinGecko
            return undefined;
        }
        throw error;
    }
}

async function fetchCoinMarketCapData(
    address: string
): Promise<MarketData | undefined> {
    if (!process.env.COINMARKETCAP_API_KEY) return undefined;

    try {
        const response = await axios.get(
            `${CMC_API}/cryptocurrency/quotes/latest`,
            {
                params: { address: address.toLowerCase() },
                timeout: TIMEOUT,
                headers: {
                    'X-CMC_PRO_API_KEY': process.env.COINMARKETCAP_API_KEY,
                    'Accept': 'application/json',
                }
            }
        );

        const data = Object.values(response.data.data)[0] as any;

        return {
            source: 'coinmarketcap',
            rank: data.cmc_rank,
            marketCap: data.quote?.USD?.market_cap,
            volume24h: data.quote?.USD?.volume_24h,
            priceUsd: data.quote?.USD?.price,
            priceChange24h: data.quote?.USD?.percent_change_24h,
            circulatingSupply: data.circulating_supply,
            totalSupply: data.total_supply,
            verified: true,
        };
    } catch (error: any) {
        if (error.response?.status === 400) {
            // Token not found on CMC
            return undefined;
        }
        throw error;
    }
}

function getPlatformId(chainId: string): string | undefined {
    const platformMap: Record<string, string> = {
        '1': 'ethereum',
        '56': 'binance-smart-chain',
        '137': 'polygon-pos',
        '43114': 'avalanche',
        '250': 'fantom',
        '42161': 'arbitrum-one',
        '10': 'optimistic-ethereum',
    };
    return platformMap[chainId];
}

// ============================================================================
// Social Links Discovery
// ============================================================================

async function fetchSocialLinks(
    address: string,
    symbol?: string
): Promise<SocialLinks> {
    const links: SocialLinks = {};

    // In a production environment, this would scrape from:
    // - Block explorers (Etherscan, BSCScan, etc.)
    // - CoinGecko/CMC API responses
    // - Direct website parsing

    // For now, we'll return empty links with a note that this needs
    // integration with specific data sources

    console.log('[OSINT] Social links discovery needs API integration');

    return links;
}

function hasVerifiedSocials(links: SocialLinks): boolean {
    // Consider verified if has official website and at least one social
    return !!(links.website && (links.twitter || links.telegram || links.github));
}

// ============================================================================
// Website Validation
// ============================================================================

async function validateWebsite(
    address: string,
    symbol?: string
): Promise<WebsiteValidation> {
    // In production, this would:
    // 1. Extract website from CoinGecko/CMC/block explorer
    // 2. Check SSL certificate
    // 3. Parse domain age from WHOIS
    // 4. Analyze content quality with cheerio
    // 5. Check for phishing patterns

    console.log('[OSINT] Website validation needs implementation');

    return createDefaultWebsiteStatus();
}

function createDefaultWebsiteStatus(): WebsiteValidation {
    return {
        exists: false,
        hasSSL: false,
        contentQuality: 'none',
        riskFlags: [],
    };
}

// ============================================================================
// Risk Scoring
// ============================================================================

function calculateOSINTRiskScore(params: {
    isVerified: boolean;
    marketData?: MarketData;
    socialLinks: SocialLinks;
    websiteStatus: WebsiteValidation;
}): number {
    const { isVerified, marketData, socialLinks, websiteStatus } = params;

    let riskScore = 50; // Start at medium risk

    // Verified on major platforms = very low risk
    if (isVerified && marketData) {
        riskScore -= 30;

        // High market cap = lower risk
        if (marketData.marketCap && marketData.marketCap > 100_000_000) {
            riskScore -= 10; // Top 100 token
        } else if (marketData.marketCap && marketData.marketCap > 10_000_000) {
            riskScore -= 5; // Established token
        }

        // Good rank = lower risk
        if (marketData.rank && marketData.rank < 100) {
            riskScore -= 5;
        }
    } else {
        // Not verified = higher risk
        riskScore += 20;
    }

    // Social presence
    const socialCount = Object.keys(socialLinks).filter(k => k !== 'website').length;
    if (socialCount >= 3) {
        riskScore -= 10; // Strong social presence
    } else if (socialCount === 0) {
        riskScore += 15; // No social = suspicious
    }

    // Website validation
    if (websiteStatus.exists) {
        if (websiteStatus.hasSSL && websiteStatus.contentQuality === 'high') {
            riskScore -= 10;
        }
        riskScore += websiteStatus.riskFlags.length * 5;
    } else {
        riskScore += 10; // No website = suspicious
    }

    return normalizeRiskScore(riskScore);
}

function calculateOSINTConfidence(params: {
    hasMarketData: boolean;
    hasSocialLinks: boolean;
    hasWebsite: boolean;
}): number {
    const { hasMarketData, hasSocialLinks, hasWebsite } = params;

    let dataPoints = 0;
    if (hasMarketData) dataPoints++;
    if (hasSocialLinks) dataPoints++;
    if (hasWebsite) dataPoints++;

    // Confidence is based on how much data we could gather
    const confidence = dataPoints / 3;

    return Math.max(0.3, confidence); // Minimum 30% confidence
}

// ============================================================================
// Utility Functions
// ============================================================================

export function getOSINTSummary(result: OSINTResult): string {
    if (result.isVerified) {
        const source = result.marketData?.source || 'verified sources';
        return `Verified on ${source}.`;
    }

    if (result.listings.length === 0) {
        return 'Not verified on major platforms.';
    }

    return `Limited verification (${result.listings.join(', ')}).`;
}
