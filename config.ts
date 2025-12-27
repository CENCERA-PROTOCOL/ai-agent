/**
 * Configuration for Cencera AI System
 * Supports B2B client-specific risk threshold customization
 */

import { RiskConfig } from './types';

// ============================================================================
// Default Configuration
// ============================================================================

export const DEFAULT_RISK_CONFIG: Required<RiskConfig> = {
    safeZone: 80,
    dangerZone: 50,
    weights: {
        onChain: 0.45,
        market: 0.30,
        social: 0.15,
        ai: 0.10,
    },
    enabledEngines: {
        patternRecognition: true,
        behavioral: true,
        contractSecurity: true,
        transactionRisk: true,
    },
};

// ============================================================================
// Engine Configuration
// ============================================================================

export const ENGINE_CONFIG = {
    /** Pattern Recognition Engine Settings */
    patternRecognition: {
        /** Minimum confidence for pattern match (0-1) */
        minConfidence: 0.6,

        /** Weight multipliers for different threat types (0-1) */
        threatWeights: {
            drainer_contract: 1.0,
            honeypot: 0.9,
            rug_pull: 0.95,
            phishing: 0.85,
            sybil_attack: 0.7,
            flash_loan_exploit: 0.8,
            mev_bot: 0.5, // MEV bots aren't necessarily malicious
            pump_and_dump: 0.8,
            fake_token: 0.9,
            unlimited_mint: 0.85,
            suspicious_pattern: 0.6,
        },
    },

    /** Behavioral Analysis Engine Settings */
    behavioral: {
        /** Z-score threshold for anomaly detection */
        anomalyZScoreThreshold: 2.5,

        /** Minimum transaction count for reliable analysis */
        minTxCountForAnalysis: 10,

        /** Days to consider for dormant wallet detection */
        dormantThresholdDays: 180,

        /** Days to consider for new wallet classification */
        newWalletThresholdDays: 7,
    },

    /** Contract Security Engine Settings */
    contractSecurity: {
        /** Bytecode size threshold for detailed analysis (bytes) */
        minBytecodeSize: 100,

        /** Vulnerability severity multipliers */
        vulnerabilitySeverityMultipliers: {
            selfdestruct: 0.95,
            delegatecall: 0.9,
            unlimited_approval: 0.85,
            hidden_mint: 0.9,
            ownership_manipulation: 0.8,
            reentrancy: 0.85,
            integer_overflow: 0.7,
            access_control: 0.75,
            unverified_source: 0.6,
            proxy_upgrade_risk: 0.7,
        },
    },

    /** Transaction Risk Engine Settings */
    transactionRisk: {
        /** Gas price spike threshold (% above average) */
        gasSpikeThreshold: 2.0, // 200% of average

        /** Minimum confidence for safe transaction (0-1) */
        minSafetyConfidence: 0.7,
    },
};

// ============================================================================
// Performance Configuration
// ============================================================================

export const PERFORMANCE_CONFIG = {
    /** Cache TTL in milliseconds */
    cacheTTL: {
        aiAnalysis: 5 * 60 * 1000, // 5 minutes
        patternRecognition: 10 * 60 * 1000, // 10 minutes
        contractSecurity: 30 * 60 * 1000, // 30 minutes (contracts don't change often)
    },

    /** Analysis timeout in milliseconds */
    analysisTimeout: 10000, // 10 seconds max per analysis

    /** Maximum concurrent engine executions */
    maxConcurrentEngines: 4,
};

// ============================================================================
// Client-Specific Configurations (B2B)
// ============================================================================

/**
 * Pre-configured risk profiles for different use cases
 * Clients can use these as templates or create custom configs
 */
export const RISK_PROFILES: Record<string, RiskConfig> = {
    /** Conservative profile for financial institutions */
    conservative: {
        safeZone: 90,
        dangerZone: 70,
        weights: {
            onChain: 0.40,
            market: 0.30,
            social: 0.15,
            ai: 0.15, // Higher AI weight for conservative clients
        },
    },

    /** Standard profile (default) */
    standard: {
        ...DEFAULT_RISK_CONFIG,
    },

    /** Aggressive profile for DeFi protocols */
    aggressive: {
        safeZone: 60,
        dangerZone: 30,
        weights: {
            onChain: 0.50,
            market: 0.25,
            social: 0.15,
            ai: 0.10,
        },
    },

    /** Development/Testing profile (permissive) */
    development: {
        safeZone: 50,
        dangerZone: 20,
        weights: {
            onChain: 0.45,
            market: 0.30,
            social: 0.15,
            ai: 0.10,
        },
        enabledEngines: {
            patternRecognition: true,
            behavioral: true,
            contractSecurity: false, // Disable for faster testing
            transactionRisk: false,
        },
    },
};

// ============================================================================
// Configuration Utilities
// ============================================================================

/**
 * Merge client config with defaults
 */
export function mergeRiskConfig(
    clientConfig?: Partial<RiskConfig>
): Required<RiskConfig> {
    if (!clientConfig) {
        return DEFAULT_RISK_CONFIG;
    }

    return {
        safeZone: clientConfig.safeZone ?? DEFAULT_RISK_CONFIG.safeZone,
        dangerZone: clientConfig.dangerZone ?? DEFAULT_RISK_CONFIG.dangerZone,
        weights: {
            onChain: clientConfig.weights?.onChain ?? DEFAULT_RISK_CONFIG.weights.onChain,
            market: clientConfig.weights?.market ?? DEFAULT_RISK_CONFIG.weights.market,
            social: clientConfig.weights?.social ?? DEFAULT_RISK_CONFIG.weights.social,
            ai: clientConfig.weights?.ai ?? DEFAULT_RISK_CONFIG.weights.ai,
        },
        enabledEngines: {
            patternRecognition: clientConfig.enabledEngines?.patternRecognition ?? DEFAULT_RISK_CONFIG.enabledEngines.patternRecognition,
            behavioral: clientConfig.enabledEngines?.behavioral ?? DEFAULT_RISK_CONFIG.enabledEngines.behavioral,
            contractSecurity: clientConfig.enabledEngines?.contractSecurity ?? DEFAULT_RISK_CONFIG.enabledEngines.contractSecurity,
            transactionRisk: clientConfig.enabledEngines?.transactionRisk ?? DEFAULT_RISK_CONFIG.enabledEngines.transactionRisk,
        },
    };
}

/**
 * Validate risk configuration
 */
export function validateRiskConfig(config: RiskConfig): {
    isValid: boolean;
    errors: string[];
} {
    const errors: string[] = [];

    // Validate zones
    if (config.safeZone <= config.dangerZone) {
        errors.push('safeZone must be greater than dangerZone');
    }

    if (config.safeZone < 0 || config.safeZone > 100) {
        errors.push('safeZone must be between 0 and 100');
    }

    if (config.dangerZone < 0 || config.dangerZone > 100) {
        errors.push('dangerZone must be between 0 and 100');
    }

    // Validate weights
    if (config.weights) {
        const { onChain = 0, market = 0, social = 0, ai = 0 } = config.weights;
        const sum = onChain + market + social + ai;

        // Allow small floating point errors
        if (Math.abs(sum - 1.0) > 0.001) {
            errors.push(`weights must sum to 1.0 (currently: ${sum})`);
        }

        if (onChain < 0 || market < 0 || social < 0 || ai < 0) {
            errors.push('all weights must be non-negative');
        }
    }

    return {
        isValid: errors.length === 0,
        errors,
    };
}

/**
 * Get risk profile by name
 */
export function getRiskProfile(profileName: string): RiskConfig | null {
    return RISK_PROFILES[profileName] || null;
}
