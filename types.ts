/**
 * Type Definitions for Cencera AI System
 * Custom AI for Trust Score Analysis
 */

// ============================================================================
// Risk Configuration (B2B Configurable)
// ============================================================================

export interface RiskConfig {
    /** Score >= safeZone = "Safe" label (default: 80) */
    safeZone: number;

    /** Score < dangerZone = "High Risk" label (default: 50) */
    dangerZone: number;

    /** Custom weights for trust score calculation (must sum to 1.0) */
    weights?: {
        onChain?: number;    // default: 0.45
        market?: number;     // default: 0.30
        social?: number;     // default: 0.15
        ai?: number;         // default: 0.10
    };

    /** Toggle specific analysis engines on/off */
    enabledEngines?: {
        patternRecognition?: boolean;
        behavioral?: boolean;
        contractSecurity?: boolean;
        transactionRisk?: boolean;
    };
}

// ============================================================================
// AI Analysis Request & Response
// ============================================================================

export interface AIAnalysisRequest {
    /** Blockchain address or ENS name */
    address: string;

    /** ENS name if resolved */
    ensName?: string | null;

    /** Account balance in ETH */
    balance: string;

    /** Total transaction count */
    txCount: number;

    /** Is this a smart contract? */
    isContract: boolean;

    /** Contract bytecode size */
    codeSize: number;

    /** Token metadata if applicable */
    tokenMetadata?: TokenMetadata;

    /** Contract bytecode (hex string) */
    bytecode?: string;

    /** Contrast source code (if verified on Explorer) */
    sourceCode?: string;

    /** Chain ID */
    chainId?: string;

    /** Preliminary trust score (used for AI analysis) */
    preliminaryScore?: number;

    /** Client-specific risk configuration */
    riskConfig?: RiskConfig;
}

export interface TokenMetadata {
    name?: string;
    symbol?: string;
    decimals?: number;
    totalSupply?: string;
}

export interface AIAnalysisResult {
    /** Human-readable summary of risk analysis */
    summary: string;

    /** Risk level classification */
    riskLevel: "Critical" | "High" | "Medium" | "Low" | "Safe";

    /** Detailed audit notes and findings */
    auditNotes: string[];

    /** Raw AI risk score (0-100, higher = more risky) */
    aiRiskScore: number;

    /** Breakdown of AI analysis by engine */
    engineResults?: {
        patternRecognition?: PatternRecognitionResult;
        behavioral?: BehavioralAnalysisResult;
        contractSecurity?: ContractSecurityResult;
        transactionRisk?: TransactionRiskResult;
    };

    /** Applied risk configuration (for transparency) */
    appliedConfig?: RiskConfig;
}

// ============================================================================
// Engine-Specific Results
// ============================================================================

export interface PatternRecognitionResult {
    /** Risk score from pattern matching (0-100) */
    riskScore: number;

    /** Detected threat patterns */
    threats: ThreatPattern[];

    /** Matched against known scam addresses */
    isKnownThreat: boolean;

    /** Confidence in pattern detection (0-1) */
    confidence: number;
}

export interface ThreatPattern {
    /** Type of threat detected */
    type: ThreatType;

    /** Description of the threat */
    description: string;

    /** Severity level (0-10) */
    severity: number;

    /** Confidence in detection (0-1) */
    confidence: number;
}

export type ThreatType =
    | "drainer_contract"
    | "honeypot"
    | "rug_pull"
    | "phishing"
    | "sybil_attack"
    | "flash_loan_exploit"
    | "mev_bot"
    | "pump_and_dump"
    | "fake_token"
    | "unlimited_mint"
    | "suspicious_pattern";

export interface BehavioralAnalysisResult {
    /** Risk score from behavioral analysis (0-100) */
    riskScore: number;

    /** Detected behavioral anomalies */
    anomalies: BehavioralAnomaly[];

    /** Activity pattern classification */
    activityPattern: "normal" | "suspicious" | "bot" | "dormant" | "new";

    /** Confidence in analysis (0-1) */
    confidence: number;
}

export interface BehavioralAnomaly {
    /** Type of behavioral anomaly */
    type: string;

    /** Description of the anomaly */
    description: string;

    /** Severity level (0-10) */
    severity: number;

    /** Statistical significance (z-score) */
    zScore?: number;
}

export interface ContractSecurityResult {
    /** Risk score from contract analysis (0-100) */
    riskScore: number;

    /** Detected vulnerabilities */
    vulnerabilities: ContractVulnerability[];

    /** Dangerous functions found */
    dangerousFunctions: string[];

    /** Is contract verified? */
    isVerified?: boolean;

    /** Confidence in analysis (0-1) */
    confidence: number;
}

export interface ContractVulnerability {
    /** Type of vulnerability */
    type: VulnerabilityType;

    /** Description of the vulnerability */
    description: string;

    /** Severity level (0-10) */
    severity: number;

    /** Recommended action */
    recommendation?: string;
}

export type VulnerabilityType =
    | "selfdestruct"
    | "delegatecall"
    | "unlimited_approval"
    | "hidden_mint"
    | "ownership_manipulation"
    | "reentrancy"
    | "integer_overflow"
    | "access_control"
    | "unverified_source"
    | "proxy_upgrade_risk";

export interface TransactionRiskResult {
    /** Risk score from transaction analysis (0-100) */
    riskScore: number;

    /** Detected transaction risks */
    risks: TransactionRisk[];

    /** Is transaction safe to execute? */
    isSafe: boolean;

    /** Confidence in analysis (0-1) */
    confidence: number;
}

export interface TransactionRisk {
    /** Type of transaction risk */
    type: string;

    /** Description of the risk */
    description: string;

    /** Severity level (0-10) */
    severity: number;
}

// ============================================================================
// Knowledge Base Types
// ============================================================================

export interface ThreatIntelligence {
    /** Known malicious addresses */
    scamAddresses: Set<string>;

    /** Known malicious contract bytecode patterns */
    scamBytecodePatterns: BytecodePattern[];

    /** Whitelisted safe addresses */
    safeAddresses: Set<string>;

    /** Known attack signatures */
    attackSignatures: AttackSignature[];
}

export interface BytecodePattern {
    /** Pattern identifier */
    id: string;

    /** Bytecode pattern (hex) */
    pattern: string;

    /** Threat type */
    threatType: ThreatType;

    /** Pattern description */
    description: string;
}

export interface AttackSignature {
    /** Signature identifier */
    id: string;

    /** Attack name */
    name: string;

    /** Attack description */
    description: string;

    /** Detection rules */
    rules: DetectionRule[];
}

export interface DetectionRule {
    /** Rule identifier */
    id: string;

    /** Rule type */
    type: "bytecode" | "transaction_pattern" | "behavior" | "metadata";

    /** Rule condition */
    condition: any;

    /** Weight in detection (0-1) */
    weight: number;
}

// ============================================================================
// Utility Types
// ============================================================================

export interface CacheEntry<T> {
    data: T;
    timestamp: number;
    ttl: number;
}

export interface StatisticalMetrics {
    mean: number;
    stdDev: number;
    min: number;
    max: number;
    median: number;
}

export interface ConfidenceScore {
    /** Overall confidence (0-1) */
    overall: number;

    /** Confidence breakdown by factor */
    factors: {
        dataQuality: number;
        sampleSize: number;
        patternClarity: number;
    };
}
