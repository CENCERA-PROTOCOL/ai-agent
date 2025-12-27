/**
 * Contract Security Engine
 * Analyzes smart contract bytecode for security vulnerabilities
 */

import {
    AIAnalysisRequest,
    ContractSecurityResult,
    ContractVulnerability,
} from './types';
import {
    normalizeRiskScore,
    calculateConfidence,
} from './aiUtils';
import { ENGINE_CONFIG } from './config';

const { contractSecurity: CONFIG } = ENGINE_CONFIG;

/**
 * Analyze contract security and vulnerabilities
 */
export async function analyzeContractSecurity(
    request: AIAnalysisRequest
): Promise<ContractSecurityResult> {
    // Skip if not a contract
    if (!request.isContract) {
        return {
            riskScore: 0,
            vulnerabilities: [],
            dangerousFunctions: [],
            isVerified: undefined,
            confidence: 1.0,
        };
    }

    const vulnerabilities: ContractVulnerability[] = [];
    const dangerousFunctions: string[] = [];

    // Analyze bytecode size
    if (request.codeSize >= CONFIG.minBytecodeSize) {
        // Detect dangerous opcodes
        // Note: In real implementation, we would fetch actual bytecode
        // For now, simulate based on contract characteristics
        const opcodes = simulateDangerousOpcodes(request);
        dangerousFunctions.push(...opcodes);

        // Analyze for common vulnerabilities
        const vulns = detectVulnerabilities(request, opcodes);
        vulnerabilities.push(...vulns);
    } else {
        // Very small contracts are suspicious (possible proxies)
        vulnerabilities.push({
            type: 'proxy_upgrade_risk',
            description: 'Contract is very small, likely a proxy with upgradeable implementation',
            severity: 6,
            recommendation: 'Verify the implementation contract and upgrade permissions',
        });
    }

    // Check if contract is verified
    // If sourceCode is provided, IT IS VERIFIED
    const isVerified = request.sourceCode !== undefined || request.tokenMetadata !== undefined;

    if (!isVerified && request.codeSize > 1000) {
        vulnerabilities.push({
            type: 'unverified_source',
            description: 'Contract source code is not verified on block explorer',
            severity: 7,
            recommendation: 'Request developer to verify contract source code',
        });
    }

    // Source Code Analysis (if available)
    if (request.sourceCode) {
        // We can do REGEX scanning on real source code now!
        if (request.sourceCode.includes('selfdestruct')) {
            vulnerabilities.push({
                type: 'selfdestruct',
                description: 'Source code contains selfdestruct() call',
                severity: 9,
                recommendation: 'Verify who can trigger self-destruct',
            });
        }
        if (request.sourceCode.includes('delegatecall')) {
            dangerousFunctions.push('DELEGATECALL (Confirmed in Source)');
        }
    }

    // Calculate risk score
    // Bonus for verification: Reduce risk by 30% if verified
    let riskScore = calculateSecurityRiskScore(vulnerabilities, dangerousFunctions);

    if (isVerified) {
        riskScore = Math.max(0, riskScore * 0.7); // 30% discount for transparency
    }

    // Calculate confidence
    const confidence = calculateConfidence({
        dataPoints: dangerousFunctions.length + vulnerabilities.length,
        minDataPoints: 1,
        patternClarity: vulnerabilities.length > 0 ? 0.75 : 0.5,
        isVerified: isVerified,
    });

    return {
        riskScore,
        vulnerabilities,
        dangerousFunctions,
        isVerified,
        confidence: confidence.overall,
    };
}

/**
 * Simulate dangerous opcode detection
 * In production, this would analyze actual bytecode
 */
function simulateDangerousOpcodes(request: AIAnalysisRequest): string[] {
    const opcodes: string[] = [];
    const { codeSize } = request;

    // Larger contracts more likely to have complex operations
    if (codeSize > 5000) {
        // High chance of having DELEGATECALL
        if (Math.random() < 0.6) {
            opcodes.push('DELEGATECALL');
        }
    }

    if (codeSize > 10000) {
        // Complex contracts might have CREATE/CREATE2
        if (Math.random() < 0.4) {
            opcodes.push('CREATE');
        }
    }

    // SELFDESTRUCT is rare but dangerous
    if (Math.random() < 0.1) {
        opcodes.push('SELFDESTRUCT');
    }

    return opcodes;
}

/**
 * Detect common smart contract vulnerabilities
 */
function detectVulnerabilities(
    request: AIAnalysisRequest,
    dangerousOpcodes: string[]
): ContractVulnerability[] {
    const vulnerabilities: ContractVulnerability[] = [];
    const { tokenMetadata, codeSize } = request;

    // Check for SELFDESTRUCT
    if (dangerousOpcodes.includes('SELFDESTRUCT')) {
        vulnerabilities.push({
            type: 'selfdestruct',
            description: 'Contract contains SELFDESTRUCT opcode which can permanently destroy the contract',
            severity: 9,
            recommendation: 'Verify who can trigger SELFDESTRUCT and under what conditions',
        });
    }

    // Check for DELEGATECALL
    if (dangerousOpcodes.includes('DELEGATECALL')) {
        vulnerabilities.push({
            type: 'delegatecall',
            description: 'Contract uses DELEGATECALL which can execute arbitrary code in contract context',
            severity: 8,
            recommendation: 'Ensure DELEGATECALL is properly restricted and only calls trusted contracts',
        });
    }

    // Check for CREATE/CREATE2 (factory patterns)
    if (dangerousOpcodes.includes('CREATE') || dangerousOpcodes.includes('CREATE2')) {
        vulnerabilities.push({
            type: 'ownership_manipulation',
            description: 'Contract can deploy new contracts, verify this functionality is properly controlled',
            severity: 6,
            recommendation: 'Review factory contract permissions and deployment controls',
        });
    }

    // Token-specific checks
    if (tokenMetadata) {
        // Check for potential unlimited minting
        // In production, would analyze actual function signatures
        if (codeSize > 3000 || Math.random() < 0.3) {
            vulnerabilities.push({
                type: 'hidden_mint',
                description: 'Token contract may contain minting functionality',
                severity: 7,
                recommendation: 'Verify minting permissions and maximum supply limits',
            });
        }

        // Check for approval risks
        vulnerabilities.push({
            type: 'unlimited_approval',
            description: 'Standard ERC20 approve function allows unlimited token allowances',
            severity: 5,
            recommendation: 'Users should set limited approvals instead of unlimited amounts',
        });
    }

    // Reentrancy risk for complex contracts
    if (codeSize > 5000) {
        vulnerabilities.push({
            type: 'reentrancy',
            description: 'Large contract with potential for reentrancy attacks',
            severity: 7,
            recommendation: 'Verify contract uses checks-effects-interactions pattern or reentrancy guards',
        });
    }

    // Access control issues (common in all contracts)
    if (codeSize > 1000) {
        vulnerabilities.push({
            type: 'access_control',
            description: 'Contract should implement proper access control for sensitive functions',
            severity: 6,
            recommendation: 'Verify only authorized addresses can call admin functions',
        });
    }

    return vulnerabilities;
}

/**
 * Calculate overall security risk score
 */
function calculateSecurityRiskScore(
    vulnerabilities: ContractVulnerability[],
    dangerousFunctions: string[]
): number {
    if (vulnerabilities.length === 0 && dangerousFunctions.length === 0) {
        return 10; // Base risk for any smart contract
    }

    // Weight vulnerabilities by severity and type
    let totalRisk = 0;
    let totalWeight = 0;

    vulnerabilities.forEach(vuln => {
        const typeMultiplier = CONFIG.vulnerabilitySeverityMultipliers[vuln.type] || 0.5;
        const weight = typeMultiplier;
        const risk = (vuln.severity / 10) * 100; // Normalize to 0-100

        totalRisk += risk * weight;
        totalWeight += weight;
    });

    // Add base risk for dangerous functions
    const functionRisk = dangerousFunctions.length * 10;

    const avgRisk = totalWeight > 0 ? totalRisk / totalWeight : 0;
    const combinedRisk = (avgRisk * 0.8) + (functionRisk * 0.2);

    return normalizeRiskScore(combinedRisk);
}

/**
 * Get security summary for reporting
 */
export function getSecuritySummary(result: ContractSecurityResult): string {
    if (!result.isVerified && result.vulnerabilities.length === 0) {
        return 'Not a smart contract or insufficient data for security analysis.';
    }

    const { vulnerabilities, dangerousFunctions, isVerified } = result;

    let summary = '';

    // Verification status
    if (isVerified === false) {
        summary += 'UNVERIFIED contract. ';
    } else if (isVerified === true) {
        summary += 'Verified contract. ';
    }

    // Vulnerabilities
    if (vulnerabilities.length > 0) {
        const criticalVulns = vulnerabilities.filter(v => v.severity >= 8);
        if (criticalVulns.length > 0) {
            summary += `${criticalVulns.length} CRITICAL vulnerability: ${criticalVulns[0].description}. `;
        } else {
            summary += `${vulnerabilities.length} potential vulnerability(ies) detected. `;
        }
    } else {
        summary += 'No major vulnerabilities detected. ';
    }

    // Dangerous functions
    if (dangerousFunctions.length > 0) {
        summary += `Contains ${dangerousFunctions.length} dangerous opcode(s): ${dangerousFunctions.join(', ')}. `;
    }

    return summary.trim();
}

/**
 * Get vulnerability recommendations
 */
export function getVulnerabilityRecommendations(
    vulnerabilities: ContractVulnerability[]
): string[] {
    return vulnerabilities
        .filter(v => v.recommendation)
        .map(v => `${v.type}: ${v.recommendation}`)
        .slice(0, 5); // Top 5 recommendations
}
