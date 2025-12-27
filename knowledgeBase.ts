/**
 * Knowledge Base for Threat Intelligence
 * Dynamically loads threat data from JSON files for easy updates
 */

import {
    ThreatIntelligence,
    BytecodePattern,
    AttackSignature,
    ThreatType,
} from './types';
import { normalizeAddress } from './aiUtils';
import * as fs from 'fs';
import * as path from 'path';

// ============================================================================
// JSON Data Paths
// ============================================================================

const DATA_DIR = path.join(__dirname, 'data');
const CHAINS_DIR = path.join(DATA_DIR, 'chains');
const SCAM_ADDRESSES_FILE = path.join(DATA_DIR, 'scamAddresses.json');
const SAFE_ADDRESSES_FILE = path.join(DATA_DIR, 'safeAddresses.json');
const BYTECODE_PATTERNS_FILE = path.join(DATA_DIR, 'bytecodePatterns.json');
const ATTACK_SIGNATURES_FILE = path.join(DATA_DIR, 'attackSignatures.json');

// ============================================================================
// JSON Data Interfaces
// ============================================================================

interface ChainAddressData {
    scamAddresses: string[];
    safeAddresses: string[];
    lastUpdated?: string;
    chainId?: string;
    chainName?: string;
    category?: string;
}

interface ManualAddressData {
    scamAddresses?: string[];
    safeAddresses?: string[];
    lastUpdated?: string;
    sources?: string[];
}

interface BytecodePatternsData {
    bytecodePatterns: BytecodePattern[];
    lastUpdated?: string;
}

interface AttackSignaturesData {
    attackSignatures: AttackSignature[];
    lastUpdated?: string;
}

// ============================================================================
// Folder Scanning & Data Loading
// ============================================================================

/**
 * Recursively find all addresses.json files in a directory
 */
function findAddressFiles(dir: string): string[] {
    let results: string[] = [];

    if (!fs.existsSync(dir)) return results;

    const list = fs.readdirSync(dir);

    list.forEach(file => {
        const filePath = path.join(dir, file);
        const stat = fs.statSync(filePath);

        if (stat && stat.isDirectory()) {
            results = results.concat(findAddressFiles(filePath));
        } else if (file === 'addresses.json') {
            results.push(filePath);
        }
    });

    return results;
}

/**
 * Load threat data from JSON file with error handling
 */
function loadJSON<T>(filePath: string, defaultValue: T): T {
    try {
        if (fs.existsSync(filePath)) {
            const data = fs.readFileSync(filePath, 'utf-8');
            return JSON.parse(data) as T;
        }
        // For specific files, we create default if missing
        if (filePath.endsWith('bytecodePatterns.json') || filePath.endsWith('attackSignatures.json')) {
            // Create directory if it doesn't exist
            const dir = path.dirname(filePath);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            fs.writeFileSync(filePath, JSON.stringify(defaultValue, null, 2));
        }
        return defaultValue;
    } catch (error) {
        console.error(`[KnowledgeBase] Error loading ${filePath}:`, error);
        return defaultValue;
    }
}

/**
 * Save JSON data to file
 */
function saveJSON(filePath: string, data: any): void {
    try {
        const dir = path.dirname(filePath);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    } catch (error) {
        console.error(`[KnowledgeBase] Error saving ${filePath}:`, error);
    }
}

/**
 * Load scam addresses from all chain files + manual file
 */
function loadAllScamAddresses(): Set<string> {
    const addresses = new Set<string>();

    // 1. Load from Chain Files
    const files = findAddressFiles(CHAINS_DIR);
    files.forEach(file => {
        const data = loadJSON<ChainAddressData>(file, { scamAddresses: [], safeAddresses: [] });
        if (data.scamAddresses) {
            data.scamAddresses.forEach(addr => addresses.add(normalizeAddress(addr)));
        }
    });

    // 2. Load from Manual File (Root)
    if (fs.existsSync(SCAM_ADDRESSES_FILE)) {
        const data = loadJSON<ManualAddressData>(SCAM_ADDRESSES_FILE, { scamAddresses: [] });
        if (data.scamAddresses) {
            data.scamAddresses.forEach(addr => addresses.add(normalizeAddress(addr)));
        }
    }

    return addresses;
}

/**
 * Load safe addresses from all chain files + manual file
 */
function loadAllSafeAddresses(): Set<string> {
    const addresses = new Set<string>();

    // 1. Load from Chain Files
    const files = findAddressFiles(CHAINS_DIR);
    files.forEach(file => {
        const data = loadJSON<ChainAddressData>(file, { scamAddresses: [], safeAddresses: [] });
        if (data.safeAddresses) {
            data.safeAddresses.forEach(addr => addresses.add(normalizeAddress(addr)));
        }
    });

    // 2. Load from Manual File (Root)
    if (fs.existsSync(SAFE_ADDRESSES_FILE)) {
        const data = loadJSON<ManualAddressData>(SAFE_ADDRESSES_FILE, { safeAddresses: [] });
        if (data.safeAddresses) {
            data.safeAddresses.forEach((addr: string) => addresses.add(normalizeAddress(addr)));
        }
    }

    return addresses;
}

/**
 * Load bytecode patterns from JSON
 */
function loadBytecodePatterns(): BytecodePattern[] {
    const data = loadJSON<BytecodePatternsData>(BYTECODE_PATTERNS_FILE, {
        bytecodePatterns: [
            {
                id: 'honeypot_transfer_lock',
                pattern: 'ff',
                threatType: 'honeypot',
                description: 'Contains SELFDESTRUCT which can lock funds permanently',
            },
            {
                id: 'hidden_mint_function',
                pattern: '6040',
                threatType: 'unlimited_mint',
                description: 'May contain hidden minting functionality',
            },
            {
                id: 'delegatecall_proxy',
                pattern: 'f4',
                threatType: 'drainer_contract',
                description: 'Uses DELEGATECALL which can execute arbitrary code',
            },
        ],
        lastUpdated: new Date().toISOString(),
    });

    return data.bytecodePatterns;
}

/**
 * Load attack signatures from JSON
 */
function loadAttackSignatures(): AttackSignature[] {
    const data = loadJSON<AttackSignaturesData>(ATTACK_SIGNATURES_FILE, {
        attackSignatures: [],
        lastUpdated: new Date().toISOString(),
    });

    return data.attackSignatures;
}

// ============================================================================
// Dangerous Function Selectors (kept in code for performance)
// ============================================================================

/**
 * Function selectors commonly used in malicious contracts
 * First 4 bytes of keccak256 hash of function signature
 */
export const DANGEROUS_FUNCTION_SELECTORS = new Set<string>([
    '0x715018a6', // renounceOwnership()
    '0xf2fde38b', // transferOwnership(address)
    '0x40c10f19', // mint(address,uint256)
    '0x42966c68', // burn(uint256)
    '0x79cc6790', // burnFrom(address,uint256)
    '0x095ea7b3', // approve(address,uint256)
    '0xa9059cbb', // transfer(address,uint256)
    '0x23b872dd', // transferFrom(address,address,uint256)
]);

/**
 * High-risk function selectors
 */
export const HIGH_RISK_FUNCTION_SELECTORS = new Set<string>([
    '0xd0e30db0', // deposit()
    '0x3ccfd60b', // withdraw()
    '0x2e1a7d4d', // withdraw(uint256)
    '0x441a3e70', // upgradeToAndCall(address,bytes)
]);

// ============================================================================
// Knowledge Base Singleton
// ============================================================================

let knowledgeBase: ThreatIntelligence | null = null;
let lastLoadTime: number = 0;
const RELOAD_INTERVAL = 5 * 60 * 1000; // Reload every 5 minutes

/**
 * Get or initialize the threat intelligence knowledge base
 * Automatically reloads data periodically for fresh threat intelligence
 */
export function getKnowledgeBase(): ThreatIntelligence {
    const now = Date.now();

    // Reload if expired or not loaded
    if (!knowledgeBase || (now - lastLoadTime) > RELOAD_INTERVAL) {
        knowledgeBase = {
            scamAddresses: loadAllScamAddresses(),
            scamBytecodePatterns: loadBytecodePatterns(),
            safeAddresses: loadAllSafeAddresses(),
            attackSignatures: loadAttackSignatures(),
        };
        lastLoadTime = now;
        console.info('[KnowledgeBase] Loaded/reloaded threat intelligence from JSON files');
    }

    return knowledgeBase;
}

/**
 * Force reload knowledge base from JSON files
 */
export function reloadKnowledgeBase(): void {
    lastLoadTime = 0; // Reset timer to force reload
    getKnowledgeBase();
}

/**
 * Check if address is known scam
 */
export function isKnownScam(address: string): boolean {
    const kb = getKnowledgeBase();
    return kb.scamAddresses.has(normalizeAddress(address));
}

/**
 * Check if address is whitelisted as safe
 */
export function isWhitelisted(address: string): boolean {
    const kb = getKnowledgeBase();
    return kb.safeAddresses.has(normalizeAddress(address));
}

/**
 * Add address to scam database (persists to JSON)
 */
export function reportScamAddress(address: string, source?: string): void {
    const kb = getKnowledgeBase();
    const normalized = normalizeAddress(address);
    kb.scamAddresses.add(normalized);

    // Save to JSON file
    const data = loadJSON<ManualAddressData>(SCAM_ADDRESSES_FILE, { scamAddresses: [] });
    if (!data.scamAddresses) data.scamAddresses = [];

    if (!data.scamAddresses.includes(normalized)) {
        data.scamAddresses.push(normalized);
        data.lastUpdated = new Date().toISOString();
        if (source && !data.sources?.includes(source)) {
            data.sources = [...(data.sources || []), source];
        }
        saveJSON(SCAM_ADDRESSES_FILE, data);
    }

    console.info(`[KnowledgeBase] Added scam address: ${address}${source ? ` (source: ${source})` : ''}`);
}

/**
 * Add address to safe whitelist (persists to root JSON)
 */
export function whitelistAddress(address: string, source?: string): void {
    const kb = getKnowledgeBase();
    const normalized = normalizeAddress(address);
    kb.safeAddresses.add(normalized);

    // Save to JSON file
    const data = loadJSON<ManualAddressData>(SAFE_ADDRESSES_FILE, { safeAddresses: [] });
    if (!data.safeAddresses) data.safeAddresses = [];

    if (!data.safeAddresses.includes(normalized)) {
        data.safeAddresses.push(normalized);
        data.lastUpdated = new Date().toISOString();
        if (source && !data.sources?.includes(source)) {
            data.sources = [...(data.sources || []), source];
        }
        saveJSON(SAFE_ADDRESSES_FILE, data);
    }

    console.info(`[KnowledgeBase] Whitelisted address: ${address}${source ? ` (source: ${source})` : ''}`);
}

/**
 * Get all attack signatures matching a threat type
 */
export function getAttackSignatures(threatType?: ThreatType): AttackSignature[] {
    const kb = getKnowledgeBase();
    if (!threatType) return kb.attackSignatures;

    return kb.attackSignatures.filter(sig =>
        sig.rules.some(rule => rule.condition?.threatType === threatType)
    );
}

/**
 * Get malicious bytecode patterns
 */
export function getMaliciousBytecodePatterns(threatType?: ThreatType): BytecodePattern[] {
    const kb = getKnowledgeBase();
    if (!threatType) return kb.scamBytecodePatterns;

    return kb.scamBytecodePatterns.filter(pattern =>
        pattern.threatType === threatType
    );
}

// ============================================================================
// Knowledge Base Statistics
// ============================================================================

/**
 * Get knowledge base statistics
 */
export function getKnowledgeBaseStats() {
    const kb = getKnowledgeBase();
    return {
        scamAddresses: kb.scamAddresses.size,
        safeAddresses: kb.safeAddresses.size,
        bytecodePatterns: kb.scamBytecodePatterns.length,
        attackSignatures: kb.attackSignatures.length,
        lastReloaded: new Date(lastLoadTime).toISOString(),
    };
}

/**
 * Export knowledge base for backup/sharing
 */
export function exportKnowledgeBase() {
    const kb = getKnowledgeBase();
    return {
        scamAddresses: Array.from(kb.scamAddresses),
        safeAddresses: Array.from(kb.safeAddresses),
        scamBytecodePatterns: kb.scamBytecodePatterns,
        attackSignatures: kb.attackSignatures,
        exportedAt: new Date().toISOString(),
    };
}
