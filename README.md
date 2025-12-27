# Cencera Custom AI System

## Overview

Custom-built AI system for analyzing blockchain entities (wallets, smart contracts, tokens) to provide real-time risk assessment and security analysis.

## Architecture

### Modular Engine Design

- **Pattern Recognition Engine**: Detects known scam patterns, attack signatures
- **Behavioral Analysis Engine**: Identifies anomalies in transaction patterns
- **Contract Security Engine**: Scans for vulnerabilities in smart contracts
- **Transaction Risk Engine**: Evaluates transaction safety
- **AI Core Orchestrator**: Coordinates all engines and produces final assessment

### B2B Configurable Risk Thresholds

Clients can customize:

- Safe zone threshold (default: 80)
- Danger zone threshold (default: 50)
- Engine weights for trust score calculation
- Enable/disable specific analysis engines

## Files

### Core Infrastructure

- `types.ts` - TypeScript type definitions
- `config.ts` - Configuration system with B2B risk profiles
- `aiUtils.ts` - Utility functions (statistics, caching, pattern matching)
- `knowledgeBase.ts` - Threat intelligence database

### Analysis Engines

- `patternRecognition.ts` - Scam pattern detection
- `behavioralAnalysis.ts` - Activity pattern classification
- `contractSecurity.ts` - Vulnerability scanning
- `transactionRisk.ts` - Transaction safety evaluation
- `aiCore.ts` - Main orchestrator

## Usage

```typescript
import { analyzeWithAI } from './aiCore';
import { RiskConfig } from './types';

// Basic analysis
const result = await analyzeWithAI({
  address: '0x...',
  balance: '1.5',
  txCount: 150,
  isContract: false,
  codeSize: 0,
});

// With custom risk config (B2B)
const customConfig: RiskConfig = {
  safeZone: 90,      // Conservative
  dangerZone: 70,
};

const result = await analyzeWithAI({
  address: '0x...',
  // ... other fields
  riskConfig: customConfig,
});
```

## Risk Profiles

Pre-configured profiles available:

- **Conservative**: Safe 90+, Danger <70 (for financial institutions)
- **Standard**: Safe 80+, Danger <50 (default)
- **Aggressive**: Safe 60+, Danger <30 (for DeFi protocols)
- **Development**: Safe 50+, Danger <20 (for testing)

## Integration

The AI system is integrated with the Cencera prototype via `prototype/src/lib/aiAgent.ts`, which acts as a bridge between the blockchain data fetching and the AI analysis.

## Future Enhancements

- Train ML models using collected data
- NFT-specific analysis
- Cross-chain correlation
- Real-time threat feed integration
- Community contribution system
