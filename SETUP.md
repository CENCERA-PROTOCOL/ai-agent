# Cencera AI Agent - Setup Guide

## Quick Start

### 1. Install Dependencies

```bash
npm install
```

### 2. Configure API Keys

Copy the example environment file:

```bash
cp .env.example .env
```

Edit `.env` and add your API keys:

```env
ETHERSCAN_API_KEY=your_actual_etherscan_api_key
POLYGONSCAN_API_KEY=your_actual_polygonscan_api_key
# ... add other keys as needed
```

**Get API Keys:**

- Etherscan: <https://etherscan.io/apis>
- Polygonscan: <https://polygonscan.com/apis>
- Optimism: <https://optimistic.etherscan.io/apis>
- Arbitrum: <https://arbiscan.io/apis>
- Base: <https://basescan.org/apis>

### 3. Run Analysis

**View Knowledge Base Stats:**

```bash
npm start -- --stats
```

**Analyze an Address:**

```bash
# Ethereum Mainnet
npm start 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D

# Polygon
npm start 0xYourAddress 137

# Any supported chain
npm start <address> <chainId>
```

## Features

✅ **Live Blockchain Data** - Fetches real-time data via Viem RPC
✅ **Etherscan Integration** - Transaction history, source code verification
✅ **Knowledge Base** - Checks against known scam/safe addresses
✅ **4 AI Engines** - Pattern recognition, behavioral analysis, security scanning, transaction risk
✅ **Multi-Chain Support** - 9 EVM chains + Non-EVM (structure ready)

## Data Sources

The AI combines three data sources:

1. **Local Knowledge Base** (`data/chains/...`)
   - Scam addresses
   - Safe addresses
   - Attack patterns
   - Bytecode signatures

2. **Live RPC** (via Viem)
   - Balance
   - Transaction count
   - Contract bytecode

3. **Etherscan API**
   - Transaction history
   - Token transfers
   - Contract source code
   - Verification status

## Supported Chains

- **EVM**: Ethereum (1), Polygon (137), Optimism (10), Arbitrum (42161), Base (8453), BSC (56), Avalanche (43114), Fantom (250), zkSync (324)
- **Non-EVM**: Solana, Cosmos (structure ready, implementation pending)

## Output

The analysis provides:

- **Risk Score** (0-100, lower is safer)
- **Risk Level** (Safe, Low, Medium, High, Critical)
- **Detailed Summary**
- **Audit Notes** (specific findings)
- **Engine Breakdown** (pattern, behavioral, security, transaction)

## Example Output

```bash
🔍 Starting Deep Analysis for: 0x7a25...2488D
   Chain ID: 1
   Data Sources: Live RPC + Etherscan API 🟢

✅ Analysis Complete
==================================================
Risk Level:   Safe
Risk Score:   8/100
Confidence:   95%
==================================================

📝 Summary:
Verified contract with extensive transaction history. No malicious patterns detected.

🚩 Risk Indicators:
   - Contract verified on Etherscan ✓
   - High transaction volume (15,000+ txs)
   - No dangerous opcodes detected
```

## Environment Variables

All environment variables are optional but **highly recommended** for full functionality:

| Variable | Description | Required For |
|----------|-------------|--------------|
| `ETHERSCAN_API_KEY` | Ethereum data | Mainnet analysis |
| `POLYGONSCAN_API_KEY` | Polygon data | Polygon analysis |
| `OPTIMISM_API_KEY` | Optimism data | Optimism analysis |
| `ARBISCAN_API_KEY` | Arbitrum data | Arbitrum analysis |
| `BASESCAN_API_KEY` | Base data | Base analysis |
| `BSCSCAN_API_KEY` | BSC data | BSC analysis |
| `SNOWTRACE_API_KEY` | Avalanche data | Avalanche analysis |
| `FTMSCAN_API_KEY` | Fantom data | Fantom analysis |

**Without API keys**, the system will still work using RPC + local knowledge base, but you'll miss:

- Transaction history analysis
- Source code verification
- Token transfer tracking
