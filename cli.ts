
import { analyzeAddress } from './aiCore';
import { getKnowledgeBase } from './knowledgeBase';
import * as dotenv from 'dotenv';

// Load environment variables
dotenv.config();

async function main() {
    const args = process.argv.slice(2);

    if (args.length === 0) {
        console.log(`
🤖 Cencera AI Agent CLI
=======================
Usage: npm start <address> [chainId]

Examples:
  npm start 0x123...          (Analyze address on Ethereum Mainnet)
  npm start 0x123... 137      (Analyze address on Polygon)
  npm start -- --stats        (Show Knowledge Base stats)
`);
        process.exit(0);
    }

    const input = args[0];

    // Stats command
    if (input === '--stats') {
        const kb = getKnowledgeBase();
        console.log('\n📊 Knowledge Base Statistics:');
        console.log(`   - Scam Addresses: ${kb.scamAddresses.size}`);
        console.log(`   - Safe Addresses: ${kb.safeAddresses.size}`);
        console.log(`   - Attack Signatures: ${kb.attackSignatures.length}`);
        console.log(`   - Bytecode Patterns: ${kb.scamBytecodePatterns.length}\n`);
        return;
    }

    // Analysis command
    const address = input;
    const chainId = args[1] || '1'; // Default to Ethereum

    console.log(`\n🔍 Starting Deep Analysis for: ${address}`);
    console.log(`   Chain ID: ${chainId}`);
    console.log(`   Data Sources: Live RPC + Etherscan V2 API 🟢\n`);

    try {
        console.time('Analysis Duration');

        // Get Etherscan V2 API key from environment (one key for all chains!)
        const apiKey = process.env.ETHERSCAN_API_KEY || '';

        const result = await analyzeAddress(address, chainId, apiKey);
        console.timeEnd('Analysis Duration');

        console.log('\n✅ Analysis Complete');
        console.log('==================================================');
        console.log(`Risk Level:   ${getColoredRisk(result.riskLevel)}`);
        console.log(`Risk Score:   ${result.aiRiskScore}/100`);
        console.log(`Confidence:   ${Math.round((result.engineResults?.contractSecurity?.confidence || 0) * 100)}%`);
        console.log('==================================================');

        console.log('\n📝 Summary:');
        console.log(result.summary);

        if (result.auditNotes.length > 0) {
            console.log('\n🚩 Risk Indicators:');
            result.auditNotes.forEach(note => console.log(`   - ${note}`));
        }

        if (result.appliedConfig) {
            console.log(`\n⚙️  Config Used: Safe Zone > ${result.appliedConfig.safeZone}, Danger Zone < ${result.appliedConfig.dangerZone}`);
        }

    } catch (error: any) {
        console.error('\n❌ Analysis Failed:', error.message);
        if (error.message.includes('fetch')) {
            console.error('   (Check your internet connection for live blockchain data)');
        }
    }
}

function getColoredRisk(level: string): string {
    // Basic ANSI colors
    const reset = "\x1b[0m";
    const red = "\x1b[31m";
    const green = "\x1b[32m";
    const yellow = "\x1b[33m";

    if (level === 'Critical' || level === 'High') return `${red}${level}${reset}`;
    if (level === 'Safe' || level === 'Low') return `${green}${level}${reset}`;
    return `${yellow}${level}${reset}`;
}

main();
