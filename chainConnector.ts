
import { createPublicClient, http, formatEther, type PublicClient } from 'viem';
import { mainnet, polygon, optimism, arbitrum, base, bsc, avalanche, fantom, zkSync } from 'viem/chains';

// ============================================================================
// Chain Configuration
// ============================================================================

export const SUPPORTED_CHAINS: Record<string, any> = {
    '1': mainnet,
    '137': polygon,
    '10': optimism,
    '42161': arbitrum,
    '8453': base,
    '56': bsc,
    '43114': avalanche,
    '250': fantom,
    '324': zkSync
};

// Etherscan V2 API - Single Endpoint for All Chains!
const ETHERSCAN_V2_API = 'https://api.etherscan.io/v2/api';

// ============================================================================
// Blockchain Service
// ============================================================================

export class BlockchainService {
    private clients: Map<string, any>; // Using any to bypass complex Viem Client constraints
    private apiKey: string; // Single Etherscan V2 API key for all chains

    constructor(apiKey: string = '') {
        this.clients = new Map();
        this.apiKey = apiKey;
    }

    /**
     * Get or create a Viem public client for the specified chain
     */
    getClient(chainId: string): PublicClient {
        if (this.clients.has(chainId)) {
            return this.clients.get(chainId)!;
        }

        const chain = SUPPORTED_CHAINS[chainId];
        if (!chain) {
            throw new Error(`Unsupported chain ID: ${chainId}`);
        }

        const client = createPublicClient({
            chain,
            transport: http() // Uses default Viem RPCs (public)
        });

        this.clients.set(chainId, client);
        return client as PublicClient;
    }

    /**
     * Fetch basic on-chain data for an address
     */
    async getIdentitydata(address: string, chainId: string) {
        if (!address.startsWith('0x')) {
            // TODO: Add Solana support logic here
            throw new Error('Only EVM addresses (0x...) are currently supported for live fetch');
        }

        const client = this.getClient(chainId);
        const [balance, txCount, code] = await Promise.all([
            client.getBalance({ address: address as `0x${string}` }),
            client.getTransactionCount({ address: address as `0x${string}` }),
            client.getBytecode({ address: address as `0x${string}` })
        ]);

        return {
            balance: formatEther(balance),
            txCount,
            isContract: !!code && code.length > 2,
            codeSize: code ? (code.length - 2) / 2 : 0,
            bytecode: code
        };
    }

    /**
     * Fetch contract source code from Etherscan V2 API
     */
    async getContractSource(address: string, chainId: string): Promise<string | null> {
        if (!this.apiKey) return null;

        try {
            const url = `${ETHERSCAN_V2_API}?chainid=${chainId}&module=contract&action=getsourcecode&address=${address}&apikey=${this.apiKey}`;
            const response = await fetch(url);
            const data = await response.json() as any;

            if (data.status === '1' && data.result && data.result[0]) {
                return data.result[0].SourceCode;
            }
        } catch (error) {
            console.error(`[BlockchainService] Error fetching source code:`, error);
        }
        return null;
    }

    /**
     * Fetch contract ABI from Etherscan V2 API
     */
    async getContractABI(address: string, chainId: string): Promise<any | null> {
        if (!this.apiKey) return null;

        try {
            const url = `${ETHERSCAN_V2_API}?chainid=${chainId}&module=contract&action=getabi&address=${address}&apikey=${this.apiKey}`;
            const response = await fetch(url);
            const data = await response.json() as any;

            if (data.status === '1' && data.result) {
                return JSON.parse(data.result);
            }
        } catch (error) {
            console.error(`[BlockchainService] Error fetching ABI:`, error);
        }
        return null;
    }

    /**
     * Fetch transaction history from Etherscan V2 API
     */
    async getTransactionHistory(address: string, chainId: string, limit: number = 100): Promise<any[] | null> {
        if (!this.apiKey) return null;

        try {
            const url = `${ETHERSCAN_V2_API}?chainid=${chainId}&module=account&action=txlist&address=${address}&startblock=0&endblock=99999999&page=1&offset=${limit}&sort=desc&apikey=${this.apiKey}`;
            const response = await fetch(url);
            const data = await response.json() as any;

            if (data.status === '1' && data.result) {
                return data.result;
            }
        } catch (error) {
            console.error(`[BlockchainService] Error fetching transactions:`, error);
        }
        return null;
    }

    /**
     * Fetch ERC20 token transfers from Etherscan V2 API
     */
    async getTokenTransfers(address: string, chainId: string, limit: number = 100): Promise<any[] | null> {
        if (!this.apiKey) return null;

        try {
            const url = `${ETHERSCAN_V2_API}?chainid=${chainId}&module=account&action=tokentx&address=${address}&startblock=0&endblock=99999999&page=1&offset=${limit}&sort=desc&apikey=${this.apiKey}`;
            const response = await fetch(url);
            const data = await response.json() as any;

            if (data.status === '1' && data.result) {
                return data.result;
            }
        } catch (error) {
            console.error(`[BlockchainService] Error fetching token transfers:`, error);
        }
        return null;
    }

    /**
     * Fetch internal transactions from Etherscan V2 API
     */
    async getInternalTransactions(address: string, chainId: string, limit: number = 100): Promise<any[] | null> {
        if (!this.apiKey) return null;

        try {
            const url = `${ETHERSCAN_V2_API}?chainid=${chainId}&module=account&action=txlistinternal&address=${address}&startblock=0&endblock=99999999&page=1&offset=${limit}&sort=desc&apikey=${this.apiKey}`;
            const response = await fetch(url);
            const data = await response.json() as any;

            if (data.status === '1' && data.result) {
                return data.result;
            }
        } catch (error) {
            console.error(`[BlockchainService] Error fetching internal transactions:`, error);
        }
        return null;
    }

    /**
     * Check if address is a contract and get creation info from Etherscan V2 API
     */
    async getContractCreationInfo(address: string, chainId: string): Promise<any | null> {
        if (!this.apiKey) return null;

        try {
            const url = `${ETHERSCAN_V2_API}?chainid=${chainId}&module=contract&action=getcontractcreation&contractaddresses=${address}&apikey=${this.apiKey}`;
            const response = await fetch(url);
            const data = await response.json() as any;

            if (data.status === '1' && data.result && data.result.length > 0) {
                return data.result[0];
            }
        } catch (error) {
            console.error(`[BlockchainService] Error fetching contract creation:`, error);
        }
        return null;
    }
}
