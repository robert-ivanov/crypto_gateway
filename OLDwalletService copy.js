const db = require('./db'); // DB utility file
const crypto = require('crypto'); // For generating unique API keys

// Function to generate a unique API key for the merchant
const generateApiKey = () => {
    return crypto.randomBytes(32).toString('hex');
};

// Function to create a wallet entry and generate keys (common for all types)
const createWallet = async (merchantId, coin, network, walletType) => {
    try {
        // Generate a mock address for the wallet (You should replace this with a proper address generation logic)
        const walletAddress = crypto.randomBytes(32).toString('hex'); // Placeholder: Replace with actual address generation logic

        // Insert wallet record into DB with the generated address
        const walletResult = await db.query(
            'INSERT INTO wallets (merchant_id, currency, network, wallet_type, address) VALUES ($1, $2, $3, $4, $5) RETURNING id',
            [merchantId, coin, network, walletType, walletAddress]  // Added walletAddress here
        );
        
        const walletId = walletResult.rows[0].id;

        // Generate wallet keys (private and public)
        const { privateKey, publicKey } = generateWalletKeys();

        // Store the wallet keys in the wallet_keys table
        await db.query(
            'INSERT INTO wallet_keys (wallet_id, private_key, public_key) VALUES ($1, $2, $3)',
            [walletId, privateKey, publicKey]
        );

        return { walletId, privateKey, publicKey, walletAddress };  // Returning wallet address as well
    } catch (error) {
        console.error('Error creating wallet:', error);
        throw new Error('Error creating wallet');
    }
};

// Function to generate wallet keys (private and public)
const generateWalletKeys = () => {
    const privateKey = crypto.randomBytes(32).toString('hex');  // Example, replace with actual wallet generation logic
    const publicKey = crypto.randomBytes(32).toString('hex');   // Example, replace with actual wallet generation logic

    return { privateKey, publicKey };
};

// Function to create multiple wallets for merchant (Merchant Wallet, Middle Wallet, Internal Wallet)
const createWalletsForMerchant = async (merchantId, coin, network) => {
    try {
        // 1. Create Merchant Wallet (only once)
        const merchantWallet = await createWallet(merchantId, coin, network, 'merchant');
        // 2. Create Middle Wallet (this can be created multiple times, e.g., for different transaction purposes)
        const middleWallets = [];
            const middleWallet = await createWallet(merchantId, coin, network, 'middle');
            middleWallets.push(middleWallet);
        
        // 3. Create Internal Wallet (only once)
        const internalWallet = await createWallet(merchantId, coin, network, 'internal');
        
        return { 
            merchantWallet, 
            middleWallets,  // Return an array of middle wallets
            internalWallet 
        };
    } catch (error) {
        console.error('Error creating wallets:', error);
        throw new Error('Internal server error');
    }
};
const createMiddleWallet = async (merchantId, coin, network) => {
    try {
        // Check if a middle wallet already exists for the given coin and network
        const existingWallet = await db.query(
            'SELECT * FROM wallets WHERE merchant_id = $1 AND wallet_type = $2 AND currency = $3 AND network = $4',
            [merchantId, 'middle', coin, network]
        );

        if (existingWallet.rows.length > 0) {
            // If a wallet exists, return a message indicating that the wallet already exists
            return { message: 'Middle wallet already exists for the given coin and network.' };
        }

        // Generate a mock address for the wallet (You should replace this with actual address generation logic)
        const walletAddress = crypto.randomBytes(32).toString('hex'); // Placeholder: Replace with actual address generation logic

        // Insert wallet record into DB with the generated address
        const walletResult = await db.query(
            'INSERT INTO wallets (merchant_id, currency, network, wallet_type, address) VALUES ($1, $2, $3, $4, $5) RETURNING id',
            [merchantId, coin, network, 'middle', walletAddress]  // Added walletAddress here
        );
        
        const walletId = walletResult.rows[0].id;

        // Generate wallet keys (private and public)
        const { privateKey, publicKey } = generateWalletKeys();

        // Store the wallet keys in the wallet_keys table
        await db.query(
            'INSERT INTO wallet_keys (wallet_id, private_key, public_key) VALUES ($1, $2, $3)',
            [walletId, privateKey, publicKey]
        );

        return { walletId, privateKey, publicKey, walletAddress };  // Returning wallet address as well
    } catch (error) {
        console.error('Error creating middle wallet:', error);
        throw new Error('Error creating middle wallet');
    }
};

// Function to get all middle wallets for a merchant
const getAllMiddleWallets = async (merchantId) => {
    try {
        const result = await db.query('SELECT * FROM wallets WHERE merchant_id = $1 AND wallet_type = $2', [merchantId, 'middle']);
        
        // Return only the relevant details (walletId, address, coin, network)
        return result.rows.map(wallet => ({
            walletId: wallet.id,
            address: wallet.address,
            coin: wallet.currency,
            network: wallet.network
        }));
    } catch (error) {
        console.error('Error retrieving middle wallets:', error);
        throw new Error('Error retrieving middle wallets');
    }
};
module.exports = {
    generateApiKey,
    createWalletsForMerchant,
    createMiddleWallet,
    getAllMiddleWallets
};
