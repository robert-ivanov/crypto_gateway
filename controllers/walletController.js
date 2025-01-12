const { generateApiKey, createWalletsForMerchant, createMiddleWallet, getAllMiddleWallets } = require('../walletService');
const db = require('../db');

async function generateApiKeyAndWallet(req, res) {
    const { merchantId, coin, network } = req.body;
    try {
        const merchant_id_from_token = req.user.merchant_id;
        if (merchantId !== merchant_id_from_token) return res.status(403).json({ message: 'Unauthorized: Merchant ID mismatch' });

        const merchantResult = await db.query('SELECT * FROM merchants WHERE id = $1 AND is_verified = true', [merchantId]);
        if (merchantResult.rows.length === 0) return res.status(400).json({ message: 'Merchant not found or not verified' });

        const merchant = merchantResult.rows[0];
        if (merchant.api_key) return res.status(400).json({ message: 'API key already exists' });

        const apiKey = generateApiKey();
        await db.query('UPDATE merchants SET api_key = $1 WHERE id = $2', [apiKey, merchantId]);

        const wallets = await createWalletsForMerchant(merchantId, coin, network);

        res.status(200).json({
            message: 'API Key and Wallets created successfully',
            api_key: apiKey,
            wallets: wallets,
        });
    } catch (error) {
        console.error('Error generating API key and creating wallets:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
}

async function addMiddleWallet(req, res) {
    const { merchantId, coin, network } = req.body;
    try {
        const merchant_id_from_token = req.user.merchant_id;
        if (merchantId !== merchant_id_from_token) return res.status(403).json({ message: 'Unauthorized: Merchant ID mismatch' });

        const merchantResult = await db.query('SELECT * FROM merchants WHERE id = $1 AND is_verified = true', [merchantId]);
        if (merchantResult.rows.length === 0) return res.status(400).json({ message: 'Merchant not found or not verified' });

        const middleWallet = await createMiddleWallet(merchantId, coin, network);
        if (middleWallet.message) return res.status(400).json({ message: middleWallet.message });

        const middleWallets = await getAllMiddleWallets(merchantId);

        res.status(200).json({
            message: 'Middle wallet created successfully',
            middleWallets: middleWallets,
        });
    } catch (error) {
        console.error('Error creating middle wallet:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
}

module.exports = {
    generateApiKeyAndWallet,
    addMiddleWallet,
};
