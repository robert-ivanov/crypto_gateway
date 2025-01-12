const express = require('express');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const db = require('./db'); // DB utility file
const { generateApiKey, createWalletsForMerchant, createMiddleWallet, getAllMiddleWallets } = require('./walletService');
const app = express();
app.use(cors()); 
app.use(bodyParser.json());

const PORT = process.env.PORT || 3000;

// Middleware to authorize internal users
const authorizeInternalUser = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', ''); // Extract the token from the Authorization header
    if (!token) {
        return res.status(401).json({ message: 'Authorization token required' });
    }

    try {
        // Verify the token using the JWT secret
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Check if the user is an internal user (admin)
        if (decoded.role !== 'internal') {
            return res.status(403).json({ message: 'Access denied. Internal users only' });
        }

        // Attach the user info to the request object
        req.user = decoded;
        next();  // Allow the request to proceed
    } catch (error) {
        return res.status(401).json({ message: 'Invalid or expired token' });
    }
};


// Middleware to authorize merchant users
const authorizeMerchantUser = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', ''); // Extract the token from the Authorization header
    if (!token) {
        return res.status(401).json({ message: 'Authorization token required' });
    }

    try {
        // Verify the token using the JWT secret
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Check if the user is a merchant user
        if (decoded.role !== 'merchant') {
            return res.status(403).json({ message: 'Access denied. Merchant users only' });
        }

        // Attach the user info to the request object
        req.user = decoded;
        next();  // Allow the request to proceed
    } catch (error) {
        return res.status(401).json({ message: 'Invalid or expired token' });
    }
};

// Merchant Login Endpoint
app.post('/api/login-merchant', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Check if the merchant user exists
        const result = await db.query('SELECT * FROM users WHERE email = $1 AND role = $2', [email, 'merchant']);
        if (result.rows.length === 0) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        const user = result.rows[0];

        // Compare the provided password with the stored hashed password
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        // Generate a JWT token for the merchant user
        const token = jwt.sign({ id: user.id, role: user.role, merchant_id: user.merchant_id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.status(200).json({
            message: 'Login successful',
            token
        });

    } catch (error) {
        console.error('Error logging in merchant user:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
app.post('/api/generate-api-key-wallet', authorizeMerchantUser, async (req, res) => {
    const { merchantId, coin, network } = req.body;

    try {
        const merchant_id_from_token = req.user.merchant_id; // Get the merchant ID from the JWT token

        // Validate that the merchantId in the body matches the merchantId in the token
        if (merchantId !== merchant_id_from_token) {
            return res.status(403).json({ message: 'Unauthorized: Merchant ID mismatch' });
        }

        // Check if the merchant exists and is verified
        const merchantResult = await db.query('SELECT * FROM merchants WHERE id = $1 AND is_verified = true', [merchantId]);
        if (merchantResult.rows.length === 0) {
            return res.status(400).json({ message: 'Merchant not found or not verified' });
        }
        const merchant = merchantResult.rows[0];

        // Check if the API key is already set
        if (merchant.api_key) {
            return res.status(400).json({ message: 'API key already exists, operation already performed' });
        }
        // Generate a new API key for the merchant
        const apiKey = generateApiKey();

        // Update the merchant with the new API key
       
        const result = await db.query('UPDATE merchants SET api_key = $1 WHERE id = $2', [apiKey, merchantId]);

        if (result.rowCount === 1) {
            // Create the wallets for the merchant and store the keys
            const wallets = await createWalletsForMerchant(merchantId, coin, network);

            res.status(200).json({
                message: 'API Key and Wallets created successfully',
                api_key: apiKey,
                wallets: wallets,
            });
        } else {
            res.status(400).json({ message: 'Failed to update merchant API key' });
        }
    } catch (error) {
        console.error('Error generating API key and creating wallets:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/api/add-middle-wallet', authorizeMerchantUser, async (req, res) => {
    const { merchantId, coin, network } = req.body;

    try {
        const merchant_id_from_token = req.user.merchant_id; // Get the merchant ID from the JWT token

        // Validate that the merchantId in the body matches the merchantId in the token
        if (merchantId !== merchant_id_from_token) {
            return res.status(403).json({ message: 'Unauthorized: Merchant ID mismatch' });
        }

        // Check if the merchant exists and is verified
        const merchantResult = await db.query('SELECT * FROM merchants WHERE id = $1 AND is_verified = true', [merchantId]);
        if (merchantResult.rows.length === 0) {
            return res.status(400).json({ message: 'Merchant not found or not verified' });
        }

        // Create a middle wallet for the merchant
        const middleWallet = await createMiddleWallet(merchantId, coin, network);
        if (middleWallet.message) {
            return res.status(400).json({ message: middleWallet.message });
        }
        // Retrieve all middle wallets for the merchant
        const middleWallets = await getAllMiddleWallets(merchantId);

        res.status(200).json({
            message: 'Middle wallet created successfully',
            middleWallets: middleWallets,  // Return all middle wallets
        });
    } catch (error) {
        console.error('Error creating middle wallet:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});



// Internal User Registration Endpoint
app.post('/api/register-internal-user', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Validate that all fields are provided
        if (!email || !password) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        // Check if email already exists for internal users
        const existingUser = await db.query('SELECT * FROM users WHERE email = $1 AND role = $2', [email, 'internal']);
        if (existingUser.rows.length > 0) {
            return res.status(400).json({ message: 'Email is already registered' });
        }

        // Hash the password for secure storage
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert the new internal user into the database
        const result = await db.query(
            'INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3) RETURNING id, email, role',
            [email, hashedPassword, 'internal']
        );

        res.status(201).json({ message: 'Internal user registered successfully', internal_user: result.rows[0] });
    } catch (error) {
        console.error('Error during internal user registration:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Merchant Registration Endpoint
app.post('/api/register', async (req, res) => {
    const { company_name, email, password } = req.body;

    try {
        // Validate that all fields are provided
        if (!company_name || !email || !password) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        // Check if email already exists
        const existingMerchant = await db.query('SELECT * FROM merchants WHERE email = $1', [email]);
        if (existingMerchant.rows.length > 0) {
            return res.status(400).json({ message: 'Email is already registered' });
        }

        // Hash the password for secure storage
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert the new merchant into the database
        const result = await db.query(
            'INSERT INTO merchants (company_name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, company_name, email',
            [company_name, email, hashedPassword]
        );

        res.status(201).json({ message: 'Merchant registered successfully', merchant: result.rows[0] });
    } catch (error) {
        console.error('Error during merchant registration:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Internal User Login Endpoint
app.post('/api/login-internal', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Check if the internal user exists
        const result = await db.query('SELECT * FROM users WHERE email = $1 AND role = $2', [email, 'internal']);
        if (result.rows.length === 0) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        const user = result.rows[0];

        // Compare the provided password with the stored hashed password
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        // Generate a JWT token for the internal user
        const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.status(200).json({
            message: 'Login successful',
            token
        });

    } catch (error) {
        console.error('Error logging in internal user:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Merchant Verification and Merchant User Creation Endpoint (only for internal users)
app.post('/api/verify-merchant', authorizeInternalUser, async (req, res) => {
    const { merchant_id } = req.body;

    try {
        // Check if the merchant exists
        const merchantResult = await db.query('SELECT * FROM merchants WHERE id = $1', [merchant_id]);
        if (merchantResult.rows.length === 0) {
            return res.status(400).json({ message: 'Merchant not found' });
        }

        // Check if the merchant is already verified
        if (merchantResult.rows[0].is_verified) {
            return res.status(400).json({ message: 'Merchant is already verified' });
        }

        // Update the merchant to be verified
        await db.query('UPDATE merchants SET is_verified = true WHERE id = $1', [merchant_id]);

        // Now create the merchant user
        const email = merchantResult.rows[0].email;
        const password = 'merchantPassword123';  // You can generate or set a password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create the merchant user in the users table
        const userResult = await db.query(
            'INSERT INTO users (email, password_hash, role, merchant_id) VALUES ($1, $2, $3, $4) RETURNING id, email, role',
            [email, hashedPassword, 'merchant', merchant_id]
        );

        res.status(200).json({
            message: 'Merchant verified and merchant user created',
            merchant_user: userResult.rows[0]
        });

    } catch (error) {
        console.error('Error verifying merchant:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
