const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('../db');

// Merchant Login Endpoint
async function loginMerchant(req, res) {
    const { email, password } = req.body;
    try {
        const result = await db.query('SELECT * FROM users WHERE email = $1 AND role = $2', [email, 'merchant']);
        if (result.rows.length === 0) return res.status(400).json({ message: 'Invalid email or password' });

        const user = result.rows[0];
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) return res.status(400).json({ message: 'Invalid email or password' });

        const token = jwt.sign({ id: user.id, role: user.role, merchant_id: user.merchant_id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.status(200).json({ message: 'Login successful', token });
    } catch (error) {
        console.error('Error logging in merchant user:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
}

// Internal User Login Endpoint
async function loginInternalUser(req, res) {
    const { email, password } = req.body;
    try {
        const result = await db.query('SELECT * FROM users WHERE email = $1 AND role = $2', [email, 'internal']);
        if (result.rows.length === 0) return res.status(400).json({ message: 'Invalid email or password' });

        const user = result.rows[0];
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) return res.status(400).json({ message: 'Invalid email or password' });

        const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.status(200).json({ message: 'Login successful', token });
    } catch (error) {
        console.error('Error logging in internal user:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
}

// Merchant Registration Endpoint
async function registerMerchant(req, res) {
    const { company_name, email, password } = req.body;
    try {
        if (!company_name || !email || !password) return res.status(400).json({ message: 'All fields are required' });

        const existingMerchant = await db.query('SELECT * FROM merchants WHERE email = $1', [email]);
        if (existingMerchant.rows.length > 0) return res.status(400).json({ message: 'Email is already registered' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await db.query(
            'INSERT INTO merchants (company_name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, company_name, email',
            [company_name, email, hashedPassword]
        );

        res.status(201).json({ message: 'Merchant registered successfully', merchant: result.rows[0] });
    } catch (error) {
        console.error('Error during merchant registration:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
}

// Internal User Registration Endpoint
async function registerInternalUser(req, res) {
    const { email, password } = req.body;
    try {
        if (!email || !password) return res.status(400).json({ message: 'All fields are required' });

        const existingUser = await db.query('SELECT * FROM users WHERE email = $1 AND role = $2', [email, 'internal']);
        if (existingUser.rows.length > 0) return res.status(400).json({ message: 'Email is already registered' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await db.query(
            'INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3) RETURNING id, email, role',
            [email, hashedPassword, 'internal']
        );

        res.status(201).json({ message: 'Internal user registered successfully', internal_user: result.rows[0] });
    } catch (error) {
        console.error('Error during internal user registration:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
}

// Merchant Verification and Merchant User Creation Endpoint (only for internal users)
async function verifyMerchant(req, res) {
    const { merchant_id } = req.body;
    try {
        const merchantResult = await db.query('SELECT * FROM merchants WHERE id = $1', [merchant_id]);
        if (merchantResult.rows.length === 0) return res.status(400).json({ message: 'Merchant not found' });

        if (merchantResult.rows[0].is_verified) return res.status(400).json({ message: 'Merchant is already verified' });

        await db.query('UPDATE merchants SET is_verified = true WHERE id = $1', [merchant_id]);

        const email = merchantResult.rows[0].email;
        const password = 'merchantPassword123';  // You can generate or set a password
        const hashedPassword = await bcrypt.hash(password, 10);

        const userResult = await db.query(
            'INSERT INTO users (email, password_hash, role, merchant_id) VALUES ($1, $2, $3, $4) RETURNING id, email, role',
            [email, hashedPassword, 'merchant', merchant_id]
        );

        res.status(200).json({ message: 'Merchant verified and merchant user created', merchant_user: userResult.rows[0] });
    } catch (error) {
        console.error('Error verifying merchant:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
}

module.exports = {
    loginMerchant,
    loginInternalUser,
    registerMerchant,
    registerInternalUser,
    verifyMerchant,
};
