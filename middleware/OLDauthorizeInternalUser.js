// middleware/authorizeInternalUser.js
const jwt = require('jsonwebtoken');

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

module.exports = authorizeInternalUser;
