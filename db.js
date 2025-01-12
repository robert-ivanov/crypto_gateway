const { Pool } = require('pg'); // PostgreSQL library
require('dotenv').config(); // Load .env variables

// Create a PostgreSQL connection pool
const pool = new Pool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: 5432, // Default PostgreSQL port
});

// Export a query function to interact with the database
module.exports = {
    query: (text, params) => pool.query(text, params),
};
