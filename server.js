const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const db = require('./db');
const { authorizeInternalUser, authorizeMerchantUser } = require('./middleware/authorization');
const { loginMerchant, loginInternalUser, registerMerchant, registerInternalUser, verifyMerchant } = require('./controllers/authController');
const { generateApiKeyAndWallet, addMiddleWallet } = require('./controllers/walletController');
const app = express();

app.use(cors());
app.use(bodyParser.json());

const PORT = process.env.PORT || 3000;

// Routes
app.post('/api/login-merchant', loginMerchant);
app.post('/api/login-internal', loginInternalUser);
app.post('/api/register', registerMerchant);
app.post('/api/register-internal-user', registerInternalUser);
app.post('/api/verify-merchant', authorizeInternalUser, verifyMerchant);
app.post('/api/generate-api-key-wallet', authorizeMerchantUser, generateApiKeyAndWallet);
app.post('/api/add-middle-wallet', authorizeMerchantUser, addMiddleWallet);

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
