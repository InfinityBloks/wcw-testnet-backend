const { Api, JsonRpc, RpcError } = require('enf-eosjs');
const { JsSignatureProvider } = require('enf-eosjs/dist/eosjs-jssig');
const fetch = require('node-fetch');
const { TextEncoder, TextDecoder } = require('util');
const { AbortController } = require("node-abort-controller");
const express = require("express");
const cors = require('cors');
var cookies = require("cookie-parser");
const redis = require('redis');
const rateLimit = require("express-rate-limit");
const RedisStore = require("rate-limit-redis");
const { check, validationResult } = require('express-validator');
const crypto = require('crypto');
const fs = require('fs'), path = require('path'), created_wallets_file = path.join(__dirname, 'created_wallet.txt');
const ecc = require('eosjs-ecc');
const ExpressBrute = require('express-brute');
const BruteRedisStore = require('express-brute-redis');
require('dotenv').config();

const { Pool} = require('pg')
const pool = new Pool({
  application_name: process.env.PGAPPNAME,
  user: process.env.PGUSER,
  host: process.env.PGHOST,
  database: process.env.PGDATABASE,
  password: process.env.PGPASSWORD,
  port: process.env.PGPORT,
  max: 100
});

pool.on('error', (err, client) => {
    console.error('Postgresql - unexpected error on idle client', err);
});

const CHAIN_ID = process.env.CHAIN_ID;
const API_PORT = process.env.API_PORT || 3001;
const WALLET_SUFFIX = process.env.WALLET_SUFFIX;
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN;
const RPC_ENDPOINT = 'https://testnet.wax.pink.gg';
const SESSION_DURATION = Number(process.env.SESSION_DURATION);
const MAX_ACCOUNT_PER_DAY = Number(process.env.MAX_ACCOUNT_PER_DAY);
const FORBIDDEN_ACTIONS = process.env.FORBIDDEN_ACTIONS.split(',');
const HASH_SALT = process.env.HASH_SALT;
const REDIS_CLIENT = redis.createClient();

const executeProc = async (pg_pool, query, values) => {
    let client = null;
    let result = null;
    try{
        client = await pg_pool.connect();
        const queryResult = await client.query(query, values);
        result = queryResult.rows;
    }
    catch(ex){
        console.log(`executeProc ${query} error`, ex);
    }
    finally {
        if(client) client.release();
    }

    return result;
};

const queryAll = async (pg_pool, query, values) => {
    const result = await executeProc(pg_pool, query, values);
    return result || [];
};

const queryFirst = async (pg_pool, query, values) => {
    return (await queryAll(pg_pool, query, values))[0];
};

const rpcFetch = (input, init) => {
    init = init || {};
    if (init.headers === undefined) {
      init.headers = {}
    }

    const controller = new AbortController();
    const promise = fetch(input, { signal: controller.signal, ...init });
    if (init?.signal) init.signal.addEventListener("abort", () => controller.abort());
    const timeout = setTimeout(() => controller.abort(), 10000); //timeout request after 10 seconds
    return promise.finally(() => clearTimeout(timeout));
};

const RPC = new JsonRpc(RPC_ENDPOINT, { fetch: rpcFetch } );
const NEWACCOUNT_API = new Api({
    rpc: RPC,
    signatureProvider: new JsSignatureProvider([process.env.NEWACCOUNT_PRV_KEY]),
    authorityProvider: {
        getRequiredKeys: async (args) => [process.env.NEWACCOUNT_PUB_KEY]
    },
    chainId: CHAIN_ID,
    textDecoder: new TextDecoder(),
    textEncoder: new TextEncoder()
});

const hashString = (str, salt) => {
    return crypto.createHash("sha256")
  .update(str)
  .update(crypto.createHash("sha256").update(salt, "utf8").digest("hex"))
  .digest("hex");
};

const generateRandomString = (length) => {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const charactersLength = characters.length;
    let result = '';
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
};

const generateSessionToken = async (wallet, session_duration) => {
    const key_by_wallet = `wallet_${wallet}`;
    let wallet_token = await REDIS_CLIENT.get(key_by_wallet);
    const is_generate_new = !wallet_token;
    while(!wallet_token && !(await REDIS_CLIENT.exists(`token_${wallet_token}`))) {
        wallet_token = generateRandomString(36);
    }

    if(is_generate_new) { 
        await REDIS_CLIENT.setEx(key_by_wallet, session_duration, wallet_token);
        await REDIS_CLIENT.setEx(`token_${wallet_token}`, session_duration, JSON.stringify({ wallet, token: wallet_token }));
    }

    return wallet_token;
};

const cacheWalletToRedis = async (wallet_info) => {
    //Cache to Redis
    await REDIS_CLIENT.set(`cache_wallet_${wallet_info['wallet']}`, JSON.stringify(wallet_info));
};

const cacheNewWallet = async ({ wallet, password, private_key, public_key }) => {
    const hashed_password = hashString(password, HASH_SALT);
    //Write to DB
    const insertResult = await queryFirst(pool, 'SELECT * FROM Wallet_InsertNewWallet($1, $2, $3, $4)', [wallet, hashed_password, public_key, private_key]);

    await cacheWalletToRedis({ wallet, password: hashed_password, private_key, public_key });
};

const getCachedWallet = async (wallet) => {
    return await REDIS_CLIENT.get(`cache_wallet_${wallet}`);
};


var app = express();

const initRedis = async() => {
    await REDIS_CLIENT.connect();
};

const initApiServer = () => {
    app.use(express.json({
        type: ['application/json', 'text/plain']
    }));
    app.use(cors({origin:true,credentials: true}));
    app.use(cookies());
    //error handler
    app.use((err, req, res, next) => {
        if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
            return res.status(400).send({ msg : "Bad request"});
        }
    
        next();
    });

    app.use(async (req, res, next) => {
        if(req.method == 'GET' || req.method == 'POST') {
            var ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
            if(ip.indexOf(',') != -1) ip = ip.split(',')[0];
            req.headers['x-ip'] = ip;
            next();
        }
        else {
            res.status(405).send({ msg : "Method not allowed"});
        }
    });

    app.listen(API_PORT, () => {
        console.log(`Api server running on port ${API_PORT}`);
    });

    //API Register new wallet
    const registerLimiter = rateLimit({
        windowMs: 24 * 3600 * 1000,
        max: MAX_ACCOUNT_PER_DAY,
        skipFailedRequests: true,
        standardHeaders: true,
        legacyHeaders: false,
        keyGenerator: (req, res) => `r_${req.headers['x-ip']}`,
        message: { msg: 'You have reached the max register wallet for 24 hours' },
        // Redis store configuration
        store: new RedisStore({
            sendCommand: (...args) => REDIS_CLIENT.sendCommand(args),
        }),
        skipFailedRequests: true
    });

    app.use('/v1/wcw/register', registerLimiter);
    
    app.post('/v1/wcw/register',
        check('wallet').custom(async wallet => {
            if(!wallet) throw new Error('Wallet name is required');
            else if(!wallet.endsWith(WALLET_SUFFIX)) throw new Error(`Wallet name must end with ${WALLET_SUFFIX}`);
            else if(!(new RegExp(`^[a-z1-5\.]{1,6}\.${WALLET_SUFFIX}$`, 'g').test(wallet))) throw new Error("Invalid wallet name");
            else if(await getCachedWallet(wallet)) throw new Error('Wallet already exsits');

            return true;
        }),
        check('password').custom(password => {
            if(!password || password.length < 8) throw new Error('The password must be at least 8 characters.');
            else if(password.length >= 64) throw new Error('The password may not be greater than 64 characters.');
            else if(!(new RegExp(`^[a-zA-Z0-9\@]{8,64}\$`, 'g').test(password))) throw new Error("Only letter, numeric characters, @ allow");
            return true;
        })
    , async (req, res) => {
        var err = validationResult(req);
        let error_msg;
        if (err.isEmpty()) {
            const { wallet, password } = req.body;
            // res.json({ msg: "success" });
            try{
                // const trx_result = {};

                //generate key pair
                const private_key = await ecc.randomKey();
                const public_key = ecc.privateToPublic(private_key);    

                const trx_result = await NEWACCOUNT_API.transact({
                    actions: [{
                        authorization: [{ actor: 'newusr.waxtn', permission: 'active' }],
                        account: 'newusr.waxtn',
                        name: 'regaccount',
                        data: { wallet, key: public_key }
                    }]
                }, {
                    blocksBehind: 3,
                    broadcast: true,
                    sign: true,
                    expireSeconds: 240,
                    returnFailureTrace: false
                });

                await cacheNewWallet({wallet, password, private_key, public_key});
                //success => save to database + generate session token
                const session_token = await generateSessionToken(wallet, SESSION_DURATION);
                res.cookie("session_token", session_token, {
                    httpOnly: true,
                    domain: COOKIE_DOMAIN,
                    maxAge: (SESSION_DURATION - 60 /*offset 60 seconds on cookie*/) * 1000
                });
                res.json({ msg: "Success" });
            }
            catch(ex){
                if (typeof (ex) == 'object') {
                    if (ex['json']) {
                        error_msg = ex['json']['error']['details'][0]['message'].replace('assertion failure with message:', '');
                    }
                    else{
                        error_msg = `Error occur: ${ex['isFetchError'] ? 'Fail to fetch' : (ex['message'] || ex.toString())}`;
                    }
                }
                else{
                    error_msg = `Error occur: ${ex.toString()}`;
                }
            }
        } else {
            const mappedError = err.mapped();
            const firstKey = Object.keys(mappedError)[0];
            error_msg = mappedError[firstKey]['msg'];
        }

        if(!error_msg){
            
        }
        else{
            res.status(500).send({ msg: error_msg });
        }
    });

    //API Get wallet info
    app.get('/wam/users', async (req, res) => {
        const session_token = req.headers['x-access-token'];
        if(session_token){
            const token_info = await REDIS_CLIENT.get(`token_${session_token}`);
            if(token_info){
                const { wallet } = JSON.parse(token_info);
                
                const cachedWallet = await getCachedWallet(wallet);
                let wallet_public_key;
                if(cachedWallet){
                    ({public_key: wallet_public_key} = JSON.parse(cachedWallet));
                }
                else{
                    const dbWallet = await queryFirst(pool, 'SELECT * FROM Wallet_GetByName($1)', [wallet + '1']);
                    if(dbWallet){
                        await cacheWalletToRedis(dbWallet);
                        ({public_key: wallet_public_key} = dbWallet);
                    }
                    else{
                        res.status(500).send();
                        return;
                    }
                }

                res.json({
                    verified: true,
                    accountName: wallet,
                    publicKeys: [
                        wallet_public_key,
                        process.env.COSIGN_PUB_KEY
                    ]
                });
                
            }
            else{
                res.status(401).send();
            }      
        }
        else{
            res.status(401).send();
        }
    });

    //API check session
    app.get('/v1/wcw/session', async (req, res) => {
        const {session_token} = (req.cookies || {});
        if(session_token){
            const cached_info = await REDIS_CLIENT.get(`token_${session_token}`);
            if(cached_info){
                res.json(JSON.parse(cached_info));
            }
            else{
                res.cookie('session_token', null, {
                    expires: new Date(0),
                    domain: COOKIE_DOMAIN
                });
                res.status(401).send();
            }            
        }
        else{
            res.status(401).send();
        }
    });

    //API Login
    const loginLimiter = rateLimit({
        windowMs: 1000,
        max: 2,
        skipFailedRequests: true,
        standardHeaders: true,
        legacyHeaders: false,
        keyGenerator: (req, res) => `l_${req.headers['x-ip']}`,
        message: { msg: 'Slow down your action' },
        // Redis store configuration
        store: new RedisStore({
            sendCommand: (...args) => REDIS_CLIENT.sendCommand(args),
        }),
        methods: ['POST']
    });

    app.use('/v1/wcw/session', loginLimiter);

    var loginBruteforce = new ExpressBrute(new BruteRedisStore({
        prefix: 'brf_'
    }), {
        freeRetries: 10,
        minWait: 5 * 60 * 1000,
        maxWait: 60 * 60 * 1000,
        failCallback: (req, res, next, nextValidRequestDate) => {
            res.status(429).send({ msg: 'user temporarily banned' });
        }
    });

    app.post('/v1/wcw/session',
        // loginBruteforce.prevent,
        loginBruteforce.getMiddleware({
            key: function(req, res, next) {
                next((req.body || {}).wallet || req.headers['x-ip']);
            }
        }),
        async (req, res) => {
            const { wallet, password } = req.body;
            const hashed_password = hashString(password || '', HASH_SALT);
            const cached_wallet = await getCachedWallet(wallet);
            let msg = "Success";
            let statusCode = 200;
            if (cached_wallet){
                const { password: cached_password } = JSON.parse(cached_wallet);
                if(cached_password == hashed_password) {
                    const session_token = await generateSessionToken(wallet, SESSION_DURATION);
                    res.cookie("session_token", session_token, {
                        httpOnly: true,
                        domain: COOKIE_DOMAIN,
                        maxAge: (SESSION_DURATION - 60 /*offset 60 seconds on cookie*/) * 1000
                    });
                }
                else{
                    msg = "Incorrect password";
                    statusCode = 401;
                }
            }
            else{
                //validate from DB
                const validateResult = await queryFirst(pool, 'SELECT * FROM Wallet_ValidateWallet($1, $2)', [wallet, hashed_password]);
                if(validateResult) {
                    if(validateResult['id'] > 0){
                        //Update Wallet Redis Cache
                        await cacheWalletToRedis(validateResult['wallet_info']);

                        const session_token = await generateSessionToken(wallet, SESSION_DURATION);
                        res.cookie("session_token", session_token, {
                            httpOnly: true,
                            domain: COOKIE_DOMAIN,
                            maxAge: (SESSION_DURATION - 60 /*offset 60 seconds on cookie*/) * 1000
                        });
                    }
                    else{
                        msg = validateResult['message'];
                        switch(validateResult['id']){
                            case -1:
                                statusCode = 404;
                                break;
                            case -2:
                                statusCode = 401;
                                break;
                            default:
                                statusCode = 500;
                        }
                    }
                }
                else{
                    msg = "Error occur. Please try again later.";
                    statusCode = 500;
                }
            }
            if(statusCode != 200) res.status(statusCode).send({ msg });
            else req.brute.reset(() => { res.status(statusCode).send({ msg }) });
    });

    //API sign transaction
    app.post('/wam/sign', async (req, res) => {
        const token = req.headers['x-access-token'];
        let errMsg = '';
        let errCode = '';
        let api;
        let transaction;
        if(token){
            const token_info = await REDIS_CLIENT.get(`token_${token}`);
            if(!token_info){
                errMsg = 'Authorization Required';
                errCode = 'AuthenticationError';
            }
            else{
                try {
                    let { trx } = req.body;
                    if(typeof(trx.serializedTransaction) == 'object'){
                        trx.serializedTransaction = Object.keys(trx.serializedTransaction).map(x => trx.serializedTransaction[x]);
                    }

                    const { wallet } = JSON.parse(token_info);
    
                    const cachedWallet = await getCachedWallet(wallet);
                    let wallet_private_key, wallet_public_key;
                    if(cachedWallet){
                        console.log('get wallet from cache');
                        ({private_key: wallet_private_key, public_key: wallet_public_key} = JSON.parse(cachedWallet));
                    }
                    else{
                        console.log('get wallet from db');
                        const dbWallet = await queryFirst(pool, 'SELECT * FROM Wallet_GetByName($1)', [wallet]);
                        if(dbWallet){
                            await cacheWalletToRedis(dbWallet);
                            ({private_key: wallet_private_key, public_key: wallet_public_key} = dbWallet);
                        }
                        else{
                            errMsg = 'Wallet not found';
                            errCode = 'NotFoundError';
                        }
                    }

                    if(!errMsg) {
                        api = new Api({
                            rpc: RPC,
                            signatureProvider: new JsSignatureProvider([process.env.COSIGN_PRV_KEY, wallet_private_key]),
                            authorityProvider: {
                                getRequiredKeys: async (args) => [process.env.COSIGN_PUB_KEY, wallet_public_key]
                            },
                            chainId: CHAIN_ID,
                            textDecoder: new TextDecoder(),
                            textEncoder: new TextEncoder()
                        });

                        transaction = await api.deserializeTransactionWithActions(trx.serializedTransaction);
                        //check forbidden actions
                        if(transaction['delay_sec'] > 0) {
                            errMsg = 'not allow delay_sec greater than 0';
                            errCode = 'InvalidParameterError';
                        }
                        else if(transaction.actions.some(x => FORBIDDEN_ACTIONS.indexOf(`${x['account']}::${x['name']}`) != -1)){
                            errMsg = 'This transaction contains forbidden actions';
                            errCode = 'ForbiddenTransactionException';
                        }
                    }
                }
                catch(ex){
                    console.log('ex', ex);
                    errMsg = 'Fail to deserialize transaction';
                    errCode = 'InvalidParameterError';
                }
            }
        }
        else{
            errMsg = 'Authorization Required';
            errCode = 'AuthenticationError';
        }

        if(!errMsg) {
            try{
                const signResult = await api.transact(transaction, {
                    broadcast: false,
                    sign: true
                });

                return res.json({
                    signatures: signResult['signatures'],
                    serializedTransaction: Array.from(signResult['serializedTransaction']),
                    estimatorWorking: false
                });

            }
            catch(ex){
                console.log('sign ex', ex);
                return res.json({ error: "FailToFetch", message: "Fail to fetch" });
            }
        }
        else{
            return res.json({ error: errCode, message: errMsg });
        }
    });

    app.post('/v1/wcw/logout', async (req, res) => {
        const {session_token} = (req.cookies || {});
        if(session_token){
            const cached_info = await REDIS_CLIENT.get(`token_${session_token}`);
            if(cached_info){
                res.cookie('session_token', null, {
                    expires: new Date(0),
                    domain: COOKIE_DOMAIN
                });
            }      
            res.status(200).send();   
        }
        else{
            res.status(404).send();
        }
    });

    const notFoundHandler = (req, res) => {
        res.status(404).send({ msg : "Not found"});
    };

    app.get('*', notFoundHandler);

    app.post('*', notFoundHandler);
};

const init = async () => {
    await initRedis();

    //WALLET CACHE INVALIDATION
    const MATCH_CACHED_KEYS = await REDIS_CLIENT.keys("cache_wallet_*");
    const CACHED_WALLETS = MATCH_CACHED_KEYS.map(x => x.replace('cache_wallet_', ''));
    const cacheInvalidationWallet = await queryAll(pool, 'SELECT * FROM Wallet_GetCacheInvalidateWallet($1)', [CACHED_WALLETS]);
    if(cacheInvalidationWallet && cacheInvalidationWallet.length > 0){
        cacheInvalidationWallet.forEach(wallet => {
            cacheWalletToRedis(wallet);
        });
    }

    initApiServer();
};

init();