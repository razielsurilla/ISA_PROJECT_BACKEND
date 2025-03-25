// Imports
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const express = require('express')
const MongoDBService = require('./MongoDBService.js');
const mongoose = require('mongoose');
// const User = require('./User.js')

const cookieParser = require('cookie-parser');
const salt = bcrypt.genSaltSync(10);
const hash = bcrypt.hashSync("B4c0/\/", salt);


/**
 * User Class 
 */
class User {
    constructor(mongoDBService) {
        this.mongoDBService = mongoDBService;
        this.mongoDBService.createSchema('user', {
            username : {type : String, require : true},
            email : {type : String, required : true},
            password : {type : String, required: true},
            admin: {type: Boolean, default: false},
            apiRequestsLeft: { type: Number, default: 20 }  // Track API request usage
            // Should add token. 
        });
    }

    async createUser(username, email, password) {
        try {
            const UserSchema = this.mongoDBService.getSchema('user');
            const encryptedPassword = UserRegistration.encrypt(password);
            const newUser = new UserSchema({username, email, password: encryptedPassword});
            await newUser.save();
            return newUser;
        } catch (error) {
            throw error;
        }
    }

    async getUser(email) {
        try {
            const UserSchema = this.mongoDBService.getSchema('user');
            const user = await UserSchema.findOne({email});
            return user;
        } 
        catch(error) {
            throw error;
        }
    } 
}

/**
 * Used in User registration for encrypting maybe needs to be revised
 */
class UserRegistration {
    static saltRounds = 12;

    static encrypt(password, saltRounds = UserRegistration.saltRounds) {
        return bcrypt.hashSync(password, saltRounds);
    }
}

/**
 * Mongo API service for communication between front and back
 */
class MongoAPIService {
    /**
     * Constructor for the MongoAPIService class
     * @param {number} port - The port number to listen on
     */
    constructor(port) {
        this.mongoDBService = new MongoDBService();
        this.userService = new User(this.mongoDBService);
        this.app = express();
        this.port = process.env.PORT || port;

        this.app.use(express.json());
        this.app.use(express.urlencoded({ extended: true }));
    }

    // /**
    //  * Defines the routes for the API
    //  * @returns {void}
    //  */
    // defineRoutes() {
    //     this.app.post('/createUser', (req, res) => this.createUser(req, res));
    //     this.app.post('/checkUser', (req, res) => this.checkUser(req, res));
    //     this.app.get('/getUser', (req, res) => this.getUser(req, res));

    //     this.app.get('/authenticate', (req, res) => this.authenticate(req, res)); 

    //     this.app.delete('/deleteUser', (req, res) => {})

    //     // handle prefligts?
    //     this.app.options('*', cors({
    //         origin: 'https://triviaproto.netlify.app', 
    //         credentials: true,
    //         methods: ['GET','HEAD','PUT','PATCH','POST','DELETE','OPTIONS'],
    //         allowedHeaders: ['Content-Type', 'Authorization']
    //     }));
    // }

    defineRoutes() {
        // Middleware executes in order, so this must come before routes it protects
        this.app.use(async (req, res, next) => {
            if (req.method === 'OPTIONS') return next(); // Skip preflight requests
            
            // Skip auth for these public routes
            if (req.path === '/createUser' || req.path === '/checkUser') {
                return next();
            }
    
            try {
                const token = req.cookies.userCookie;
                if (!token) {
                    return res.status(401).json({ message: 'Unauthorized - No token provided' });
                }
    
                // NOTE: In production, replace 'your_jwt_secret_key' with process.env.JWT_SECRET
                const decoded = jwt.verify(token, 'your_jwt_secret_key');
                const UserSchema = this.userService.mongoDBService.getSchema('user');
                const user = await UserSchema.findById(decoded.userId);
    
                if (!user) return res.status(404).json({ message: 'User not found' });
    
                // API Limit Check
                if (user.apiRequestsLeft <= 0) {
                    return res.status(429).json({ 
                        message: 'API limit reached',
                        detail: 'You have used all 20 API requests'
                    });
                }
    
                // Decrement counter
                user.apiRequestsLeft -= 1;
                await user.save();
    
                // Add remaining count to headers for frontend
                res.set('X-API-Requests-Remaining', user.apiRequestsLeft);
                next();
            } catch (error) {
                // Better error differentiation
                if (error.name === 'JsonWebTokenError') {
                    return res.status(401).json({ message: 'Invalid token' });
                }
                console.error('API Tracking Error:', error);
                res.status(500).json({ message: 'Server error tracking API usage' });
            }
        });
    
        // 2. Routes - NOW PROTECTED BY MIDDLEWARE
        this.app.post('/createUser', (req, res) => this.createUser(req, res));
        this.app.post('/checkUser', (req, res) => this.checkUser(req, res));
        this.app.get('/getUser', (req, res) => this.getUser(req, res));
        this.app.get('/authenticate', (req, res) => this.authenticate(req, res));
        this.app.delete('/deleteUser', (req, res) => {}) // added back
        
        // 3. Admin Reset Endpoint
        this.app.post('/resetApiRequests', async (req, res) => {
            try {
                const token = req.cookies.userCookie;
                // NOTE: Should use process.env.JWT_SECRET in production
                const decoded = jwt.verify(token, 'your_jwt_secret_key');
                
                const UserSchema = this.userService.mongoDBService.getSchema('user');
                const adminUser = await UserSchema.findById(decoded.userId);
                
                // Admin check
                if (!adminUser || !adminUser.admin) {
                    return res.status(403).json({ message: 'Admin access required' });
                }
    
                const { email } = req.body;
                const user = await UserSchema.findOne({ email });
                if (!user) return res.status(404).json({ message: 'User not found' });
    
                // Reset logic
                user.apiRequestsLeft = 20;
                await user.save();
    
                res.status(200).json({ 
                    message: 'API requests reset to 20',
                    user: user.email,
                    requestsLeft: user.apiRequestsLeft
                });
            } catch (error) {
                console.error('Reset Error:', error);
                res.status(500).json({ message: 'Error resetting API requests' });
            }
        });
    }


    /**
     * Starts express server
     * Defines API routes
     */
    async start() {
        try {
            if (this.connection) {
                return this.connection;
            }
            this.connection = await this.mongoDBService.connect();
        } catch (error) {
            console.error('Error connecting to MongoDB:', error);
            throw new Error('Database connection failed');
        }

        // this.app.use(cors({
        //     origin: 'https://triviaproto.netlify.app', // frontend
        //     // origin: 'http://localhost:3000', // frontend
        //     // origin: '127.0.0.1', // frontend
        //     credentials: true,
        //     methods: ['GET','HEAD','PUT','PATCH','POST','DELETE','OPTIONS'], //allows the handling of pre-flights
        //     allowedHeaders: ['Content-Type', 'Authorization']
        // })); 
        this.app.use(cors({
            origin: ['https://triviaproto.netlify.app', 'http://localhost:3000'], // Allow both
            credentials: true,
            methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
            allowedHeaders: ['Content-Type', 'Authorization']
        }));
        this.app.use(cookieParser())
        this.defineRoutes(); 

        this.app.listen(this.port, () => {
            console.log(`Listening on port ${this.port}`)
        });
    }

    /**
     * Authenticates the user by verifying the cookie credentials
     * 
     * @param {object} req express request object 
     * @param {object} res express response object
     * @returns {Promise<void>} - A promise that resolves after authentication.
     */
    authenticate(req, res) {
        console.log("Authenticating user")
        const token = req.cookies.userCookie; //Uses cookieParser
        
        if (!token) {
            console.log("No token provided")
            return res.status(401).json({ authenticated: false, message: 'No token provided' });
        }

        jwt.verify(token, 'your_jwt_secret_key', (err, decoded) => {
            if (err) {
                console.log("Error verifying token: ", err)
                return res.status(403).json({ authenticated: false, message: 'Invalid token' });
            }
            // Token is valid
            console.log("Token is valid")
            res.status(200).json({ message : 'user authenticated',  authenticated: true, user: decoded }); //send the user data back.
        });
    }

    /**
     * Creates a user and adds it onto the database
     * 
     * @param {object} req An express request object
     * @param {object} res An express response object
     * @returns {Promise<void>} - A promise that resolves after user has been added to database
     */
    async createUser(req, res) {
        try {
            const userCollection = this.userService.mongoDBService.getSchema('user');
            
            const existingUser = await userCollection.findOne({ email: req.body.email });
            if (existingUser) {
                res.status(400).json({ message: 'User already exists' });
                return;
            }
            
            const result = await this.userService.createUser(req.body.username, req.body.email, req.body.password);
            res.status(201).json({ message: 'User Created Successfully', userId: result._id });
        } catch (error) {
            res.status(500).json({ message: 'Error creating user: ' + error.message });
        }        
    }    
    
    /**
     * Verifys credentials and issuing a JWT cookie.
     * 
     * @param {object} req - The Express request object.
     * @param {object} res - The Express response object.
     * @returns {Promise<void>} - A promise that resolves after authentication.
     */
    async checkUser(req, res) {
        try {
            const userCollection = this.userService.mongoDBService.getSchema('user'); 
            const user = await userCollection.findOne({ email: req.body.email });
            if (!user) {
                res.status(404).json({ message: 'User not found' }); //user doesnt exist
                return;
            }

            //validataes the password
            const isPasswordValid = bcrypt.compareSync(req.body.password, user.password); 
            if (!isPasswordValid) {
                res.status(401).json({ message: 'Invalid password' });
                return;
            }

            //Creates a signed token by jwt, and attach it to httpCookie
            const token = jwt.sign({ userId: user._id, email: user.email }, 'your_jwt_secret_key', { expiresIn: '1h' });
            res.cookie('userCookie', token, 
                {
                    httpOnly: true, 
                    secure : true, 
                    // secure: false, 
                    sameSite: 'lax', 
                    // domain : 'triviaproto.netlify.app', 
                    maxAge: 3600000 //1hr ms  -> make these a session cookie
                });

            res.status(200).json({ message: 'Login successful', admin: user.admin, username: user.username});
        } catch (error) {
            res.status(500).json({ message: 'Error logging in: ' + error.message });
        }
    }

    /**
     * Retrieves a user from the database by email and sends the user data as JSON.
     *
     * @param {object} req - The Express request object containing the user's email in the request body.
     * @param {object} res - The Express response object used to send the user data or an error message.
     * @returns {Promise<void>} - A promise that resolves after sending the response.
     */
    async getUser(req, res) {
        try {
            const result = await this.userService.getUser(req.body.email)
            if (result) {
                result.password = undefined;
            }
            res.status(200).json({message : 'User retrieved successfully', user : result})
        } catch (error) {
            res.status(500).json({ message: 'Error retrieving user: ' + error.message });
        }
    }
}

// Start the API
const apiService = new MongoAPIService(3000);
apiService.start();
