// Imports
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const express = require('express')
const MongoDBService = require('./MongoDBService.js');
const mongoose = require('mongoose');
const QuestionService = require('./QuestionService.js');

// const User = require('./User.js')
const cookieParser = require('cookie-parser');
const salt = bcrypt.genSaltSync(10);
const hash = bcrypt.hashSync("B4c0/\/", salt);

//Swagger api documentation
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');


/**
 * API Statistics Class to track endpoint usage
 */
class ApiStats {
    constructor(mongoDBService) {
        this.mongoDBService = mongoDBService;
        this.mongoDBService.createSchema('apiStats', {
            method: { type: String, required: true },
            endpoint: { type: String, required: true },
            requests: { type: Number, default: 0 },
            lastAccessed: { type: Date, default: Date.now }
        });
    }

    async recordRequest(method, path) {
        try {
            // Normalize the endpoint (remove IDs for /getQuestion/:id, etc.)
            let endpoint = path;
            if (path.startsWith('/getQuestion/')) {
                endpoint = '/getQuestion/';
            } else if (path.startsWith('/deleteQuestion/')) {
                endpoint = '/deleteQuestion/';
            }
            // /updateQuestion and /createQuestion don't need normalization

            const ApiStatsSchema = this.mongoDBService.getSchema('apiStats');
            const stats = await ApiStatsSchema.findOneAndUpdate(
                { method, endpoint },
                { 
                    $inc: { requests: 1 },
                    $set: { lastAccessed: Date.now() }
                },
                { upsert: true, new: true }
            );
            return stats;
        } catch (error) {
            console.error('Error recording API stats:', error);
            throw error;
        }
    }

    async getStats() {
        try {
            const ApiStatsSchema = this.mongoDBService.getSchema('apiStats');
            const stats = await ApiStatsSchema.find().sort({ requests: -1 });
            return stats;
        } catch (error) {
            console.error('Error getting API stats:', error);
            throw error;
        }
    }
}

/**
 * API Usage Class to track API requests
 */
class ApiUsage {
    constructor(mongoDBService) {
        this.mongoDBService = mongoDBService;
        this.mongoDBService.createSchema('apiUsage', {
            userId: { type: mongoose.Schema.Types.ObjectId, ref: 'user', required: true },
            requestsLeft: { type: Number, default: 20 },
            totalRequests: { type: Number, default: 0 },
            lastReset: { type: Date, default: Date.now }
        });
    }

    async getUsage(userId) {
        try {
            const ApiUsageSchema = this.mongoDBService.getSchema('apiUsage');
            let usage = await ApiUsageSchema.findOne({ userId });
            
            if (!usage) {
                usage = new ApiUsageSchema({ userId });
                await usage.save();
            }
            
            return usage;
        } catch (error) {
            throw error;
        }
    }

    async decrementRequests(userId) {
        try {
            const ApiUsageSchema = this.mongoDBService.getSchema('apiUsage');
            const usage = await ApiUsageSchema.findOneAndUpdate(
                { userId },
                { 
                    $inc: { 
                        requestsLeft: -1,
                        totalRequests: 1 
                    } 
                },
                { new: true, upsert: true }
            );
            return usage;
        } catch (error) {
            throw error;
        }
    }

    async resetRequests(userId) {
        try {
            const ApiUsageSchema = this.mongoDBService.getSchema('apiUsage');
            const usage = await ApiUsageSchema.findOneAndUpdate(
                { userId },
                { 
                    requestsLeft: 20,
                    lastReset: Date.now()
                },
                { new: true, upsert: true }
            );
            return usage;
        } catch (error) {
            throw error;
        }
    }
}

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
        //Services
        this.mongoDBService = new MongoDBService();
        this.userService = new User(this.mongoDBService);
        this.questionService = new QuestionService(this.mongoDBService);
        this.apiUsageService = new ApiUsage(this.mongoDBService); // Add this line
        this.apiStatsService = new ApiStats(this.mongoDBService); // Add this line

        // Server
        this.app = express();
        this.port = process.env.PORT || port;
        this.app.use(express.json());
        this.app.use(express.urlencoded({ extended: true }));
    }

    /**
     * Defines the routes for the API
     * @returns {void}
     */
    defineRoutes() {
        // handle prefligts?
        this.app.options('*', cors({
            origin: [ 'https://triviaproto.netlify.app', 'http:localhost:5500','https://isa-project-frontend-yvfn.onrender.com'], 
            credentials: true,
            methods: ['GET','HEAD','PUT','PATCH','POST','DELETE','OPTIONS'],
            allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
        }));


        // Swagger setup
        const options = {
            definition: {
                openapi: '3.0.0',
                info: {
                    title: 'TriviaProto API',
                    version: '1.0.0',
                    description: 'A simple API for Trivia questions that are converted into TTS using HexGrads Kokoro Hugging face model',
                },
                servers: [
                    {
                        url: `https://isa-project-backend-ultkx.ondigitalocean.app`, // Important: Use your server's port
                    },
                ],
                components: {
                    securitySchemes: {
                        cookieAuth: {
                            type: 'apiKey',
                            in: 'cookie',
                            name: 'userCookie',
                        },
                    },
                },
                security: [{ cookieAuth: [] }],
            },
            apis: ['./MongoAPIService.js'], // Path to the API docs
        };

        const specs = swaggerJsdoc(options);
        this.app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs));

        // Middleware executes in order, so this must come before routes it protects
        this.app.use((req, res, next) => this.apiUsageMiddleware(req, res, next));
        this.app.use((req, res, next) => this.apiStatsMiddleware(req, res, next));
        
        // Add this with your other routes
        this.app.get('/getApiStats', (req, res) => this.getApiStats(req, res));

        // User Service
        this.app.post('/createUser', (req, res) => this.createUser(req, res));
        this.app.post('/checkUser', (req, res) => this.checkUser(req, res));
        this.app.post('/logout', (req, res) => this.logout(req, res));
        this.app.get('/getUser', (req, res) => this.getUser(req, res));
        this.app.get('/getAllUsers', (req, res) => this.getAllUsers(req, res)); 
        this.app.get('/authenticate', (req, res) => this.authenticate(req, res)); 
        this.app.get('/getApiRequests', (req, res) => this.getApiRequests(req, res));
        this.app.delete('/deleteUser/:id', (req, res) => this.deleteUser(req, res));
        this.app.get('/getApiRequests', (req, res) => this.getApiRequests(req, res));


        // Question Service
        /**
         * @swagger
         * /createQuestion:
         *   post:
         *     summary: Creates a new question
         *     security:
         *       - cookieAuth: []
         *     requestBody:
         *       required: true
         *       content:
         *         application/json:
         *           schema:
         *             type: object
         *             properties:
         *               category:
         *                 type: string
         *               question:
         *                 type: string
         *               answer:
         *                 type: string
         *     responses:
         *       201:
         *         description: Question created successfully
         *       500:
         *         description: Error creating question
         */
        this.app.post('/createQuestion', (req, res) => {
            this.questionService.createQuestion(req, res);
        });

        /**
         * @swagger
         * /updateQuestion:
         *   put:
         *     summary: Updates a question
         *     security:
         *       - cookieAuth: []
         *     requestBody:
         *       required: true
         *       content:
         *         application/json:
         *           schema:
         *             type: object
         *             properties:
         *               id:
         *                 type: string
         *               category:
         *                 type: string
         *               question:
         *                 type: string
         *               answer:
         *                 type: string
         *     responses:
         *       200:
         *         description: Question updated successfully
         *       400:
         *         description: Invalid question ID format or no fields provided
         *       404:
         *         description: Question not found
         *       500:
         *         description: Internal server error
         */
        this.app.put('/updateQuestion', (req, res) => {
            this.questionService.updateQuestion(req, res);
        });

        /**
         * @swagger
         * /getQuestion/{id}:
         *   get:
         *     summary: Retrieves a question by ID
         *     security:
         *       - cookieAuth: []
         *     parameters:
         *       - in: path
         *         name: id
         *         required: true
         *         schema:
         *           type: string
         *     responses:
         *       200:
         *         description: Question retrieved successfully
         *       404:
         *         description: Question not found
         *       422:
         *         description: Improper ID length
         *       500:
         *         description: Internal server error
         */
        this.app.get('/getQuestion/:id', (req, res) => {
            this.questionService.getQuestion(req, res);
        });

        /**
         * @swagger
         * /deleteQuestion/{id}:
         *   delete:
         *     summary: Deletes a question by ID
         *     security:
         *       - cookieAuth: []
         *     parameters:
         *       - in: path
         *         name: id
         *         required: true
         *         schema:
         *           type: string
         *     responses:
         *       200:
         *         description: Question deleted successfully
         *       404:
         *         description: Question not found
         *       422:
         *         description: Improper ID length
         *       500:
         *         description: Internal server error
         */
        this.app.delete('/deleteQuestion/:id', (req, res) => {
            this.questionService.deleteQuestion(req, res);
        });

        
        // Admin Reset Endpoint
        this.app.post('/resetApiRequests', (req, res) => {this.resetApiRequests(req, res)});
    }

    async apiStatsMiddleware(req, res, next) {
        try {
            // Only track these question-related endpoints
            const trackedEndpoints = [
                '/getQuestion',
                '/deleteQuestion',
                '/updateQuestion',
                '/createQuestion'
            ];
            
            // Check if the request path starts with any of our tracked endpoints
            const shouldTrack = trackedEndpoints.some(endpoint => 
                req.path.startsWith(endpoint)
            );
            
            if (!shouldTrack) {
                return next();
            }
    
            await this.apiStatsService.recordRequest(req.method, req.path);
            next();
        } catch (error) {
            console.error('API stats middleware error:', error);
            next(); // Don't block the request if stats tracking fails
        }
    }

    async apiUsageMiddleware(req, res, next) {
        if (req.method === 'OPTIONS') return next();
        
        // Only track these question-related endpoints
        const trackedEndpoints = [
            '/getQuestion',
            '/deleteQuestion',
            '/updateQuestion',
            '/createQuestion'
        ];
        
        // Check if the request path starts with any of our tracked endpoints
        const shouldTrack = trackedEndpoints.some(endpoint => 
            req.path.startsWith(endpoint)
        );
        
        if (!shouldTrack) {
            return next();
        }
    
        try {
            const token = req.headers.cookie?.split("=")[1];
            if (!token) { 
                return res.status(401).json({ message: 'Unauthorized - No token provided' });
            }
            
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            const usage = await this.apiUsageService.getUsage(decoded.id);
    
            // API Limit Check
            if (usage.requestsLeft <= 0) {
                return res.status(429).json({ 
                    message: 'API limit reached',
                    detail: 'You have used all 20 API requests'
                });
            }
    
            // Decrement counter
            const updatedUsage = await this.apiUsageService.decrementRequests(decoded.id);
            
            // Add remaining count to headers for frontend
            res.set('X-API-Requests-Remaining', updatedUsage.requestsLeft);
            next();
        } catch (error) {
            if (error.name === 'JsonWebTokenError') {
                return res.status(401).json({ message: 'Invalid token' });
            }
            res.status(500).json({ message: 'Server error tracking API usage' });
        }
    }

    async getApiStats(req, res) {
        try {
            const token = req.headers.cookie?.split("=")[1];
            if (!token) {
                return res.status(401).json({ message: 'Unauthorized' });
            }
    
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            const UserSchema = this.userService.mongoDBService.getSchema('user');
            const user = await UserSchema.findById(decoded.id);
            
            if (!user || !user.admin) {
                return res.status(403).json({ message: 'Admin access required' });
            }
    
            const stats = await this.apiStatsService.getStats();
            res.status(200).json(stats);
        } catch (error) {
            console.error('Error getting API stats:', error);
            res.status(500).json({ message: 'Error getting API statistics' });
        }
    }

    // Update the resetApiRequests method
    async resetApiRequests(req, res) {
        try {
            const token = req.headers.cookie?.split("=")[1];
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            
            const UserSchema = this.userService.mongoDBService.getSchema('user');
            const adminUser = await UserSchema.findById(decoded.id);
            
            if (!adminUser || !adminUser.admin) {
                return res.status(403).json({ message: 'Admin access required' });
            }

            const { email } = req.body;
            const user = await UserSchema.findOne({ email });
            if (!user) return res.status(404).json({ message: 'User not found' });

            // Reset logic using ApiUsage
            const usage = await this.apiUsageService.resetRequests(user._id);

            res.status(200).json({ 
                message: 'API requests reset to 20',
                user: user.email,
                requestsLeft: usage.requestsLeft,
                totalRequests: usage.totalRequests
            });
        } catch (error) {
            res.status(500).json({ message: 'Error resetting API requests' });
        }
    }

    // Add a new endpoint to get API usage stats
    async getApiRequests(req, res) {
        try {
            const token = req.headers.cookie?.split("=")[1];
            if (!token) {
                return res.status(401).json({ message: 'Unauthorized' });
            }

            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            const usage = await this.apiUsageService.getUsage(decoded.id);

            res.status(200).json({ 
                requestsLeft: usage.requestsLeft,
                totalRequests: usage.totalRequests,
                lastReset: usage.lastReset
            });
        } catch (error) {
            res.status(500).json({ message: 'Error getting API usage' });
        }
    }


    /**
     * Starts express server
     * Defines API routes
     */
    async start(req ,res, next) {
        try {
            if (this.connection) {
                return this.connection;
            }
            this.connection = await this.mongoDBService.connect();
        } catch (error) {
            console.error('Error connecting to MongoDB:', error);
            throw new Error('Database connection failed');
        }

        this.app.use(cors({
            origin: [
                'https://triviaproto.netlify.app', 
                'http://localhost:5500', 
                'https://isa-project-frontend-yvfn.onrender.com',
                'http://127.0.0.1:5500'
            ], // Allow all production and testing url
            credentials: true,
            methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
            allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
        }));

        this.defineRoutes(); 

        this.app.listen(this.port, () => {
            // console.log(`Listening on port ${this.port}`)
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
        const token = req.headers.cookie?.split("=")[1]; //parse the cookie ourselves

        if (!token) {   
            return res.status(401).json({ message: 'No token provided' });
        }

        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            res.status(200).json({ id: decoded.id, email: decoded.email, username: decoded.username});
        } catch {
            res.status(401).json({ message: "Invalid token" });
        }
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
                return res.status(400).json({ message: 'User already exists' });
            }
            
            const result = await this.userService.createUser(req.body.username, req.body.email, req.body.password);
            res.status(201).json({ message: 'User Created Successfully' });
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
                return res.status(404).json({ message: 'User not found' }); //user doesnt exist
            }

            //validataes the password
            const isPasswordValid = bcrypt.compareSync(req.body.password, user.password); 
            if (!isPasswordValid) {
                return res.status(401).json({ message: 'Invalid password' });
            }

            // Creates a signed token by jwt, and attach it to httpCookie
            const token = jwt.sign(
                { username: user.username, email: user.email, id: user._id }, 
                process.env.JWT_SECRET, 
                { expiresIn: '1h' }
            );

            res.writeHead(200, {
                "Set-Cookie": `userCookie=${token}; HttpOnly; Secure; SameSite=None; Path=/;`, //removed secure, path, sameSite
                "Content-Type": "application/json",
            });
            res.end(JSON.stringify({ message: "Logged in successfully" }));
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
    // Update the getUser method to include API usage
    async getUser(req, res) {
        try {
            const token = req.headers.cookie?.split('=')[1];
            if (!token) { 
                return res.status(401).json({ message: 'Unauthorized - No token provided' });
            }
    
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            const UserSchema = this.userService.mongoDBService.getSchema('user');
            const user = await UserSchema.findById(decoded.id);
            const usage = await this.apiUsageService.getUsage(decoded.id);
    
            if (!user) {
                return res.status(404).json({ message: 'User not found' });
            }
    
            const userData = {
                id: user._id,
                username: user.username,
                email: user.email,
                admin: user.admin,
                apiUsage: {
                    requestsLeft: usage.requestsLeft,
                    totalRequests: usage.totalRequests,
                    lastReset: usage.lastReset
                }
            };
            
            return res.status(200).json({ 
                user: userData,
                message: 'User data retrieved successfully'
            });
    
        } catch (error) {
            if (error instanceof jwt.JsonWebTokenError) {
                return res.status(401).json({ message: 'Invalid token' });
            }
            return res.status(500).json({ message: 'Server error retrieving user data' });
        }
    }

    async getAllUsers(req, res) {
        try {
            const token = req.headers.cookie?.split("=")[1];
            if (!token) {
                return res.status(401).json({ message: 'Unauthorized' });
            }
    
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            const UserSchema = this.userService.mongoDBService.getSchema('user');
            const ApiUsageSchema = this.mongoDBService.getSchema('apiUsage');
            
            // Verify requesting user is admin
            const adminUser = await UserSchema.findById(decoded.id);
            if (!adminUser || !adminUser.admin) {
                return res.status(403).json({ message: 'Admin access required' });
            }
    
            // Pagination parameters
            const page = parseInt(req.query.page) || 1;
            const limit = parseInt(req.query.limit) || 20;
            const skip = (page - 1) * limit;
    
            // Get paginated users (excluding passwords) and their API usage
            const [users, totalCount] = await Promise.all([
                UserSchema.aggregate([
                    { $match: {} },
                    { $skip: skip },
                    { $limit: limit },
                    { $project: { password: 0 } },
                    {
                        $lookup: {
                            from: 'apiusages', // This should match your MongoDB collection name for apiUsage
                            localField: '_id',
                            foreignField: 'userId',
                            as: 'apiUsage'
                        }
                    },
                    {
                        $addFields: {
                            apiUsage: { $arrayElemAt: ['$apiUsage', 0] }
                        }
                    },
                    {
                        $project: {
                            username: 1,
                            email: 1,
                            admin: 1,
                            createdAt: 1,
                            updatedAt: 1,
                            requestsLeft: { $ifNull: ['$apiUsage.requestsLeft', 0] },
                            totalRequests: { $ifNull: ['$apiUsage.totalRequests', 0] },
                            lastReset: { $ifNull: ['$apiUsage.lastReset', new Date(0)] }
                        }
                    }
                ]),
                UserSchema.countDocuments({})
            ]);
    
            res.status(200).json({ 
                users,
                totalCount,
                currentPage: page,
                totalPages: Math.ceil(totalCount / limit)
            });
            
        } catch (error) {
            console.error('Error fetching users:', error);
            res.status(500).json({ message: 'Error fetching users' });
        }
    }

    /**
     * Logs out the user by clearing the authentication cookie
     * 
     * @param {object} req - The Express request object
     * @param {object} res - The Express response object
     * @returns {Promise<void>} - A promise that resolves after logging out
     */
    async logout(req, res) {
        try {
            // Clear the cookie by setting an expired cookie with same name
            res.writeHead(200, {
                "Set-Cookie": `userCookie=; HttpOnly; Secure; SameSite=None; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT;`,
                "Content-Type": "application/json",
            });
            
            res.end(JSON.stringify({ message: "Logged out successfully" }));
        } catch (error) {
            console.error('Logout error:', error);
            res.status(500).json({ message: 'Error logging out' });
        }
    }

    async deleteUser(req, res) {
        try {
            const token = req.headers.cookie?.split("=")[1];
            if (!token) {
                return res.status(401).json({ message: 'Unauthorized' });
            }
    
            // Verify requesting user is admin
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            const UserSchema = this.userService.mongoDBService.getSchema('user');
            const adminUser = await UserSchema.findById(decoded.id);
            
            if (!adminUser || !adminUser.admin) {
                return res.status(403).json({ message: 'Admin access required' });
            }
    
            // Prevent self-deletion
            if (decoded.id === req.params.id) {
                return res.status(400).json({ message: 'Cannot delete yourself' });
            }
    
            // Delete the user
            const result = await UserSchema.findByIdAndDelete(req.params.id);
            
            if (!result) {
                return res.status(404).json({ message: 'User not found' });
            }
    
            res.status(200).json({ 
                message: 'User deleted successfully',
                deletedUser: result.email
            });
            
        } catch (error) {
            console.error('Error deleting user:', error);
            res.status(500).json({ message: 'Error deleting user' });
        }
    }
}

// Start the API
const apiService = new MongoAPIService(3000);
apiService.start();
