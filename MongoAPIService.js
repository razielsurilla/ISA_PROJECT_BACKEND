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
            admin: {type: Boolean, default: false}
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

    /**
     * Defines the routes for the API
     * @returns {void}
     */
    defineRoutes() {
        this.app.post('/createUser', (req, res) => this.createUser(req, res));
        this.app.post('/checkUser', (req, res) => this.checkUser(req, res));
        this.app.get('/getUser', (req, res) => this.getUser(req, res));

        this.app.get('/authenticate', (req, res) => this.authenticate(req, res)); 

        this.app.delete('/deleteUser', (req, res) => {})
    }

    /**
     * Starts express server
     * Defines API routes
     */
    async start() {
        await this.mongoDBService.connect();
        this.app.use(cors({
            origin: 'https://triviaproto.netlify.app/', // Allow both origins
            credentials: true,
            methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS', //allows the handling of pre-flights
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
        const token = req.cookies.userCookie; //Uses cookieParser
        
        if (!token) {
            return res.status(401).json({ authenticated: false, message: 'No token provided' });
        }

        jwt.verify(token, 'your_jwt_secret_key', (err, decoded) => {
            if (err) {
                return res.status(403).json({ authenticated: false, message: 'Invalid token' });
            }
            // Token is valid
            res.status(200).json({ authenticated: true, user: decoded }); //send the user data back.
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
            res.cookie('userCookie', token, {httpOnly: true, secure : true, sameSite: 'None'});
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
