// Imports
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const express = require('express')
const MongoDBService = require('./MongoDBService.js');
const mongoose = require('mongoose');

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
        }, {
            collection : 'users'
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

class UserRegistration {
    static saltRounds = 12;

    static encrypt(password, saltRounds = UserRegistration.saltRounds) {
        return bcrypt.hashSync(password, saltRounds);
    }

    // debating making this its own class or a static method
    async authentication(user, password) {
        const match = await bcrypt.compareSync(password, user.password);
        return match;
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
        
        // digitalocean.com/getUser

        this.app.delete('/deleteUser', (req, res) => {
            //delete user function
        })
    }

    async start() {
        await this.mongoDBService.connect();
        this.app.use(cors());

        this.defineRoutes(); 

        this.app.listen(this.port, () => {

        });
    }

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

    async checkUser(req, res) {
        try {
            const userCollection = this.userService.mongoDBService.getSchema('user');
            const user = await userCollection.findOne({ email: req.body.email });
            if (!user) {
                res.status(404).json({ message: 'User not found' });
                return;
            }
            
            const isPasswordValid = bcrypt.compareSynsc(req.body.password, user.password);
            if (!isPasswordValid) {
                res.status(401).json({ message: 'Invalid password' });
                return;
            }
            const token = jwt.sign({ userId: user._id, email: user.email }, 'your_jwt_secret_key', { expiresIn: '1h' });
            res.status(200).json({ message: 'Login successful', token, admin: user.admin });
        } catch (error) {
            res.status(500).json({ message: 'Error logging in: ' + error.message });
        }
    }


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

const apiService = new MongoAPIService(3000);
apiService.start();
