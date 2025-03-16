// Imports
const bcrypt = require('bcrypt');
const express = require('express')
const MongoDBService = require('./MongoDBService');
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
        }, {
            collection : 'users'
        });
    }

    async createUser(username, email, password) {
        try {
            const UserSchema = this.mongoDBService.getSchema('user');
            const encryptedPassword = UserRegistration.encrypt(password);
            const newUser = new UserSchema({username, email, encryptedPassword});
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
        this.port = port || 3000;

        this.app.use(express.json());
        this.app.use(express.urlencoded({ extended: true }));
        this.app.use(express.static('public'));
    }

    /**
     * Defines the routes for the API
     * @returns {void}
     */
    defineRoutes() {
        this.app.post('/createUser', (req, res) => {
            this.createUser()
        });

        this.app.get('/getUser', (req, res) => {
            this.getUser(req, res)
        });
        // digitalocean.com/getUser

        this.app.delete('/deleteUser', (req, res) => {
            //delete user function
        })
    }

    
    async start() {
        await this.mongoDBService.connect();

        this.defineRoutes(); 

        this.app.listen(this.port, () => {

        });
    }

    async createUser(req, res) {
        try {
            const result = await this.userService.createUser(req.body.name, req.body.email, req.body.password)
            res.status(201).json({message : 'User Created Succesfully: ' + result.insertedId})
        } catch (error) {
            res.status(500).json({ message: 'Error creating user: ' + error.message });
        }        
    }

    async getUser(req, res) {
        try {
            const result = await this.userService.getUser(req.body.email)
            res.status(200).json(result)
        } catch (error) {
            res.status(500).json({ message: 'Error retrieving user: ' + error.message });
        }
    }
}
