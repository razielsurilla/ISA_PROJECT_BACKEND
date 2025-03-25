/**
 * @file MongoDBService.js
 * @description This file contains the MongoDBService class which is used to connect to the MongoDB database.
 * @version 1.0.0
 * @since 16/03/2025
 */

require('dotenv').config();
const { MongoClient } = require('mongodb');

const mongoose = require('mongoose')
const { Schema, model } = mongoose;

/**
 * @class MongoDBService
 * @description This class is used to connect to the MongoDB database.
 */
class MongoDBService {
    
    /**
     * @constructor
     * @description Initialize the MongoDBS connection URI and sets up the database name.
     */
    constructor() {
        this.uri = `mongodb+srv://${process.env.MONGODB_USERNAME}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}?retryWrites=true`;
        this.connection = null;
        this.schema = {};
    }

    /**
     * Connects to the MongoDB database.
     * @returns {Promise<MongoClient>} The MongoDB client instance.
     * @throws {Error} If connection to the database fails.
     */
    // async connect() {
    //     try {
    //         if (this.connection) {
    //             return this.connection;
    //         }

    //         this.connection = await mongoose.connect(this.uri);

    //     } catch (error) {
    //         throw error;
    //     }
    //     if (this.client) {
    //         return this.client;
    //     }
    // }
    async connect() {
        try {
            if (this.connection) return this.connection;
            
            // Added connection options for stability
            this.connection = await mongoose.connect(this.uri, {
                useNewUrlParser: true, // Avoids deprecation warning
                useUnifiedTopology: true // New connection engine
            });
            
            return this.connection;
        } catch (error) {
            console.error("MongoDB connection error:", error);
            throw error;
        }
    }

    /**
     * Disconnects from the MongoDB database.
     * @returns {Promise<void>} Resolves when the connection is closed.
     * @throws {Error} If closing the connection fails or the connection is already closed.
     */
    async disconnect() {
        try {
            if (!this.connection) { return; }
            await mongoose.disconnect();
            this.connection = null;
        } catch (error) {
            throw error;
        }
        if (!this.client) {
            return;
        }
    }

    /**
     * Creates a schema for mongodb 
     * @param {string} name - The name of the schema
     * @param {object} schemaDefinition - The definition of the schema
     */
    createSchema(name, schemaDefinition) {
        try {
            const schema = new Schema(schemaDefinition);
            const model = mongoose.model(name, schema);
            this.schema[name] = model;
        } catch (error) {
            throw error;
        }
    }
    
    /**
     * Retrieves Schema and its name
     */
    getSchema(name){
        try {
            return this.schema[name];
        } catch (error){
            throw error;
        };
    }
}

module.exports = MongoDBService;
