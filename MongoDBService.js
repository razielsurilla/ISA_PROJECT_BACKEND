/**
 * @file MongoDBService.js
 * @description This file contains the MongoDBService class which is used to connect to the MongoDB database.
 * @version 1.0.0
 * @since 16/03/2025
 */

require('dotenv').config();
const { MongoClient } = require('mongodb');

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
        this.uri = this.uri = `mongodb+srv://${process.env.MONGODB_USERNAME}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}?retryWrites=true`;
        this.client = null;
        this.database = process.env.MONGODB_DATABASE;
    }

    /**
     * Connects to the MongoDB database.
     * @returns {Promise<MongoClient>} The MongoDB client instance.
     * @throws {Error} If connection to the database fails.
     */
    async connect() {
        if (this.client) {
            return this.client;
        }

        try {
            this.client = await MongoClient.connect(this.uri);
            console.log('Connected to MongoDB');
            return this.client;
        } catch (error) {
            console.error('Error connecting to MongoDB:', error);
            throw error;
        }
    }

    /**
     * Disconnects from the MongoDB database.
     * @returns {Promise<void>} Resolves when the connection is closed.
     * @throws {Error} If closing the connection fails or the connection is already closed.
     */
    async disconnect() {
        if (!this.client) {
            return;
        }

        await this.client.close();
        this.client = null;
        console.log('Connection to MongoDB closed');
    }

    /**
     * Connects to a specific collection in the database.
     * @param {string} collectionName The name of the collection to connect to.
     * @returns {Promise<Collection>} The collection instance.
     * @throws {Error} If connection to the collection fails.   
     */
    async connectToCollection(collectionName) {
        try {
            const client = await this.connect();
            const db = client.db(this.database);
            const requestedCollection = db.collection(collectionName);
            console.log(`Connected to ${collectionName} collection`);
            return requestedCollection;
        } catch (error) {
            console.error('Error connecting to MongoDB collection:', error);
            throw error;
        }
    }
}

module.exports = MongoDBService;
