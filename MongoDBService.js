require('dotenv').config();
const { MongoClient } = require('mongodb');

class MongoDBService {
    constructor() {
        this.uri = this.uri = `mongodb+srv://${process.env.MONGODB_USERNAME}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}?retryWrites=true`;
        this.client = null;
        this.database = process.env.MONGODB_DATABASE;
    }

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

    async disconnect() {
        if (!this.client) {
            return;
        }

        await this.client.close();
        this.client = null;
        console.log('Connection to MongoDB closed');
    }

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
