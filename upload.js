const { MongoClient } = require('mongodb');
const fs = require('fs');
require('dotenv').config();

// Connection URL (from .env or hardcoded)
const url = `mongodb+srv://${process.env.MONGODB_USERNAME}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}?retryWrites=true`;
const dbName = 'Trivia'; // Default to 'Trivia' if not specified
const collectionName = 'trivia_style'; // Replace with your collection name

// Path to the JSON file
const filePath = 'C:/Users/nhild/Downloads/trivia.json'; // Replace with your file path

// Read the JSON file
const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));

async function main() {
    const client = new MongoClient(url, { useUnifiedTopology: true });

    try {
        // Connect to the MongoDB server
        await client.connect();
        console.log('Connected successfully to server');

        const db = client.db(dbName);
        const collection = db.collection(collectionName);

        // Insert the JSON data into the collection
        const result = await collection.insertMany(data);
        console.log(`${result.insertedCount} documents were inserted into ${collectionName}`);
    } catch (error) {
        console.error('Error uploading JSON data:', error);
    } finally {
        // Close the connection
        await client.close();
        console.log('Connection closed');
    }
}

// Run the script
main();