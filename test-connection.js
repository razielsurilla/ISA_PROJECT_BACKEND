const MongoDBService = require('./MongoDBService');

async function testConnection() {
    const mongoDBService = new MongoDBService();

    try {
        const userCollection = await mongoDBService.connectToCollection('users');

        const newUser = {
            name: "Bil Nye",
            email: "billnye@test.com"
        };
        const result = await userCollection.insertOne(newUser);
        console.log(`New user inserted with id: ${result.insertedId}`);

        const updateResult = await userCollection.updateOne(
            { email: "billnye@test.com" },
            { $set: { name: "Billian Nye" } }
        );
        console.log(`User updated: ${updateResult.modifiedCount}`);
    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoDBService.disconnect();
    }
}

testConnection();
