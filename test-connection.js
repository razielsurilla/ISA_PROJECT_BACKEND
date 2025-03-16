const MongoDBService = require('./MongoDBService');

async function testConnection() {
    const mongoDBService = new MongoDBService();

    try {
        const userCollection = await mongoDBService.connectToCollection('users');

        const existingUser = await userCollection.findOne({ email: "billnye@test.com" });
        if (existingUser) {
            console.log("User already exists:", existingUser);
        } else {
            const newUser = {
                name: "Bil Nye",
                email: "billnye@test.com"
            };
            const result = await userCollection.insertOne(newUser);
            console.log(`New user inserted with id: ${result.insertedId}`);
        }

        const updateResult = await userCollection.updateOne(
            { email: "billnye@test.com" },
            { $set: { name: "Billian Nye" } }
        );
        console.log(`User update result:`, updateResult);
        console.log(`Documents modified: ${updateResult.modifiedCount}`);

        if (updateResult.modifiedCount === 0) {
            console.log("No documents were updated. Check the filter and the data.");
        }

    } catch (error) {
        console.error('Error:', error);
    } finally {
        await mongoDBService.disconnect();
    }
}

testConnection();
