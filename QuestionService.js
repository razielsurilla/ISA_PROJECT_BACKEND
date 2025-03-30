// Imports
const MongoDBService = require('./MongoDBService.js');
const mongoose = require('mongoose');
const axios = require('axios');

class QuestionService{
    constructor(mongoDBService){
        this.mongoDBService = mongoDBService;
        this.mongoDBService.createSchema('trivia_style', {
            Category : {type : String, require : true},
            Question : {type : String, require : true},
            Answer : {type : String , require : true},
            Question_Audio: {type : String}, 
            Answer_Audio: {type : String}, 
            Audio_type : {type : String}
        });
    }

    /**
     * Retrieves the question and answer
     * 
     * @param {object} req as express request object
     * @param {object} res as express response object
     * @returns 
     */
    async getQuestion(req, res) {
        const questionId = req.params.id;
        
        //validate quesiton ID
        if (mongoose.Types.ObjectId.isValid(questionId)) {
            try {
                const triviaStyleSchema = this.mongoDBService.getSchema('trivia_style');
                const questionEntry = await triviaStyleSchema.findById(questionId);
                
                if (!questionEntry) {
                    return res.status(404).json({ message: `404 Question of ID ${questionId} does not exist` });
                }
                
                //get the data ponits
                const question = questionEntry.Question;
                const answer = questionEntry.Answer;
                const questionAudio = questionEntry.Question_Audio; 
                const answerAudio = questionEntry.Answer_Audio; 
                const audioType = questionEntry.Audio_type;

                //check if audio byte data exists
                if (!answerAudio || !questionAudio) {
                    console.log(`Audio Doesn't exists`)
                    const data = await this.aiServerRequest(question, answer);

                    //update object
                    const updateObject = {};
                    updateObject.Question_Audio = data.question_audio;
                    updateObject.Answer_Audio = data.answer_audio;
                    updateObject.Audio_Type = data.media_type;

                    // Use findByIdAndUpdate to update the document
                    const updatedQuestion = await triviaStyleSchema.findByIdAndUpdate(
                        questionId,
                        updateObject, 
                        { new: true, runValidators: true }
                    );
                    
                    // Check Updated Question Exists
                    if (!updatedQuestion) {throw error;}

                    res.status(200).json({ 
                        message : `200 Audio Retrieved successfully`, 
                        questionAudio : data.question_audio, 
                        answerAudio : data.answer_audio,
                        audioType : data.media_type
                    });
                } else {
                    try {
                        console.log('Audio Exists');
                        res.status(200).json({ 
                            message : '200 Audio Retrieved successfully', 
                            questionAudio : questionAudio, 
                            answerAudio : answerAudio,
                            audioType : audioType
                        });
                    } catch (error) {
                        throw error;
                    }
                }
            } catch (e) {
                res.status(500).json({ message: "500 Internal server error" });
            }
        } else {
            res.status(422).json({ message: "422 Improper ID Length" });
        }
    }

    async aiServerRequest(question, answer) {
        try {
            const response = await axios.post('http://localhost:8000/tts/', { question, answer }, {
                headers: {
                    'Content-Type': 'application/json; charset=utf-8',
                },
            });
            return response.data;
        } catch (error) {
            throw error;
        }
    }

    /**
     * Updates the trivia style question in database
     * 
     * @param {object} req express request object
     * @param {object} res express response object
     */
    async updateQuestion(req, res) {
        const _id = req.body.id;
        const Category = req.body.category;
        const Question = req.body.question;
        const Answer = req.body.answer;
        
        if(mongoose.Types.ObjectId.isValid(_id)){
            try {
                const triviaStyleSchema = this.mongoDBService.getSchema('trivia_style');
    
                // Check ID exists
                const exists = await triviaStyleSchema.findById(_id);
                if (!exists) {
                    return res.status(404).json({ message : `Question of ID ${_id} does not exist`})
                }
        
                // Check if all fields are empty
                if (!Category && !Question && !Answer) {
                    return res.status(400).json({ message: "No fields provided for update." });
                }
        
                // Create an update object with only non-empty fields
                const updateObject = {};
                if (Category) updateObject.Category = Category;
                if (Question) updateObject.Question = Question;
                if (Answer) updateObject.Answer = Answer;
        
                // Use findByIdAndUpdate to update the document
                const updatedQuestion = await triviaStyleSchema.findByIdAndUpdate(
                    _id,
                    updateObject, // Use the update object
                    { new: true, runValidators: true }
                );
                
                // Check Updated Question Exists
                if (!updatedQuestion) {
                    return res.status(404).json({ message: `Question with ID ${_id} not found` });
                }
    
                // Success
                res.status(200).json({
                    message: `Updated Question ${_id} successfully`,
                });
    
            } catch (error) {
                res.status(500).json({ message: "Internal Server Error" });
            }
        } else {
            return res.status(400).json({ message : "Invalid question ID format" })
        }
    }

    async deleteQuestion(){

    }

    /**
     * Creates a trivia style question into the database
     * 
     * @param {object} req express request object
     * @param {object} res express response object
     */
    async createQuestion(req, res){
        try {
            const Category = req.body.category;
            const Question = req.body.question;
            const Answer = req.body.answer;

            const triviaStyleSchema = this.mongoDBService.getSchema('trivia_style');  
            const newQuestion = new triviaStyleSchema({
                Category, 
                Question, 
                Answer,     
                Question_Audio: null,
                Answer_Audio: null,
            });
            await newQuestion.save();

            res.status(201).json({ message : 'Question Created Succesfully', questionId : newQuestion._id});
        } catch (error){
            res.status(500).json({ message : "Error Creating Question : " + error.message});
        }
    }
}


module.exports = QuestionService;
