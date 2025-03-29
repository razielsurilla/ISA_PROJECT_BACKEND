    // Imports
    const MongoDBService = require('./MongoDBService.js');
    const mongoose = require('mongoose');

    class QuestionService{
        constructor(mongoDBService){
            this.mongoDBService = mongoDBService;
            this.mongoDBService.createSchema('trivia_style', {
                Category : {type : String, require : true},
                Question : {type : String, require : true},
                Answer : {type : String , require : true},
                Question_Audio: { type: 'BinData', require : false}, 
                Answer_Audio: { type: 'BinData', require : false }, 
            });
        }

        /**
         * Retrieves the question and answer
         * 
         * @param {object} req as express request object
         * @param {object} res as express response object
         * @returns 
         */
        async getQuestion(req, res){
            const questionId = req.params.id;

            //locate the questionId 

            console.log(questionId);

            if(questionId) return res.status(200).json({ message : "Successfully retrieved question" });
            res.status(404).json({ message : "Failed to retrieve question" });
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
                const newQuestion = new triviaStyleSchema({Category, Question, Answer});
                await newQuestion.save();

                res.status(201).json({ message : 'Question Created Succesfully', questionId : newQuestion._id});
            } catch (error){
                res.status(500).json({ message : "Error Creating Question : " + error.message});
            }
        }
    }


    module.exports = QuestionService;
