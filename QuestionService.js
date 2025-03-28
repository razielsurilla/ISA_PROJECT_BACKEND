// Imports
const MongoDBService = require('./MongoDBService.js');


class QuestionService{
    constructor(mongoDBService){
        this.mongoDBService = mongoDBService;
        this.mongoDBService.createSchema('trivia_style', {
            Category : {type : String, require : true},
            Question : {type : String, require : true},
            Answer : {type : String , require : true}
        });
    }

    async getQuestion(){

    }

    async updateQuestion(){

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
