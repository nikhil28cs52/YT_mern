const Joi= require('joi');
const User = require('../models/user');
const bcrypt = require('bcryptjs');

const userDTO = require('../dto/user');
const UserDTO = require('../dto/user');


const passwordPattern = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;

const authController = {

    async register(req, res, next) {
        // 1. validate user input

        const userRegisterSchema = Joi.object({
            username: Joi.string().min(5).max(30).required(),
            name: Joi.string().max(30).required(),
            email: Joi.string().email().required(),
            password: Joi.string().pattern(passwordPattern).required(),
            confirmPassword : Joi.ref('password')
            
        });

        const {error} = userRegisterSchema.validate(req.body);

        //2. if error in validation return error via middleware
        if (error) {
            return next(error); 
        }

        // if email or username is registere return error
        const {username,name,email,password} = req.body;

        try {
            const emailInUse = await User.exists({email});
            const usernameInUse = await User.exists({username});

            if (emailInUse || usernameInUse) {
                const error = {
                    status: 409,
                    message:'Email/Username already registered use another email!'
                }
                return next(error);

            }

        } catch (error) {
            return next(error);
        }

        // password hash
        const hashedPassword = await bcrypt.hash(password,10);
        // store user data in db
        const userToRegister = new User({
            username,  
            name,
            email,
            password: hashedPassword
            });
        const user= await userToRegister.save();
        // response end

        const userDTO = new UserDTO(user);

        return res.status(201).json({user:userDTO});
        // data validation by JOI

    },

    async login(req,res,next) {
        // validation of user data
        // if validation error ,return error
        // match username and password
        //return response

        const userLoginSchema = Joi.object({
            username: Joi.string().min(5).max(30).required(),
            password: Joi.string().pattern(passwordPattern).required(),
        });

        const {error} = userLoginSchema.validate(req.body);


        if (error) {
            return next(error); 
        }
        // check if user exists in db
        const {username, password} = req.body;
        let user;
        try {
            user = await User.findOne({username});


            if (!user) {
                const error = {
                    status: 401,
                    message:'Invalid Username',
                }
                return next(error);

            };

            // match password
            const isValidPassword = await bcrypt.compare(password, user.password);
            if (!isValidPassword){
                const error = {
                    status: 401,
                    message:'Invalid Password',
                }
                return next(error);
            };

        } catch (error) {
            return next(error);
        }
        const userDTO = new UserDTO(user);

        return res.status(200).json({user:userDTO});
    }
}
module.exports = authController;