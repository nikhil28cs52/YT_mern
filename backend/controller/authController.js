const Joi= require('joi');
const User = require('../models/user');
const bcrypt = require('bcryptjs');
const RefreshToken = require('../models/token');
const UserDTO = require('../dto/user');
const JWTService =  require('../services/JWTService')

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

        let accessToken;
        let refreshToken;
        // store user data in db
        let user;
        try { 
            const userToRegister = new User({
                username,  
                name,
                email,
                password: hashedPassword
            });
            user= await userToRegister.save();
            //token Generation

        accessToken = JWTService.signAccessToken({_id:user._id }, '30m');
        refreshToken = JWTService.signRefreshToken({ _id:user._id},'60m');
 
    } catch (error) {
            return next(error);
        }
        // store refresh token

        await JWTService.storeRefreshToken(refreshToken,user._id);

        // send token in cookie 
        res.cookie('accessToken',accessToken,{
            maxAge:1000*60*60*24*7,
            httpOnly: true
        });

        res.cookie('refreshToken',refreshToken,{
            maxAge:1000*60*60*24*7,
            httpOnly: true
        })
        // res


        // response end

        const userDto = new UserDTO(user);

        return res.status(201).json({user:userDto,auth:true});
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

        const accessToken = JWTService.signAccessToken({_id:user._id}, '30m');
        const refreshToken = JWTService.signRefreshToken({ _id:user._id},'60m');
        
        
        //update refresh token DB

        try {
            await RefreshToken.updateOne({userId:user._id},{token:refreshToken},{upsert:true});
        } catch (error) {
            return next(error);
        }
        res.cookie('accessToken',accessToken,{
            maxAge:1000*60*60*24*7,
            httpOnly: true
        });
        res.cookie('refreshToken',refreshToken,{
            maxAge:1000*60*60*24*7,
            httpOnly: true
            });

        
        const userDto = new UserDTO(user);

        return res.status(200).json({user:userDto, auth:true});
    },

    async logout(req,res,next) {
        // remove refresh token from db
        // remove cookies
        // return response

        const {refreshToken} = req.cookies;

        if (!refreshToken) {
            const error = {
                status: 400,
                message:'Bad Request'
            }
            return next(error);
        }

        try {
            await RefreshToken.deleteOne({token:refreshToken});
        } catch (error) {
            return next(error);
        }

        res.clearCookie('accessToken');
        res.clearCookie('refreshToken');

        return res.status(200).json({user:null,auth:false, msg:'Logout Successful'});
    }
}
module.exports = authController;