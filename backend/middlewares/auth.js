const JWTService = require('../services/jwtService');
const User = require('../models/user');
const UserDTO = require('../dto/user');


const auth = async (req, res, next) => {

    try {
        const { refreshToken ,accessToken} = req.cookies;

    if (!refreshToken || !accessToken) {
        const error = {
            status: 401,
            message: 'Unauthorized',
        }
        return next(error);
    }

    let _id;
    try {
       _id = JWTService.verifyAccessToken(accessToken)._id;
        
    } catch (error) {
        return next(error);
        
    }
    
    try {
        user = await User.findOne({_id});
    } catch (error) {
        return next(error);
    }

    const userDto = new UserDTO(user);

    req.user = userDto;

    next();
        
    } catch (error) {
        return next(error);
        
    }
    
}

module.exports = auth;