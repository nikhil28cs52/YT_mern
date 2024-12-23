const jwt = require('jsonwebtoken');
const {ACCESS_TOKEN_SECRET, REFRESH_TOKEN_SECRET} = require('../config/index');
const RefreshToken = require('../models/token');
class JWTService{

    //sign refresh token
    static signAccessToken(payload,expiryTime,secret=ACCESS_TOKEN_SECRET){
        return jwt.sign(payload,secret,{expiresIn:expiryTime});
    }


    static signRefreshToken(payload,expiryTime,secret=REFRESH_TOKEN_SECRET){
        return jwt.sign(payload,secret,{expiresIn:expiryTime});
    }

    //varify access token

    static verifyAccessToken(token){
        return jwt.verify(token,ACCESS_TOKEN_SECRET);
    }
    // varify refresh token

    static verifyRefreshToken(token){
        return jwt.verify(token,ACCESS_TOKEN_SECRET);
    }
    //store refresh token
    static async storeRefreshToken(token){
        try {
            const newToken = new RefreshToken (
            {
                token:token,
                userId: userId

            });
            await newToken.save();
        } catch (error) {
            console.log(error);
        }
    }
}

module.exports = JWTService;