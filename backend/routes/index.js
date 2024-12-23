const express = require('express');
const authController = require('../controller/authController')
const auth = require('../middlewares/auth');

const router = express.Router();

router.get('/test', (req,res) =>{
    res.json({msg: 'Testing webpage of route/index.js '})
 });

 router.post('/login', authController.login);

 router.post('/register', authController.register);

 //logout

    router.post('/logout', auth, authController.logout);

 module.exports = router;