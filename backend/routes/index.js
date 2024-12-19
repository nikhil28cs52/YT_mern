const express = require('express');

const router = express.Router();

router.get('/test', (req,res) =>{
    res.json({msg: 'Testing webpage of route/index.js '})
 });

 module.exports = router;