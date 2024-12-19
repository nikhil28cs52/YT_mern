const express = require('express');
const dbConnect = require('./database/index');
const {PORT} = require('./config/index');
const router = require('./routes/index')
const app = express();

 dbConnect();


app.use(router)


 app.listen(PORT, console.log(`Backend is running on port ${PORT}`));
