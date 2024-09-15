// gathering all the dependencies
const express = require('express');
const app = express();
const cors = require('cors');
const mongoose = require('mongoose');
const router = require('./Routes/route')

// sitting middlewares
app.use(express.json());
app.use(cors());
require('dotenv').config();

// set up database connection & server startup
mongoose.connect(process.env.MONGODB_URI).then(()=>{
    app.listen(process.env.PORT,()=>{
        console.log(`http://localhost:${process.env.PORT}`)
    })
}).catch((error)=>{
    console.log(`Error connecting mongoDB -> ${error}`)
})

// using route file to manage all routes
app.use(router)