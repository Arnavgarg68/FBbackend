const express = require('express');
const app = express();
const cors = require('cors');
const mongoose = require('mongoose');
const router = require('./Routes/route')
app.use(express.json());
app.use(cors());
require('dotenv').config();
mongoose.connect(process.env.MONGODB_URI).then(()=>{
    app.listen(process.env.PORT,()=>{
        console.log(`http://localhost:${process.env.PORT}`)
    })
}).catch((error)=>{
    console.log(`Error connecting mongoDB -> ${error}`)
})

// app.get('/',async(req,res)=>{
//     res.json("Hello server here");
// })
app.use(router)