// schema is username(unique like a handle for social),password(hashed),details(can be used in future to filter or show similar fields recomendations),Friends (array to handle 1-> pending requested to be accepted/rejected by user , 2-> accepted the friends which are confirmed from both the sides ,3-> requests made by user to other people for friends) 



const { Schema, model } = require('mongoose')
const userschema = new Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    details: {
        state: {
            type: String,
        }
    },
    friends: {
        pending: [{
            type: Schema.Types.ObjectId,
            ref: 'user'
        }
        ],
        accepted: [{
            type: Schema.Types.ObjectId,
            ref: 'user'
        }],
        requested: [{
            type: Schema.Types.ObjectId,
            ref:'user'
        }]
    }



}, { timestamps: true })

const user = model("user", userschema);

module.exports = user;