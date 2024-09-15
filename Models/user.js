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