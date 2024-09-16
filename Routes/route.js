const mongoose = require('mongoose');
const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../Models/user');
const bcrypt = require('bcrypt');
const router = express.Router();
require('dotenv').config();
const key = process.env.KEY;
const options = {
    expiresIn: "1h"
}
// Middlewares

//  1)      authjwt to create a jwt token
const authjwt = (payload, key, options) => {
    return jwt.sign(payload, key, options)
}

//  2) authVerify to check validity of token and fetch username from it
const authVerify = (req, res, next) => {
    const token = req.headers['token'];
    if (!token) {
        return res.status(400).json({ errormsg: "token no provided login/signup" })
    }
    try {
        const decoded = jwt.verify(token, key);
        req.user = decoded;
        next();
    } catch (error) {
        console.log(error);
        res.status(400).json({ errormsg: "Invalid token" ,type:"token" })
    }
}

//  3) hash to generate a hashedpassword from password
const hash = async (pass) => {
    try {
        return bcrypt.hash(pass, 10)
    }
    catch (error) {
        console.log(error);
    }
}
//  4) hashverify to verify the passowrd and stored hashed password
const hashverify = async (pass, hpass) => {
    try {
        return bcrypt.compare(pass, hpass)
    } catch (error) {
        console.log(error);
    }
}


// routes or endpoints REST  (note*=> used only GET & POST but can use Update/Delete but for simplicity GET&POST are only used)


// route just to check working of server
router.get('/ping', async (req, res) => {
    res.json("Server working perfectly");
})

// application routes
// 1) route to create a new user / singup
router.post('/create', async (req, res) => {
    let { username, password, state } = req.body;
    if (!username?.trim(' ') || !password?.trim(' ')) {
        return res.status(400).json({ errormsg: "username and password are required" })
    }
    username = username.trim(' ').toLowerCase();
    password = password.trim(' ');
    if (password.length < 6) {
        res.status(400).json({ errormsg: "Password is too  short" })
        return;
    }
    if (password.indexOf(' ') > 0) {
        res.status(400).json({ errormsg: "password cannot contain spaces" })
        return;
    }
    const check = await User.findOne({ username: username });
    if (check) {
        return res.status(400).json({ errormsg: "try another user name this already exists" })
    }
    const hpass = await hash(password);
    const user = new User({
        username: username,
        password: hpass,
        details: {
            state: state
        }
    });
    try {
        const savedUser = await user.save();
        const token = authjwt({ username: username }, key, options);
        res.status(200).json({ token: token });
    } catch (err) {
        res.status(400).json({ errormsg: err.message });
    }
})

// 2) Route to create a login user
router.post('/login', async (req, res) => {
    let { username, password } = req.body;
    if (!username?.trim(' ') || !password?.trim(' ')) {
        return res.status(400).json({ errormsg: "username and password are required" })
    }
    username = username.trim(' ').toLowerCase();
    password = password.trim(' ');
    if (password.length < 6) {
        res.status(400).json({ errormsg: "Password is too  short" })
        return;
    }
    if (password.indexOf(' ') > 0) {
        res.status(400).json({ errormsg: "password cannot contain spaces" })
        return;
    }
    const user = await User.findOne({ username: username });
    if (!user) {
        return res.json({ errormsg: "User dont exist try another username" })
    }
    if (!await hashverify(password, user.password)) {
        return res.status(400).json({ errormsg: "Incorrect username/password" })
    }
    else {
        const token = authjwt({ username: username }, key, options);
        res.status(200).json({ token: token });
    }
})


// 3) Route to send all friends list including the recommendations
router.get('/list', authVerify, async (req, res) => {
    const { username } = req.user;

    try {
        const user = await User.findOne({ username: username });

        if (!user) {
            return res.status(400).json({ errormsg: "User not found" });
        }

        const result = await User.aggregate([
            // Match the current user
            { $match: { _id: user._id } },

            // Lookup the pending friends
            {
                $lookup: {
                    from: 'users',
                    localField: 'friends.pending', 
                    foreignField: '_id',   
                    as: 'friendsPending' 
                }
            },

            // Lookup the requested not neccessary as not showing in frontend
            {
                $lookup: {
                    from: 'users',           
                    localField: 'friends.requested',  
                    foreignField: '_id',  
                    as: 'friendsRequested'    
                }
            },

            // Lookup the accepted friends
            {
                $lookup: {
                    from: 'users',          
                    localField: 'friends.accepted', 
                    foreignField: '_id',     
                    as: 'friendsAccepted'    
                }
            },

            // Lookup friends of friends
            {
                $lookup: {
                    from: 'users', 
                    localField: 'friendsAccepted.friends.accepted',
                    foreignField: '_id',  
                    as: 'friendsOfFriends' 
                }
            },

            // Filter out already accepted friends from friendsOfFriends
            {
                $addFields: {
                    friendsOfFriends: {
                        $filter: {
                            input: "$friendsOfFriends",
                            as: "fof",
                            cond: {
                                $not: {
                                    $in: ["$$fof._id", "$friendsAccepted._id"]
                                }
                            }
                        }
                    }
                }
            },

            // Project to shape the output
            // {
            //     $project: {
            //         _id: 0,
            //         username: 1,     
            //         'friendsPending': 1,
            //         'friendsRequested': 1,
            //         'friendsAccepted': 1,
            //         'friendsOfFriends': 1
            //     }
            // }
            {
            $project: {
                _id: 0,
                username: 1,     
                friendsPending: {
                    $map: {
                        input: "$friendsPending",
                        as: "friend",
                        in: {
                            username: "$$friend.username",
                            details: "$$friend.details"
                        }
                    }
                },
                friendsRequested: {
                    $map: {
                        input: "$friendsRequested",
                        as: "friend",
                        in: {
                            username: "$$friend.username",
                            details: "$$friend.details"
                        }
                    }
                },
                friendsAccepted: {
                    $map: {
                        input: "$friendsAccepted",
                        as: "friend",
                        in: {
                            username: "$$friend.username",
                            details: "$$friend.details"
                        }
                    }
                },
                friendsOfFriends: {
                    $map: {
                        input: "$friendsOfFriends",
                        as: "friend",
                        in: {
                            username: "$$friend.username",
                            details: "$$friend.details"
                        }
                    }
                }
            }
        }
        ]);
        if (!result || result.length === 0) {
            return res.status(400).json({ errormsg: "User not found" });
        }

        // Send the processed result
        res.json(result[0]);  // Since result is an array, use result[0]
    } catch (error) {
        console.log(error);
        res.status(500).json({ errormsg: error.message });
    }
});



// 4) search people currently on one person later on can show many results
router.post('/search', authVerify, async (req, res) => {
    const { username } = req.user;
    const { search } = req.body;
    const searchuser = search.trim(' ').toLowerCase();
    if (!searchuser || !username) {
        return res.status(350).json({ errormsg: "Invalid user login/singup again" })
    }
    try {
        const frienduser = await User.findOne({ username: searchuser })
        const user = await User.findOne({ username: username })
        if(!user||!frienduser){
            return res.status(400).json({errormsg:"user/friend not found"})
        }
        if(user._id.equals(frienduser._id)){
            return res.status(200).json({errormsg:"Searching yourself isn't a cool practice"})
        }
        let val = -1;
        if (user && frienduser) {
            if (user.friends.requested.includes(frienduser._id)) {
                val = 0;
            }
            else if (user.friends.pending.includes(frienduser._id)) {
                val = 1;
            }
            else if (user.friends.accepted.includes(frienduser._id)) {
                val = 2;
            }
            res.status(200).json({ username: frienduser.username, val: val });
        }
        else {
            res.status(200).json({ errormsg: "No user found" })
        }

    } catch (error) {
        console.log(error)
        res.status(400).json({ errormsg: "error" });
    }
})
// 5) ADD friend new
router.post('/addfriend', authVerify, async (req, res) => {
    try {
        const { friendname } = req.body;
        const { username } = req.user;
        if (!friendname) {
            res.status(400).json({ errormsg: "Invalid entry" });
            return;
        }
        const fn = friendname.trim(' ').toLowerCase();
        if (!fn) {
            res.status(400).json({ errormsg: "Invalid entry" });
            return;
        }
        const friend = await User.findOne({ username: fn });
        const user = await User.findOne({ username: username })
        if (!user || !friend) {
            return res.status(200).json({ errormsg: "user/friend dont exist or invalid username" });
        }
        if (user.friends.requested.includes(friend._id) || user.friends.accepted.includes(friend._id) || user.friends.pending.includes(friend._id)) {
            res.status(400).json({ errormsg: "user already in pending/accepted/request list" });
            return;
        }
        user.friends.requested.push(friend._id);
        friend.friends.pending.push(user._id);
        await user.save();
        await friend.save();
        res.status(200).json({ success: "request sent successfully" });

    } catch (error) {
        return res.status(400).json({ errormsg: error });
    }
})


// 6) Accept/Reject pending user requests
router.post('/decision', authVerify, async (req, res) => {
    const { friendname, value } = req.body; // value is true for accepting, false for rejecting
    const { username } = req.user;

    try {
        if (!friendname) {
            return res.status(400).json({ errormsg: "Invalid friend name" });
        }

        // Find the friend and user
        const friend = await User.findOne({ username: friendname });
        const user = await User.findOne({ username: username });
        if (!user || !friend) {
            return res.status(404).json({ errormsg: "User or friend not found" });
        }
        if (value) {
            // Accept friend request: remove from pending and add to accepted
            user.friends.pending = user.friends.pending.filter(id => !id.equals(friend._id));
            user.friends.accepted.push(friend._id);

            friend.friends.requested = friend.friends.requested.filter(id => !id.equals(user._id));
            friend.friends.accepted.push(user._id);
        } else {
            // Reject friend request: just remove from pending/requested
            user.friends.pending = user.friends.pending.filter(id => !id.equals(friend._id));
            friend.friends.requested = friend.friends.requested.filter(id => !id.equals(user._id));
        }
        await user.save();
        await friend.save();
        res.status(200).json("Decision completed successfully");

    } catch (error) {
        console.error(error);
        res.status(500).json({ errormsg: "Server error" });
    }
});

// 7) unfriend friend
router.post('/unfriend', authVerify, async (req, res) => {
    try {
        const { friendname } = req.body;
        const { username } = req.user;

        if (!friendname) {
            return res.status(400).json({ errormsg: "Invalid entry" });
        }
        const fn = friendname.trim().toLowerCase();

        if (!fn) {
            return res.status(400).json({ errormsg: "Invalid entry" });
        }

        const friend = await User.findOne({ username: fn });
        const user = await User.findOne({ username: username });

        if (!user || !friend) {
            return res.status(404).json({ errormsg: "User or friend does not exist" });
        }

        const isFriend = user.friends.requested.includes(friend._id) ||
            user.friends.accepted.includes(friend._id) ||
            user.friends.pending.includes(friend._id);

        if (!isFriend) {
            return res.status(400).json({ errormsg: "Friend not found in any list" });
        }
        // removed all relations between user and friend
        user.friends.requested = user.friends.requested.filter(id => !id.equals(friend._id));
        user.friends.accepted = user.friends.accepted.filter(id => !id.equals(friend._id));
        user.friends.pending = user.friends.pending.filter(id => !id.equals(friend._id));

        friend.friends.requested = friend.friends.requested.filter(id => !id.equals(user._id));
        friend.friends.accepted = friend.friends.accepted.filter(id => !id.equals(user._id));
        friend.friends.pending = friend.friends.pending.filter(id => !id.equals(user._id));

        await user.save();
        await friend.save();
        res.status(200).json({ successmsg: "Friend removed successfully" });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ errormsg: "Server error" });
    }
});


// exporting these routes

module.exports = router;