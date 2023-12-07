const express = require("express")
const app = express()
const Sequelize = require("sequelize")
const jwt = require("jsonwebtoken")
const models = require("./models/index.js")
// const {User, UserPassword} = models
const bcrypt = require('bcryptjs');
const dotEnv = require('dotenv').config()
const port_num = process.env.PORT || 3000
const crypto = require("crypto")

//  The expressjwt function is exported by the express-jwt module.
//  The syntax { expressjwt: expressJwt } extracts the expressjwt function and renames it to expressJwt
const {expressjwt: expressJwt} = require("express-jwt")

const sequelize = new Sequelize({
    dialect: 'sqlite',
    storage: ".storage/main.sqlite" // or ':memory:' for an in-memory database

    // If wanted temporary memory not saved between runs?
    // storage: ':memory:'
});

sequelize.authenticate().then(()=>{console.log("connected")})

function encrypt(str, key) {
    const algorithm = 'aes-256-ctr'
    //  initialization vector to make encryption value unique
    const iv = crypto.randomBytes(16)
    const encKey = crypto.createHash('sha256').update(String(key)).digest('base64').slice(0,32)
    const cipher = crypto.createCipheriv(algorithm, encKey, iv)
    let crypted = cipher.update(str, 'utf-8', 'base64') + cipher.final('base64')
    return `${crypted}-${iv.toString('base64')}`
}

function decrypt(encStr, key){
    const algorithm = 'aes-256-ctr'
    const encArr = encStr.split('-')
    const encKey = crypto.createHash('sha256').update(String(key)).digest('base64').slice(0,32)
    const decipher = crypto.createDecipheriv(algorithm, encKey, Buffer.from(encArr[1], 'base64'))
    let decrypted = decipher.update(encArr[0], 'base64', 'utf-8')
    decrypted += decipher.final('utf-8')
    return decrypted
}

app.use(express.json()) // built-in body parser

app.use(
    expressJwt ({
        secret: process.env.JWT_SECRET,
        algorithms: ["HS256"]
    }).unless ({path: ["/login", "/signup", '/']})
);

app.get('/', (req, res, next)=>{
    res.send("Greetings!")
})

app.post('/signup', async (req, res, next)=> {
    // req.body.email;
    // req.body.password;
    // req.body.encryption_key;
    // req.body.name;
    const { email, password, encryption_key, name } = req.body;

    try {
        // Hash password and encryption_key
        const hashedPassword = await hashStr(password);
        const hashedEncryptionKey = await hashStr(encryption_key);

        // Prepare the data object with hashed values
        const data = {
            email,
            password: hashedPassword,
            encryption_key: hashedEncryptionKey,
            name
        };

        // Fetch the models
        const User = models.User;

        // Check if email already exists
        const emailExists = await User.findOne({ attributes: ['id'], where: { email } });
        if (emailExists) {
            res.status(400);
            return res.json({ message: "This email already exists", "sys_message": "email_exists" });
        }

        // Create a new user
        const result = await User.create(data);
        console.log(result);
        res.send("Signup successful");
    } catch (error) {
        console.error(error); // Log the error for debugging
        res.status(500).json({message: error.message});
    }
})

app.post('/login', async (req, res, next)=> {
    const { email, password } = req.body;
    const User = models.User
    try {
        const user_record = await User.findOne({attributes: ["id", "email", "password"], where: {email: email}})
        if (!user_record){
            res.status(403);
            return res.json({
                message: "Invalid email or password",
                "sys_message": "invalid_email_password"
            });
        }
        //  Email exists, check that inputted password is correct
        const password_matched = await bcrypt.compare(password, user_record.password)
        if (password_matched){

            //  Non-promise type, so no await needed
            const token = jwt.sign(
                {user_id: user_record.id},
                process.env.JWT_SECRET,
                {algorithm: "HS256"}
                )

            res.json({
                message: "login was successful",
                "sys_message": "login_success",
                token
            });
            return;
        }
        res.status(403);
        res.json({
            message: "Invalid email or password",
            "sys_message": "invalid_email_password"})
    }
    catch (e){
        res.status(403);
        res.json({message: e.message})
    }
})

app.post('/passwords/save', async(req, res, next) => {
    const {url, username, password, encryption_key, label} = req.body;
    if(!(username && password && url)){
        res.status(400)
        return res.json({
            message: "Missing parameters"
        })
    }

    const userId = req.auth.user_id; //  Returns ID that we placed in token if authenticated
    const User = models.User

    const user_record = await User.findOne({
        attributes: ['encryption_key'],
        where: {id: userId}
    })
    if (!user_record){
        res.status(404)
        return res.json({
            message: "Unable to find user account"
        })
    }

    const correct_encryption = await bcrypt.compare(encryption_key, user_record.encryption_key)
    if(!correct_encryption){
        res.status(400)
        return res.json({
            message: "Incorrect encryption key"
        })
    }

    const encrypted_username = encrypt(username, encryption_key)
    const encrypted_password = encrypt(password, encryption_key)
    const result = await models.UserPassword.create({
        owner_user_ID: userId, password: encrypted_password, username: encrypted_username, URL: url, label: label
    })

    res.status(200)
    res.json({message: "Password saved"})
})

app.post('/passwords/list', async (req, res, next) => {
    //  Assuming user is logged in already, so will just validate encryption key
    const userId = req.auth.user_id;
    const encryption_key  = req.body.encryption_key;

    const User = models.User;
    const UserPassword = models.UserPassword;

    const user_record = await User.findOne({
        where: {id: userId},
        attributes: ["encryption_key"]
    });
    const valid_encryption_key = await bcrypt.compare(encryption_key, user_record.encryption_key);
    if (!valid_encryption_key){
        res.status(400)
        return res.json({
            message: "Incorrect encryption key"
        })
    }

    const passwords = await UserPassword.findAll({
        where: {owner_user_ID: userId},
        attributes: ['id', 'label', 'URL', 'username', 'password', 'weak_encryption']
    });

    /*
    * This code for some reason made it that the first time a recipient of a new password checks their passwords list,
    * the username and password are still encrypted in some way. Only after they run the passwords list request a second
    * time does the most recently received password appear correctly. At some point, try to understand why, for the sake
    * of learning.
    * */

    // passwords.forEach(async curr_password => {
    //     if (curr_password.weak_encryption === true){
    //         const decrypted_username = decrypt(curr_password.username, user_record.encryption_key)
    //         const decrypted_password = decrypt(curr_password.password, user_record.encryption_key)
    //         curr_password.set({
    //             username: encrypt(decrypted_username, encryption_key),
    //             password: encrypt(decrypted_password, encryption_key),
    //             weak_encryption: false
    //         })
    //         await curr_password.save()
    //     }
    //     curr_password.set({
    //         username: decrypt(curr_password.username, encryption_key),
    //         password: decrypt(curr_password.password, encryption_key)
    //     })
    // })

    for (const curr_password of passwords) {
        if (curr_password.weak_encryption === true) {
            const decrypted_username = decrypt(curr_password.username, user_record.encryption_key);
            const decrypted_password = decrypt(curr_password.password, user_record.encryption_key);

            curr_password.set({
                username: encrypt(decrypted_username, encryption_key),
                password: encrypt(decrypted_password, encryption_key),
                weak_encryption: false
            });

            await curr_password.save();
        }

        curr_password.set({
            username: decrypt(curr_password.username, encryption_key),
            password: decrypt(curr_password.password, encryption_key)
        });
    }

    res.json({
        message: "Passwords list",
        passwords
    })
});

app.post('/passwords/share-passwords', async (req, res, next) => {
    const {password_id, encryption_key, email} = req.body;
    const user_id = req.auth.user_id;
    const UserPassword = models.UserPassword;
    const User = models.User;

    //  Validate encryption_key entered by sharer is correct
    const sharer_record = await User.findOne({
        where: {id: user_id},
        attributes: ["encryption_key"]
    })
    const valid_encryption_key = await bcrypt.compare(encryption_key, sharer_record.encryption_key)
    if (!valid_encryption_key){
        res.status(400);
        res.json({
            message: 'Not a valid encryption key (in share-passwords handler)'
        })
    }

    const password_to_share = await UserPassword.findOne({
        where: {owner_user_ID: user_id, id: password_id},
        // attributes: ['URL', 'username', 'password'] //   Wrong because we want to share all info except ID of pass.
        attributes: ['label', 'URL', 'username', 'password']

    })
    if (!password_to_share){
        res.status(400);
        return res.json({message: "Password doesn't exist, or you are trying to access a password that isn't yours to share"})
    }

    const user_we_are_sharing_with = await User.findOne({
        where: {email: email},
        attributes: ['id', 'email', 'encryption_key']
    });
    if (!user_we_are_sharing_with){
        res.status(400);
        return res.json({message: "User with whom you want to share your password doesn't exist"})
    }

    const password_already_shared_before = await UserPassword.findOne({
        where: {
            owner_user_ID: user_we_are_sharing_with.id,
            id_of_original_password: password_id
        },
        attributes: ['id']
    })
    if (password_already_shared_before){
        res.status(400);
        return res.json({message: "This password was already shared with the user!"})
    }

    const recipients_new_password = {
        owner_user_ID: user_we_are_sharing_with.id,
        label: password_to_share.label,
        URL: password_to_share.URL,
        // decrypting username and password with sharer's e-key, and re-encrypting with the hashed-e-key of recipient
        username: encrypt(decrypt(password_to_share.username, encryption_key), user_we_are_sharing_with.encryption_key),
        password: encrypt(decrypt(password_to_share.password, encryption_key), user_we_are_sharing_with.encryption_key),
        shared_by_user_ID: user_id,
        weak_encryption: true,
        id_of_original_password: password_id
    }
    await UserPassword.create(recipients_new_password)
    res.status(201) //  Created - The request succeeded, and a new resource was created as a result.
    return res.json ({
        message: "Successfully shared password"
    })


})

// expressJwt({secret: process.env.JWT_SECRET, algorithms: ["HS256"]})

// Should always come after defining your routes
app.listen(port_num, () => {
    console.log(`Listening on port ${port_num}`)
})

async function hashStr(str){
    const salt = await bcrypt.genSalt()
    return bcrypt.hash(str, salt)
}