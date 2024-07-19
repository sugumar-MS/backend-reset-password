const express = require('express');
const cors = require('cors');
const bcryptjs = require('bcryptjs');
const mongodb = require('mongodb');
const dotenv = require('dotenv').config();
const jwt = require('jsonwebtoken');
const rn = require('random-number');
const nodemailer = require("nodemailer");

const app = express();
app.use(express.json());
app.use(cors());

const mongoClient = mongodb.MongoClient;
const URL = process.env.MONGO_URL;
const usermail = process.env.USER;
const mailpassword = process.env.PASSWORD;
const SECRET_KEY = process.env.SECRET_KEY;
const PORT = process.env.PORT || 3000;

// Log the environment variables to ensure they are loaded correctly
// console.log("MongoDB URL:", URL);
// console.log("User Mail:", usermail);
// console.log("Mail Password:", mailpassword);
// console.log("Secret Key:", SECRET_KEY);
// console.log("Port:", PORT);

if (!URL || !usermail || !mailpassword || !SECRET_KEY) {
    throw new Error("Missing required environment variables");
}

const options = {
    min: 1000,
    max: 9999,
    integer: true
};

app.get("/", (req, res) => {
    res.send("Welcome to the password reset flow API");
});

//1 Register
app.post('/register', async (req, res) => {
    try {
        const { username, email, password1, password2 } = req.body;

        if (!username || !email || !password1 || !password2) {
            return res.status(400).json({ message: "All fields are required" });
        }

        if (password1 !== password2) {
            return res.status(400).json({ message: "Passwords do not match" });
        }

        const connection = await mongoClient.connect(URL);
        const db = connection.db('passwordreset');
        const salt = await bcryptjs.genSalt(10);
        const hash = await bcryptjs.hash(password1, salt);
        req.body.password1 = hash;
        delete req.body.password2;
        await db.collection('users').insertOne(req.body);
        await connection.close();
        res.json({ message: "User registered successfully" });
    } catch (error) {
        console.error("Error during registration:", error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});

//3 Login
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: "Username and password are required" });
        }

        const connection = await mongoClient.connect(URL);
        const db = connection.db('passwordreset');
        const user = await db.collection('users').findOne({ email });
        if (user) {
            const match = await bcryptjs.compare(password, user.password1);
            if (match) {
                const token = jwt.sign({ _id: user._id, name: user.email }, SECRET_KEY);
                res.status(200).json({
                    message: 'Successfully Logged in',
                    token: token,
                    name: user.username
                });
            } else {
                res.json({ message: 'Password Incorrect' });
            }
        } else {
            res.json({ message: 'User not found' });
        }
        await connection.close();
    } catch (error) {
        console.error("Error during login:", error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});

//4 Verification mail
app.post('/sendmail', async (req, res) => {
    try {
        const connection = await mongoClient.connect(URL);
        const db = connection.db('passwordreset');
        const user = await db.collection('users').findOne({ email: req.body.email });

        if (user) {
            let randomnum = rn(options);
            console.log("Generated verification code:", randomnum);

            await db.collection('users').updateOne({ email: req.body.email }, { $set: { rnum: randomnum } });

            let transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                    user: usermail,
                    pass: mailpassword,
                }
            });

            let mailOptions = {
                from: "msugumar832@gmail.com",
                to: req.body.email,
                subject: 'User verification',
                text: `Your verification code is: ${randomnum}`,
            };

            let info = await transporter.sendMail(mailOptions);
            console.log('Email sent: ' + info.response);

            res.json({ message: "Email sent" });
        } else {
            res.status(400).json({ message: 'User not found' });
        }

        await connection.close();
    } catch (error) {
        console.error("Error during sending mail:", error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});


// 5.Verify

app.post("/verify", async (req, res) => {
    try {
        const { email, vercode } = req.body;

        // Log the incoming request data
        console.log("Verification request received:", { email, vercode });

        if (!email || !vercode) {
            return res.status(400).json({ message: "Email and verification code are required" });
        }

        const connection = await mongoClient.connect(URL);
        const db = connection.db('passwordreset');
        const user = await db.collection('users').findOne({ email });

        if (user) {
            // Log the retrieved user data
            console.log("User found:", user);

            // Ensure both vercode and user.rnum are strings for comparison
            if (String(user.rnum) === String(vercode)) {
                // Reset the verification code after successful verification
                await db.collection('users').updateOne({ email }, { $unset: { rnum: "" } });
                await connection.close();
                console.log("Verification successful");
                res.status(200).json({ message: "Verification successful", user });
            } else {
                console.log("Invalid verification code provided:", vercode, "Expected:", user.rnum);
                await connection.close();
                res.status(400).json({ message: "Invalid Verification Code" });
            }
        } else {
            console.log("User not found with email:", email);
            await connection.close();
            res.status(400).json({ message: "User not found" });
        }
    } catch (error) {
        console.error("Error during verification:", error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});



//6 Update password
app.post('/changepassword/:id', async (req, res) => {
    try {
        const { password1, password2 } = req.body;
        const email = req.params.id;

        if (!email || !password1 || !password2) {
            return res.status(400).json({ message: "Email and passwords are required" });
        }

        if (password1 !== password2) {
            return res.status(400).json({ message: "Passwords do not match" });
        }

        const connection = await mongoClient.connect(URL);
        const db = connection.db('passwordreset');
        const salt = await bcryptjs.genSalt(10);
        const hash = await bcryptjs.hash(password1, salt);
        await db.collection('users').updateOne({ email }, { $set: { password1: hash } });
        await connection.close();
        res.json({ message: "Password updated successfully" });
    } catch (error) {
        console.error("Error during password update:", error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});

app.listen(PORT, () => console.log("Server is running at", PORT));
