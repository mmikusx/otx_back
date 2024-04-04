// server/server.js

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

app.use(express.json());

mongoose.connect('mongodb://localhost:2717/otx_db', { useNewUrlParser: true, useUnifiedTopology: true });

const userSchema = new mongoose.Schema({
    username: String,
    email: String,
    password: String,
    address: String,
    phone_number: String,
    orders: [
        {
            order_date: Date,
            status: String,
            total_cost: Number,
            items: [
                {
                    product_id: mongoose.Schema.Types.ObjectId,
                    quantity: Number,
                    buying_price: Number
                }
            ]
        }
    ]
});

const User = mongoose.model('User', userSchema);

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const user = await User.findOne({ username });

    if (!user) {
        console.log(`User not found for username: ${username}`);
        return res.status(400).send('User not found');
    }

    console.log(`Found user for username: ${username}`);

    // porównanie hasła
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
        console.log(`Invalid password for username: ${username}`);
        return res.status(400).send('Invalid password');
    }

    console.log(`Successful login for username: ${username}`);

    const token = jwt.sign({ _id: user._id }, 'SECRET_KEY');

    res.send({ token });
});

app.post('/register', async (req, res) => {
    const { username, email, password, address, phone_number } = req.body;

    console.log(`Received register request for username: ${username}`);

    const userExists = await User.findOne({ $or: [{ username }, { email }] });
    if (userExists) {
        console.log(`User already exists for username: ${username}`);
        return res.status(400).send('User already exists');
    }

    // haszowanie hasła
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = new User({ username, email, password: hashedPassword, address, phone_number });
    await user.save();

    console.log(`User registered successfully for username: ${username}`);

    res.send('User registered successfully');
});

app.listen(3000, () => console.log('Server started on port 3000'));