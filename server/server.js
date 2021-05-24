//loads env variable (secret access token) into our process
require('dotenv').config()

const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const PORT = process.env.PORT || 5000;

//creating an instance of jwt library (npm install jsonwebtoken first!)
const jwt = require('jsonwebtoken')

//for Auth, creates an instance of bcrypt library for salting/hashing passwords
const bcrypt = require('bcrypt')

/** ---------- MIDDLEWARE ---------- **/
app.use(bodyParser.json()); // needed for axios requests
app.use(express.static('build'));

//lets our app use json from the req body
app.use(express.json())

//test data
const posts = [
    {
        username: 'Kyle',
        title: 'Post 1'
    },
    {
        username: 'Shyla',
        title: 'Post 2'
    },
]

//stores refresh tokens on sever. NOT FOR PRODUCTION, store on DB instead.
let refreshTokens = []

//array for Auth. for production store users on DB
const users = []

/** ---------- TODO - EXPRESS ROUTES ---------- **/
//Auth get route
app.get ('/users', (req, res) => {
    res.json(users)
})

//Auth post route for password salting/hashing
app.post('/users', async (req, res) => {
    try {
        //const salt = await bcrypt.genSalt(10)
        const hashedPassword = await bcrypt.hash(req.body.password, 10) //salt
        //console.log(salt);
        //console.log(hashedPassword);
        const user = { name: req.body.name, password: hashedPassword } //req.body.password
        users.push(user)
        res.status(201).send()
    } catch {
        res.sendStatus(500)
    }
})

//Auth post route for login
app.post('/users/login', async (req, res) => {
    //match the user to one from our array
    const user = users.find(user => user.name = req.body.name)
    if(user == null){
        return res.status(400).send('Cannot find user')
    }
    //comparison for password checking original password matches hashed password
    //adding await checks that passwords are the same and that user is logged in
    try {
        if(await bcrypt.compare(req.body.password, user.password)) {
        } else {
            res.send('Not Allowed!')
        }
    } catch {
        res.status(500).send()
    }
})

//JWT create a get route, test in postman, to know our app is working
app.get('/posts', (req, res) => {
    //req.user
    //res.json(posts)
    //only return the post that the user has access to
    req.json(posts.filter(post => post.username === req.user.name))
})

//JWT to send a new token instance/refresh token
app.post('/token', (req, res) => {
    const refreshToken = req.body.token 
    if(refreshToken == null) return res.sendStatus(401)
    //do we have a valid refresh token for this refresh?
    if(!refreshTokens.includes(refreshToken)) return res.sendStatus(403)
    //verify token
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if(err) return res.sendStatus(403)
        //need to pass user.name to only send that info
        const accessToken = generateAccessToken({ name: user.name })
        res.json({ accessToken: accessToken })
    })
})

//JWT to delete access to infinite refresh tokens
app.delete('/logout', (req, res) => {
    //checking refreshTokens array above, CANNOT do this if tokens are in a DB
    refreshTokens = refreshTokens.filter(token => token !== req.body.token)
    //msg that token is sucessfully deleted
    res.sendStatus(204)
})

//JWT authenticates token after the user has been authenticated
app.post('/login', authenticateToken, (req, res) => {
    //Authenticate User here (watch other tutorial w/ bcrypt salt/hash passwords)
    
    //this user has already been authenticated, in theory
    const username = req.body.username
    
    //create object to serialize w jwt
    const user = {name: username}
    
    //authenticate and serialize the user with jwt ACCESS_TOKEN_SECRET in .env file
    //const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET) BEFORE creating generate token function
    const accessToken = generateAccessToken(user)

    //refresh token 
    const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)
    
    //adds refresh tokens to server array
    refreshTokens.push(refreshToken)

    //creates access to the token/refresh token for an authenticated user
    res.json({ accessToken: accessToken, refreshToken: refreshToken})
})

//JWT authenticates token header
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization']
    
    //variable for Bearer TOKEN returning index 1, the token, and checking
    //that there is a token or returning undefined if there is not
    const token = authHeader && authHeader.split(' ')[1]
    //Bearer TOKEN
    //indicates that a token has not been sent yet
    if(token == null) return res.sendStatus(401)

    //verify valid token and secret. callback for err and user (from post)
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        //error lets user know they don't have access bc token is no longer valid
        if(err) return res.sendStatus(403)
        //when we get here, we know we have a valid token, set user to request
        req.user = user
        //let's us move past our middleware and can call req.user in get route
        next()
    })
}

//around 15m this server is tested and working.
//A second server is created only to create, delete and refresh tokens.
//It only handles log in, log out, and refresh tokens. No post routes.

//JWT function lives on an auth server to generate access tokens includes exp
function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '15s'})
}

/** ---------- START SERVER ---------- **/
app.listen(PORT,  () => {
    console.log('Listening on port: ', PORT);
});