const express = require("express");
const mysql = require("mysql");
const cors = require("cors");

const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const session = require("express-session");

const bcrypt = require("bcrypt");
const saltRounds = 10;

// REQUIRE JSON WEB TOKEN 
const jwt = require('jsonwebtoken')

const app = express();

app.use(express.json());
app.use(
  cors({
    origin: ["http://localhost:3000"],
    methods: ["GET", "POST"],
    credentials: true,
  })
);
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(
  session({
    key: "userId",
    secret: "subscribe",
    resave: false,
    saveUninitialized: false,
    cookie: {
      expires: 60 * 60 * 24,
    },
  })
);

const db = mysql.createConnection({
  user: "root",
  host: "localhost",
  password: "password",
  database: "LoginSystem",
});

app.post("/register", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) {
      console.log(err);
    }

    db.query(
      "INSERT INTO users (username, password) VALUES (?,?)",
      [username, hash],
      (err, result) => {
        console.log(err);
      }
    );
  });
});

const verifyJWT = (req, res, next) => {
  const token = req.headers["x-access-token"]

  if (!token){
    res.send("Yo! we need a token, try again.")
  } else {
    jwt.verify(token, "jwtSecret", (err, decoded) => {
      if (err) {
        res.json({auth: false, message: "Failed to authenticate!"});
      } else {
        req.userId = decoded.id;
        next();
      }
    });
  }
};


// make a request to endpoint. pass in middleware we create, verifyJWT, to verify whenever we call this endpoint that 
// user has the correct endpoint. we have to aapply this same middleware to every other request because all other requests
// will be sensitive. make sure middleware is created above request!!!
app.get('/isUserAuth', verifyJWT, (req, res) => {
  res.send("Authentication Confirmed. OMW2FYB")
})

app.get("/login", (req, res) => {
  if (req.session.user) {
    res.send({ loggedIn: true, user: req.session.user });
  } else {
    res.send({ loggedIn: false });
  }
});

//grab user name and password to check authorization and check comparison between user and password
// create a session sends result.
app.post("/login", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  db.query(
    "SELECT * FROM users WHERE username = ?;",
    username,
    (err, result) => {
      if (err) {
        res.send({ err: err });
      }
// WHEN YOU LOG IN TO AN ACCOUNT YOU CREATE A TOKEN
      if (result.length > 0) {
        bcrypt.compare(password, result[0].password, (error, response) => {
          if (response) {
            // WE WANT THE ID BECAUSE WE NEED TO CREATE OUR TOKEN WITH THAT
            const id = result[0].id
            // IMPORTANT: WE NEED TO PUT jwtSecret from line 96 in the .env file and pass it in through a variable 
            const token = jwt.sign({id}, "jwtSecret", {
              // VALUE FOR TOKEN EXPIRATION 300= 5 minutes
              expiresIn: 300,
            })
            req.session.user = result;
            // WE HAVE TO SEND TOKEN TO FRONT END
          // check if user is authorized then pass token we createad and pass all results all info from users: id, username, role, group whatever.
            res.json({
              auth: true, 
              token: token, 
              result: result
            });
            console.log(req.session.user);
          } else {
            res.json({
              // if it exists but password is wrong send message
              auth: false, 
              message: "wrong username or password."
            });
          }
        });
      } else {
        // if it doesnt exist send message.
       res.json({
         auth: false, 
         message: "no user exists. please check user name or register."
        });
      }
    }
  );
});

app.listen(3001, () => {
  console.log("running server");
});