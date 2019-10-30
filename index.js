const express = require("express");
const mysql = require('mysql');
const session = require('express-session'); //https://www.npmjs.com/package/express-session
const bodyParser = require('body-parser');
const path = require('path');
const cors = require('cors');

const tokenLib = require('./token');

const app = express();

const connection = mysql.createConnection({
    host     : '127.0.0.1',
    port     : '3306',   
	user     : 'root',
	password : 'root',
	database : 'store'
});

app.use(session({
	secret: 'secret', // This is the secret used to sign the session ID cookie. it can be any string or array of string 
	resave: true,
	saveUninitialized: true
}));
app.use(bodyParser.urlencoded({extended : true}));
app.use(bodyParser.json());

app.use(cors({
    "origin": "*",
    "methods": "GET,HEAD,PUT,PATCH,POST,DELETE",
    "preflightContinue": false,
    "optionsSuccessStatus": 206
}));

var AppUserAuth = {
    userName:'',
    bearerToken:'',
    isAuthenticated:false,
    userAccess:{
        canAccessHome:false,
        canAccessProduct:false
    }
};

//console.log("AppUserAuth in server...", AppUserAuth);

app.get("/", function(req, res){
    //console.log(req);
	/*res.setHeader('Content-Type', 'text/plain');
    res.end('You\'re in reception');*/
    res.sendFile(path.join(__dirname + '/login.html'));
});

function getUserAccessInfo(userid, callback) {
    //console.log("getUserAccessInfo...", userid, AppUserAuth);    
    if(userid) {
        connection.query("SELECT * FROM access_info WHERE user_id=?", [userid], function(error, results, fields){
            //console.log("acess results...", results);
            results.forEach(element => {
                //console.log("+++", element);
                if(element.access_type ==  'canAccessHome') {
                    AppUserAuth.userAccess.canAccessHome = element.access_value;
                } else if(element.access_type ==  'canAccessProduct') {
                    AppUserAuth.userAccess.canAccessProduct = element.access_value;
                }
            });
            //console.log("1 after...", AppUserAuth); 
            //return AppUserAuth;    // node will not work this way       
            callback(AppUserAuth); // this will "return" your value to the original caller
        });
        //console.log("2 after...", AppUserAuth); 
       // return AppUserAuth;
    }
}

app.post("/auth", function(req, res){
    const username = req.body.username;
    const password = req.body.password;
    //console.log(req.body);
    if(username && password) {
        connection.query("SELECT * FROM login WHERE username=? and password=?", [username, password], function(error, results, fields){
            //console.log("result...", results);
            if(results.length > 0) {
                //console.log("sesssion..", req.session);
                req.session.loggedIn = true;
                req.session.username = username;                          
                getUserAccessInfo(results[0].userid, function(AppUserAuth) {
                    //console.log("returned value...", AppUserAuth);
                    AppUserAuth.isAuthenticated = req.session.loggedIn;
                    AppUserAuth.userName = req.session.username;
                    var options = {
                        issuer: "server",
                        subject: AppUserAuth.userName,
                        audience:''
                    }
                    //console.log("options...", options);

                    AppUserAuth.bearerToken = tokenLib.sign({userName:AppUserAuth.userName}, options);
                    res.status(200).json(AppUserAuth);
                    res.end();
                });
            } else {
                //res.send('Incorrect Username and/or Password!');
                res.status(500).json({ error: 'Incorrect Username and/or Password!' });
                res.end();
            }            
        });
    } else {
        /*res.status(500);
        res.send("Please enter username and password");*/
        res.status(500).json({ error: 'Please enter username and password' });
        res.end();
    }
});

app.get('/home', function(request, response) {
    //console.log(request.session);
	if (request.session.loggedIn) {
        //response.send('Welcome back, ' + request.session.username + '!');
        response.send(AppUserAuth);
	} else {
		response.send('Please login to view this page!');
	}
	response.end();
});

app.get('/product/:id', function(req, res){
    console.log(req.header('bearerToken'));
    var options = {
        issuer: "server",
        subject: AppUserAuth.userName,
        audience:''
    }
    //console.log(tokenLib.verify(req.header('bearerToken'), options));
    if(tokenLib.verify(req.header('bearerToken'), options)) {
        res.status(200).json({"allowAccess": true});
        res.end();
    } else {
        res.status(500).json({ error: 'invalid token' });
        res.end();
    }
});




app.listen(3000, () => console.log('Example app listening on port 3000!'));
