'use strict';

const fs = require('fs');
const jwt = require('jsonwebtoken');

var privateKEY  = fs.readFileSync('./private.key', 'utf8');
var publicKEY  = fs.readFileSync('./public.key', 'utf8');

module.exports = {
    sign: (payload, options) => {
        // SIGNING OPTIONS
        var signOptions = {
            issuer: options.issuer,
            subject: options.subject,
            audience: options.audience,
            expiresIn: "40000",
            algorithm: "RS256"
        };

        var token = jwt.sign(payload, privateKEY, signOptions);
        console.log("token is ...", token);
        return token;
    },

    verify: (token, options) => {
        var verifyOptions = {
            issuer: options.issuer,
            subject: options.subject,
            audience: options.audience,
            expiresIn: "40000",
            algorithm: ["RS256"]
        };
        
        try {
            return jwt.verify(token, publicKEY, verifyOptions);
        } catch (err) {
            console.log("err..", err);
            return false;
        }        
    },

    decode: (token) => {        
        return jwt.decode(token, { complete: true });
        //returns null if token is invalid
    }
};