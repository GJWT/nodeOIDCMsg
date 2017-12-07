var JsonWebTokenError = require('./lib/JsonWebTokenError');
var NotBeforeError    = require('./lib/NotBeforeError');
var TokenExpiredError = require('./lib/TokenExpiredError');
var decode            = require('./decode');
var timespan          = require('./lib/timespan');
var xtend             = require('xtend');
var messageVerifier = require('../../../message/verify');

/* Calls super class' verification method */ 
var jwtVerifier= JWTVerifier.prototype;
jwtVerifier = Object.create(messageVerifier);
jwtVerifier.constructor = JWTVerifier;

function JWTVerifier(){
};

module.exports = jwtVerifier;