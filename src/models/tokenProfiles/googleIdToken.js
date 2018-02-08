'use strict';

var jwtDecoder = require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');
var jwtSigner = require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');
var BasicIdToken = require('./basicIdToken');  

/**
 * @fileoverview 
 * GoogleIdToken
 * Required claims : name, email, picture, iss, sub, iat
 * Optional claims : exp, aud
 */

/**
 * GoogleIdToken
 * Init token using required claims
 * @class
 * @constructor
 * @extends BasicIdToken
 * @param {*} name
 * @param {*} email
 * @param {*} picture
 * @param {*} iss
 * @param {*} sub
 * @param {*} iat
 */ 
function GoogleIdToken(name, email, picture, iss, sub, iat){
    this.initData();        
    this.name = name;
    this.email = email;
    this.picture = picture;
    this.iss = iss;
    this.sub = sub;
    this.iat = iat;
    this.validateRequiredFields();
};

GoogleIdToken.prototype.requiredClaims = {};

GoogleIdToken.prototype.optionalClaims = {};

GoogleIdToken.prototype = Object.create(BasicIdToken.prototype);
GoogleIdToken.prototype.constructor = GoogleIdToken;

/** Required claims */
GoogleIdToken.prototype.optionsToPayload = {
    'name': 'name',
    'email': 'email',
    'picture': 'picture',
    'iss': 'iss',
    'sub': 'sub',
    'iat': 'iat',
};
  
/** Other option values */
GoogleIdToken.prototype.optionsForObjects = [
    'expiresIn',
    'notBefore',
    'noTimestamp',
    'audience',
    'issuer',
    'subject',
    'jwtid',
];

/** Known optional claims */
GoogleIdToken.prototype.knownOptionalClaims = {
    'exp' : 'exp',
    'aud' : 'aud',
};

/** Required claims that need to be verified */
GoogleIdToken.prototype.claimsForVerification = {
    'name': 'name',
    'email': 'email',
    'picture': 'picture',
    'iss': 'iss',
    'sub': 'sub',
    'maxAge' : 'maxAge',
};

GoogleIdToken.prototype.initData = function(){
    GoogleIdToken.prototype.optionalVerificationClaims = {};    
    GoogleIdToken.prototype.noneAlgorithm = false;
};

GoogleIdToken.prototype.addOptionalClaims = function(optionalClaims){
    GoogleIdToken.prototype.optionalClaims = optionalClaims;

    GoogleIdToken.prototype.optionalVerificationClaims = {};
    Object.keys(optionalClaims).forEach(function (key) {
        if (GoogleIdToken.prototype.knownOptionalClaims[key]) {
            GoogleIdToken.prototype.optionalVerificationClaims[key] = optionalClaims[key];
        }
    });  
};
GoogleIdToken.prototype.getOptionalClaims = function(optionalClaims){
    return GoogleIdToken.prototype.optionalClaims;
};


GoogleIdToken.prototype.getVerificationClaims = function(){
    return GoogleIdToken.prototype.verificationClaims;
}; 

GoogleIdToken.prototype.getOptionalVerificationClaims = function(){
    return GoogleIdToken.prototype.optionalVerificationClaims;
};

GoogleIdToken.prototype.validateRequiredFields = function(){
    if (this.name && this.email && this.picture && this.iss && this.sub && this.iat){
        console.log("Validated all required fields")
    }else {
        throw new Error("You are missing a required parameter");
    }
};

/* Deserialization for JWT type */
GoogleIdToken.prototype.fromJWT = function(signedJWT, secretOrPrivateKey, claimsToVerify, options){
        this.validateRequiredVerificationClaims(claimsToVerify);
        this.validateOptionalVerificationClaims(claimsToVerify);
        return jwtDecoder.decode(signedJWT,secretOrPrivateKey, this, options);
};

GoogleIdToken.prototype.getRequiredClaims = function(){
    GoogleIdToken.prototype.requiredClaims = {"name": this.name, "email" : this.email, "picture": this.picture,  "iss" : this.iss, "sub" : this.sub, "iat": this.iat};
    return GoogleIdToken.prototype.requiredClaims;         
};

/* Throws error if missing required verification claims */
GoogleIdToken.prototype.validateRequiredVerificationClaims = function(claimsToVerify)
{
    Object.keys(GoogleIdToken.prototype.claimsForVerification).forEach(function (key) {
        if (!claimsToVerify[key]) {
            throw new Error('Missing required verification claim: ' + key);
        }
      });  
    GoogleIdToken.prototype.verificationClaims = claimsToVerify;
};

/** Throws error if missing optional verification claims */
GoogleIdToken.prototype.validateOptionalVerificationClaims = function(claimsToVerify)
{
    if (GoogleIdToken.prototype.optionalVerificationClaims['exp']){
        this.OptionalVerificationClaimsCheck('clockTolerance', claimsToVerify);
    }
    if (GoogleIdToken.prototype.optionalVerificationClaims['aud']){
        this.OptionalVerificationClaimsCheck('aud', claimsToVerify);
    }
};

GoogleIdToken.prototype.OptionalVerificationClaimsCheck = function(key, claimsToVerify){
    if (!claimsToVerify[key]) {
        throw new Error('Missing required verification claim: ' + key);
    }else{
        GoogleIdToken.prototype.verificationClaims[key] = claimsToVerify[key];
        if (key == "aud"){
            GoogleIdToken.prototype.claimsForVerification['aud'] = 'aud';
        }
    }
}

module.exports = GoogleIdToken;