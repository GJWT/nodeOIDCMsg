'use strict';

var GoogleIdToken = require('./googleIdToken');  
var jwtDecoder = require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');
var jwtSigner = require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');

/**
 * @fileoverview 
 * AccessToken
 * Required claims : name, email, picture, iss, sub, iat
 * Optional claims : aud, exp, nbf
 */

/**
 * ExtendedIdToken
 * Init token using required claims
 * @class
 * @constructor
 * @extends GoogleIdToken
 * @param {*} name
 * @param {*} email
 * @param {*} picture
 * @param {*} iss
 * @param {*} sub
 * @param {*} iat
 */
function ExtendedIdToken(name, email, picture, iss, sub, iat){
    this.initData();
    this.name = name;
    this.email = email;
    this.picture = picture;
    this.iss = iss;
    this.sub = sub;
    this.iat = iat;
    this.validateRequiredFields();
};

ExtendedIdToken.prototype = Object.create(GoogleIdToken.prototype);
ExtendedIdToken.prototype.constructor = ExtendedIdToken;

/** Required claims */
ExtendedIdToken.prototype.optionsToPayload = {
    'name': 'name',
    'email': 'email',
    'picture': 'picture',
    'iss': 'iss',
    'sub': 'sub',
    'iat': 'iat',
};

/** Other options values */
ExtendedIdToken.prototype.optionsForObjects = [
    'expiresIn',
    'notBefore',
    'noTimestamp',
    'audience',
    'issuer',
    'subject',
    'jwtid',
];

/** Known optional claims to be verified */
ExtendedIdToken.prototype.knownOptionalClaims = {
    'aud': 'aud',
    'exp': 'exp',
    'nbf': 'nbf',
};

/** Required claims to be verified */
ExtendedIdToken.prototype.claimsForVerification = {
    'name': 'name',
    'email': 'email',
    'picture': 'picture',
    'iss': 'iss',
    'sub': 'sub',
    'maxAge' : 'maxAge',
};

/* Check for missing requiredclaims */
ExtendedIdToken.prototype.validateRequiredFields = function(){
    if (this.name && this.email && this.picture && this.iss && this.sub && this.iat){
        console.log("Validated all requiredfields")
    }else {
        throw new Error("You are missing a requiredparameter");
    }
};

ExtendedIdToken.prototype.getRequiredClaims = function(){
    ExtendedIdToken.prototype.requiredClaims = {"name": this.name, "email" : this.email, "picture": this.picture,  "iss" : this.iss, "sub" : this.sub, "iat": this.iat};
    return ExtendedIdToken.prototype.requiredClaims;         
};

ExtendedIdToken.prototype.initData = function(){
    ExtendedIdToken.prototype.optionalVerificationClaims = {};    
    ExtendedIdToken.prototype.noneAlgorithm = false;
};

ExtendedIdToken.prototype.addOptionalClaims = function(optionalClaims){
    ExtendedIdToken.prototype.optionalClaims = optionalClaims;

    ExtendedIdToken.prototype.optionalVerificationClaims = {};
    Object.keys(optionalClaims).forEach(function (key) {
        if (ExtendedIdToken.prototype.knownOptionalClaims[key]) {
            ExtendedIdToken.prototype.optionalVerificationClaims[key] = optionalClaims[key];
        }
    });  
};
ExtendedIdToken.prototype.getOptionalClaims = function(optionalClaims){
    return ExtendedIdToken.prototype.optionalClaims;
};


ExtendedIdToken.prototype.getVerificationClaims = function(){
    return ExtendedIdToken.prototype.verificationClaims;
}; 

ExtendedIdToken.prototype.getOptionalVerificationClaims = function(){
    return ExtendedIdToken.prototype.optionalVerificationClaims;
};

ExtendedIdToken.prototype.fromJWT = function(signedJWT, secretOrPrivateKey, claimsToVerify, options){
        this.validateRequiredVerificationClaims(claimsToVerify);
        this.validateOptionalVerificationClaims(claimsToVerify);
        return jwtDecoder.decode(signedJWT,secretOrPrivateKey, this, options);
};

/** Check for required verification claims that need to be verified */
ExtendedIdToken.prototype.validateRequiredVerificationClaims = function(claimsToVerify)
{
    Object.keys(ExtendedIdToken.prototype.claimsForVerification).forEach(function (key) {
        if (!claimsToVerify[key]) {
            throw new Error('Missing requiredverification claim: ' + key);
        }
      });  
      ExtendedIdToken.prototype.verificationClaims = claimsToVerify;
};

/** Check for optional claims that need to be verified */
ExtendedIdToken.prototype.validateOptionalVerificationClaims = function(claimsToVerify)
{
    if (ExtendedIdToken.prototype.optionalVerificationClaims['exp']){
        this.optionalVerificationClaimsCheck('clockTolerance', claimsToVerify);
    }
    if (ExtendedIdToken.prototype.optionalVerificationClaims['aud']){
        this.optionalVerificationClaimsCheck('aud', claimsToVerify);
    }

};

ExtendedIdToken.prototype.optionalVerificationClaimsCheck = function(key, claimsToVerify){
    if (!claimsToVerify[key]) {
        throw new Error('Missing requiredverification claim: ' + key);
    }else{
        ExtendedIdToken.prototype.verificationClaims[key] = claimsToVerify[key];
        if (key == "aud"){
            ExtendedIdToken.prototype.claimsForVerification['aud'] = 'aud';
        }
    }
}

module.exports = ExtendedIdToken;