'use strict';

var AccessToken = require('./accessToken');  
var jwtDecoder = require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');
var jwtSigner = require('../../controllers/messageTypes/jwt/jsonwebtoken/sign');

/**
 * @fileoverview 
 * Required claims : iss, sub, iat, scope
 * Optional claims : aud, exp
 */

/**
 * ScopedAccessToken
 * Init token using required claims
 * @class
 * @constructor
 * @extends AccessToken
 * @param {*} iss
 * @param {*} sub
 * @param {*} iat
 * @param {*} scope
 */
function ScopedAccessToken(iss, sub, iat, scope){
    this.iss = iss;
    this.sub = sub;
    this.iat = iat;
    this.scope = scope;
    this.validateRequiredFields();
};

ScopedAccessToken.prototype = Object.create(AccessToken.prototype);
ScopedAccessToken.prototype.constructor = AccessToken;

/** optional claims */
ScopedAccessToken.prototype.optionsToPayload = {
    'iss': 'iss',
    'sub': 'sub',
    'iat': 'iat',
    'scope': 'scope',
};

/** Other option values */
ScopedAccessToken.prototype.optionsForObjects = [
    'expiresIn',
    'notBefore',
    'noTimestamp',
    'audience',
    'issuer',
    'subject',
    'jwtid',
];

/** Known optional claims */ 
ScopedAccessToken.prototype.knownOptionalClaims = {
    'aud' : 'aud',
    'exp' : 'exp',
};

/** optional verification claims */
ScopedAccessToken.prototype.claimsForVerification = {
    'iss': 'iss',
    'sub': 'sub',
    'scope': 'scope',
    'maxAge' : 'maxAge',
};

/** Check for missing required claims */
ScopedAccessToken.prototype.validateRequiredFields = function(){
    if (this.iss && this.sub && this.iat && this.scope){
        console.log("Validated all required fields")
    }else {
        throw new Error("You are missing a required parameter");
    }
};

ScopedAccessToken.prototype.getRequiredClaims = function(){
    ScopedAccessToken.prototype.requiredClaims = { "iss" : this.iss, "sub" : this.sub, "iat": this.iat, "scope" : this.scope};
    return ScopedAccessToken.prototype.requiredClaims;         
};

ScopedAccessToken.prototype.initData = function(){
    ScopedAccessToken.prototype.optionalVerificationClaims = {};    
    ScopedAccessToken.prototype.noneAlgorithm = false;
};

ScopedAccessToken.prototype.addOptionalClaims = function(optionalClaims){
    ScopedAccessToken.prototype.optionalClaims = optionalClaims;

    ScopedAccessToken.prototype.optionalVerificationClaims = {};
    Object.keys(optionalClaims).forEach(function (key) {
        if (ScopedAccessToken.prototype.knownOptionalClaims[key]) {
            ScopedAccessToken.prototype.optionalVerificationClaims[key] = optionalClaims[key];
        }
    });  
};

ScopedAccessToken.prototype.getOptionalClaims = function(optionalClaims){
    return ScopedAccessToken.prototype.optionalClaims;
}; 

ScopedAccessToken.prototype.getVerificationClaims = function(){
    return ScopedAccessToken.prototype.verificationClaims;
}; 

ScopedAccessToken.prototype.getOptionalVerificationClaims = function(){
    return ScopedAccessToken.prototype.optionalVerificationClaims;
}; 

ScopedAccessToken.prototype.setNoneAlgorithm = function(boolVal){
    ScopedAccessToken.prototype.noneAlgorithm = boolVal;
};

ScopedAccessToken.prototype.getNoneAlgorithm = function(boolVal){
    return ScopedAccessToken.prototype.noneAlgorithm;
};

ScopedAccessToken.prototype.toJWT = function(secretOrPrivateKey, options, callback){
    return jwtSigner.sign(this, secretOrPrivateKey, options, callback);
};

/** Deserialization for JWT type */ 
ScopedAccessToken.prototype.fromJWT = function(signedJWT, secretOrPrivateKey, claimsToVerify, options){
    this.validateRequiredVerificationClaims(claimsToVerify);
    this.validateOptionalVerificationClaims(claimsToVerify);
    return jwtDecoder.decode(signedJWT, secretOrPrivateKey, this, options);
};

/** Throw error if missing optional verification claims */ 
ScopedAccessToken.prototype.validateRequiredVerificationClaims = function(claimsToVerify)
{
    Object.keys(ScopedAccessToken.prototype.claimsForVerification).forEach(function (key) {
        if (!claimsToVerify[key]) {
            throw new Error('Missing required verification claim: ' + key);
        }
      });  
      ScopedAccessToken.prototype.verificationClaims = claimsToVerify;
};

/** Throw error if missing required optional verification claims */ 
ScopedAccessToken.prototype.validateOptionalVerificationClaims = function(claimsToVerify)
{
    if (ScopedAccessToken.prototype.optionalVerificationClaims['exp']){
        this.optionalVerificationClaimsCheck('clockTolerance', claimsToVerify);
    }
    if (ScopedAccessToken.prototype.optionalVerificationClaims['aud']){
        this.optionalVerificationClaimsCheck('aud', claimsToVerify);
    }
};

ScopedAccessToken.prototype.optionalVerificationClaimsCheck = function(key, claimsToVerify){
    if (!claimsToVerify[key]) {
        throw new Error('Missing required verification claim: ' + key);
    }else{
        ScopedAccessToken.prototype.verificationClaims[key] = claimsToVerify[key];
    }
}

module.exports = ScopedAccessToken;