'use strict';

var BasicIdToken = require('./basicIdToken');  
var jwtDecoder = require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');
var jwtSigner = require('../../controllers/messageTypes/jwt/jsonwebtoken/sign');

/**
 * @fileoverview
 * FacebookIdToken
 * Required claims : user_id, app_id, issued_at
 * Optional claims : expired_at
 */
/**
 * FacebookIdToken
 * Init token using required claims
 * @class
 * @constructor
 * @extends BasicIdToken
 * @param {*} userId 
 * @param {*} appId 
 * @param {*} issuedAt 
 */
function FacebookIdToken(userId, appId, issuedAt){
    this.userId = userId;
    this.appId = appId;
    this.iat = issuedAt;
    this.validateRequiredFields();
};

FacebookIdToken.prototype = Object.create(BasicIdToken.prototype);
FacebookIdToken.prototype.constructor = FacebookIdToken;

/** Required claims */ 
FacebookIdToken.prototype.optionsToPayload = {
    'userId' : 'userId',
    'appId' : 'appId',
    'iat' : 'iat',
  };
  
/** Other option values */
FacebookIdToken.prototype.optionsForObjects = [
    'expiresIn',
    'notBefore',
    'noTimestamp',
    'audience',
    'issuer',
    'subject',
    'jwtid',
  ];
 
/** Required verification claims */
FacebookIdToken.prototype.claimsForVerification = {
    'userId' : 'userId',
    'appId' : 'appId',
    'maxAge' : 'maxAge',
}; 

/** Known optional claims */
FacebookIdToken.prototype.knownOptionalClaims = {
    'expiredAt': 'expiredAt',
};

FacebookIdToken.prototype.validateRequiredFields = function(){
    if (this.userId && this.appId && this.iat){
        console.log("Validated all fields")
    }else{
        throw new Error("You are missing the required parameter : age");
    }
};

FacebookIdToken.prototype.getRequiredClaims = function(){
    FacebookIdToken.prototype.requiredClaims = { "userId" : this.userId, "appId" : this.appId, "iat" : this.iat};
    return FacebookIdToken.prototype.requiredClaims;         
};

FacebookIdToken.prototype.initData = function(){
    FacebookIdToken.prototype.optionalVerificationClaims = {};    
    FacebookIdToken.prototype.noneAlgorithm = false;
};

FacebookIdToken.prototype.addOptionalClaims = function(optionalClaims){
    FacebookIdToken.prototype.optionalClaims= optionalClaims;

    FacebookIdToken.prototype.optionalVerificationClaims = {};
    Object.keys(optionalClaims).forEach(function (key) {
        if (FacebookIdToken.prototype.knownOptionalClaims[key]) {
            FacebookIdToken.prototype.optionalVerificationClaims[key] = optionalClaims[key];
        }
    });  
};

FacebookIdToken.prototype.getOptionalClaims = function(optionalClaims){
    return FacebookIdToken.prototype.optionalClaims;
}; 

FacebookIdToken.prototype.getVerificationClaims = function(){
    return FacebookIdToken.prototype.verificationClaims;
}; 

FacebookIdToken.prototype.getOptionalVerificationClaims = function(){
    return FacebookIdToken.prototype.optionalVerificationClaims;
}; 

FacebookIdToken.prototype.setNoneAlgorithm = function(boolVal){
    FacebookIdToken.prototype.noneAlgorithm = boolVal;
};

FacebookIdToken.prototype.getNoneAlgorithm = function(boolVal){
    return FacebookIdToken.prototype.noneAlgorithm;
};

FacebookIdToken.prototype.toJWT = function(secretOrPrivateKey, options){
    return jwtSigner.sign(this, secretOrPrivateKey, options);
};

FacebookIdToken.prototype.fromJWT = function(signedJWT, secretOrPrivateKey, claimsToVerify, options){
    this.validateRequiredVerificationClaims(claimsToVerify);
    this.validateOptionalVerificationClaims(claimsToVerify);
    return jwtDecoder.decode(signedJWT, secretOrPrivateKey, this, options);
};

/* Throws error if missing required verification claims */
FacebookIdToken.prototype.validateRequiredVerificationClaims = function(claimsToVerify)
{
    Object.keys(FacebookIdToken.prototype.claimsForVerification).forEach(function (key) {
        if (!claimsToVerify[key]) {
            throw new Error('Missing required verification claim: ' + key);
        }
      });  
      FacebookIdToken.prototype.verificationClaims = claimsToVerify;
};

/** Throws error if missing optional claims */
FacebookIdToken.prototype.validateOptionalVerificationClaims = function(claimsToVerify)
{
    if (FacebookIdToken.prototype.optionalVerificationClaims['expiredAt']){
        this.optionalVerificationClaimsCheck('clockTolerance', claimsToVerify);
    }
};

FacebookIdToken.prototype.optionalVerificationClaimsCheck = function(key, claimsToVerify){
    if (!claimsToVerify[key]) {
        throw new Error('Missing required verification claim: ' + key);
    }else{
        FacebookIdToken.prototype.verificationClaims[key] = claimsToVerify[key];
    }
}

module.exports = FacebookIdToken;