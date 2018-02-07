'use strict';

var BasicIdToken = require('./basicIdToken');  
var jwtDecoder = require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');
var jwtSigner = require('../../controllers/messageTypes/jwt/jsonwebtoken/sign');

/**
 * FacebookIdToken
 * Init token using standard claims
 * @class
 * @constructor
 * @extends BasicIdToken
 * @param {*} user_id 
 * @param {*} app_id 
 * @param {*} issued_at 
 */
function FacebookIdToken(user_id, app_id, issued_at){
    this.userId = user_id;
    this.appId = app_id;
    this.iat = issued_at;
    this.validateRequiredFields();
};

FacebookIdToken.prototype = Object.create(BasicIdToken.prototype);
FacebookIdToken.prototype.constructor = FacebookIdToken;

/** Required standard claims */ 
FacebookIdToken.prototype.options_to_payload = {
    'userId' : 'userId',
    'appId' : 'appId',
    'iat' : 'iat',
  };
  
/** Other option values */
FacebookIdToken.prototype.options_for_objects = [
    'expiresIn',
    'notBefore',
    'noTimestamp',
    'audience',
    'issuer',
    'subject',
    'jwtid',
  ];
 
/** Required standard verification claims */
FacebookIdToken.prototype.claims_to_verify = {
    'userId' : 'userId',
    'appId' : 'appId',
    'maxAge' : 'maxAge',
}; 

/** Known non standard claims */
FacebookIdToken.prototype.knownNonStandardClaims = {
    'expired_at': 'expired_at',
};


FacebookIdToken.prototype.validateRequiredFields = function(){
    if (this.userId && this.appId && this.iat){
        console.log("Validated all fields")
    }else{
        throw new Error("You are missing the required parameter : age");
    }
};

FacebookIdToken.prototype.getStandardClaims = function(){
    FacebookIdToken.prototype.standard_claims = { "userId" : this.userId, "appId" : this.appId, "iat" : this.iat};
    return FacebookIdToken.prototype.standard_claims;         
};


FacebookIdToken.prototype.initData = function(){
    FacebookIdToken.prototype.non_standard_verification_claims = {};    
    FacebookIdToken.prototype.NoneAlgorithm = false;
};


FacebookIdToken.prototype.addNonStandardClaims = function(nonStandardClaims){
    FacebookIdToken.prototype.non_standard_claims = nonStandardClaims;

    FacebookIdToken.prototype.non_standard_verification_claims = {};
    Object.keys(nonStandardClaims).forEach(function (key) {
        if (FacebookIdToken.prototype.knownNonStandardClaims[key]) {
            FacebookIdToken.prototype.non_standard_verification_claims[key] = nonStandardClaims[key];
        }
    });  
};

FacebookIdToken.prototype.getNonStandardClaims = function(nonStandardClaims){
    return FacebookIdToken.prototype.non_standard_claims;
}; 

FacebookIdToken.prototype.getVerificationClaims = function(){
    return FacebookIdToken.prototype.verification_claims;
}; 

FacebookIdToken.prototype.getNonStandardVerificationClaims = function(){
    return FacebookIdToken.prototype.non_standard_verification_claims;
}; 

/** User explicitly wants to set None Algorithm attribute */
FacebookIdToken.prototype.setNoneAlgorithm = function(boolVal){
    FacebookIdToken.prototype.NoneAlgorithm = boolVal;
};

FacebookIdToken.prototype.getNoneAlgorithm = function(boolVal){
    return FacebookIdToken.prototype.NoneAlgorithm;
};

/** Serialization for JWT type */
FacebookIdToken.prototype.toJWT = function(secretOrPrivateKey, options){
    return jwtSigner.sign(this, secretOrPrivateKey, options);
};

/** Deserialization for JWT type */
FacebookIdToken.prototype.fromJWT = function(signedJWT, secretOrPrivateKey, claimsToVerify, options){
    this.validateRequiredVerificationClaims(claimsToVerify);
    this.validateRequiredNonStandardVerificationClaims(claimsToVerify);
    return jwtDecoder.decode(signedJWT, secretOrPrivateKey, this, options);
};

/* Throws error if missing required verification claims */
FacebookIdToken.prototype.validateRequiredVerificationClaims = function(claimsToVerify)
{
    Object.keys(FacebookIdToken.prototype.claims_to_verify).forEach(function (key) {
        if (!claimsToVerify[key]) {
            throw new Error('Missing required verification claim: ' + key);
        }
      });  
      FacebookIdToken.prototype.verification_claims = claimsToVerify;
};

/** Throws error if missing required non standard claims */
FacebookIdToken.prototype.validateRequiredNonStandardVerificationClaims = function(claimsToVerify)
{
    if (FacebookIdToken.prototype.non_standard_verification_claims['expired_at']){
        this.nonStandardVerificationClaimsCheck('clockTolerance', claimsToVerify);
    }
};

FacebookIdToken.prototype.nonStandardVerificationClaimsCheck = function(key, claimsToVerify){
    if (!claimsToVerify[key]) {
        throw new Error('Missing required verification claim: ' + key);
    }else{
        FacebookIdToken.prototype.verification_claims[key] = claimsToVerify[key];
    }
}

module.exports = FacebookIdToken;

