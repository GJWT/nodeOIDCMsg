'use strict';

var AccessToken = require('./accessToken');  
var jwtDecoder = require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');
var jwtSigner = require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');

/* Init token using standard claims */ 
function ScopedAccessToken(iss, sub, iat, scope){
    this.iss = iss;
    this.sub = sub;
    this.iat = iat;
    this.scope = scope;
    this.validateRequiredFields();
};

ScopedAccessToken.prototype = Object.create(AccessToken.prototype);
ScopedAccessToken.prototype.constructor = AccessToken;

/* Required standard claims */
ScopedAccessToken.prototype.options_to_payload = {
    'iss': 'iss',
    'sub': 'sub',
    'iat': 'iat',
    'scope': 'scope',
};
  
/* Other option values */
ScopedAccessToken.prototype.options_for_objects = [
    'expiresIn',
    'notBefore',
    'noTimestamp',
    'audience',
    'issuer',
    'subject',
    'jwtid',
];

/* Known non standard claims */ 
ScopedAccessToken.prototype.knownNonStandardClaims = {
    'aud' : 'aud',
    'exp' : 'exp',
};

/* Required standard verification claims */
ScopedAccessToken.prototype.claims_to_verify = {
    'iss': 'iss',
    'sub': 'sub',
    'scope': 'scope',
    'maxAge' : 'maxAge',
};

ScopedAccessToken.prototype.validateRequiredFields = function(){
    if (this.iss && this.sub && this.iat && this.scope){
        console.log("Validated all standard fields")
    }else {
        throw new Error("You are missing a required parameter");
    }
};

ScopedAccessToken.prototype.getStandardClaims = function(){
    ScopedAccessToken.prototype.standard_claims = { "iss" : this.iss, "sub" : this.sub, "iat": this.iat, "scope" : this.scope};
    return ScopedAccessToken.prototype.standard_claims;         
};

ScopedAccessToken.prototype.initData = function(){
    ScopedAccessToken.prototype.non_standard_verification_claims = {};    
    ScopedAccessToken.prototype.NoneAlgorithm = false;
};

ScopedAccessToken.prototype.addNonStandardClaims = function(nonStandardClaims){
    ScopedAccessToken.prototype.non_standard_claims = nonStandardClaims;

    ScopedAccessToken.prototype.non_standard_verification_claims = {};
    Object.keys(nonStandardClaims).forEach(function (key) {
        if (ScopedAccessToken.prototype.knownNonStandardClaims[key]) {
            ScopedAccessToken.prototype.non_standard_verification_claims[key] = nonStandardClaims[key];
        }
    });  
};

ScopedAccessToken.prototype.getNonStandardClaims = function(nonStandardClaims){
    return ScopedAccessToken.prototype.non_standard_claims;
}; 

ScopedAccessToken.prototype.getVerificationClaims = function(){
    return ScopedAccessToken.prototype.verification_claims;
}; 

ScopedAccessToken.prototype.getNonStandardVerificationClaims = function(){
    return ScopedAccessToken.prototype.non_standard_verification_claims;
}; 

/* User explicitly wants to set None Algorithm attribute */
ScopedAccessToken.prototype.setNoneAlgorithm = function(boolVal){
    ScopedAccessToken.prototype.NoneAlgorithm = boolVal;
};

ScopedAccessToken.prototype.getNoneAlgorithm = function(boolVal){
    return ScopedAccessToken.prototype.NoneAlgorithm;
};

/* Deserialization for JWT type */ 
ScopedAccessToken.prototype.fromJWT = function(signedJWT, secretOrPrivateKey, claimsToVerify, options){
    this.validateRequiredVerificationClaims(claimsToVerify);
    this.validateRequiredNonStandardVerificationClaims(claimsToVerify);
    return jwtDecoder.decode(signedJWT, secretOrPrivateKey, this, options);
};

/* Throw error if missing required standard verification claims */ 
ScopedAccessToken.prototype.validateRequiredVerificationClaims = function(claimsToVerify)
{
    Object.keys(ScopedAccessToken.prototype.claims_to_verify).forEach(function (key) {
        if (!claimsToVerify[key]) {
            throw new Error('Missing required verification claim: ' + key);
        }
      });  
      ScopedAccessToken.prototype.verification_claims = claimsToVerify;
};

/* Throw error if missing required non standard verification claims */ 
ScopedAccessToken.prototype.validateRequiredNonStandardVerificationClaims = function(claimsToVerify)
{
    if (ScopedAccessToken.prototype.non_standard_verification_claims['exp']){
        this.nonStandardVerificationClaimsCheck('clockTolerance', claimsToVerify);
    }
    if (ScopedAccessToken.prototype.non_standard_verification_claims['aud']){
        this.nonStandardVerificationClaimsCheck('aud', claimsToVerify);
    }
};

ScopedAccessToken.prototype.nonStandardVerificationClaimsCheck = function(key, claimsToVerify){
    if (!claimsToVerify[key]) {
        throw new Error('Missing required verification claim: ' + key);
    }else{
        ScopedAccessToken.prototype.verification_claims[key] = claimsToVerify[key];
    }
}

module.exports = ScopedAccessToken;

