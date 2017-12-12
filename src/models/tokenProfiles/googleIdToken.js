'use strict';

var jwtDecoder = require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');
var jwtSigner = require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');
var BasicIdToken = require('./basicIdToken');  

/* Init token using standard claims */ 
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

GoogleIdToken.prototype.standard_claims = {};

GoogleIdToken.prototype.non_standard_claims = {};

GoogleIdToken.prototype = Object.create(BasicIdToken.prototype);
GoogleIdToken.prototype.constructor = GoogleIdToken;

/* Required standard claims */
GoogleIdToken.prototype.options_to_payload = {
    'name': 'name',
    'email': 'email',
    'picture': 'picture',
    'iss': 'iss',
    'sub': 'sub',
    'iat': 'iat',
};
  
/* Other option values */
GoogleIdToken.prototype.options_for_objects = [
    'expiresIn',
    'notBefore',
    'noTimestamp',
    'audience',
    'issuer',
    'subject',
    'jwtid',
];

/* Required known non standard claims */
GoogleIdToken.prototype.knownNonStandardClaims = {
    'exp' : 'exp',
    'aud' : 'aud',
};

/* Required standard claims that need to be verified */
GoogleIdToken.prototype.claims_to_verify = {
    'name': 'name',
    'email': 'email',
    'picture': 'picture',
    'iss': 'iss',
    'sub': 'sub',
    'maxAge' : 'maxAge',
};

GoogleIdToken.prototype.initData = function(){
    GoogleIdToken.prototype.non_standard_verification_claims = {};    
    GoogleIdToken.prototype.NoneAlgorithm = false;
};

GoogleIdToken.prototype.addNonStandardClaims = function(nonStandardClaims){
    GoogleIdToken.prototype.non_standard_claims = nonStandardClaims;

    GoogleIdToken.prototype.non_standard_verification_claims = {};
    Object.keys(nonStandardClaims).forEach(function (key) {
        if (GoogleIdToken.prototype.knownNonStandardClaims[key]) {
            GoogleIdToken.prototype.non_standard_verification_claims[key] = nonStandardClaims[key];
        }
    });  
};
GoogleIdToken.prototype.getNonStandardClaims = function(nonStandardClaims){
    return GoogleIdToken.prototype.non_standard_claims;
};


GoogleIdToken.prototype.getVerificationClaims = function(){
    return GoogleIdToken.prototype.verification_claims;
}; 

GoogleIdToken.prototype.getNonStandardVerificationClaims = function(){
    return GoogleIdToken.prototype.non_standard_verification_claims;
};

GoogleIdToken.prototype.validateRequiredFields = function(){
    if (this.name && this.email && this.picture && this.iss && this.sub && this.iat){
        console.log("Validated all standard fields")
    }else {
        throw new Error("You are missing a required parameter");
    }
};

/* Deserialization for JWT type */
GoogleIdToken.prototype.fromJWT = function(signedJWT, secretOrPrivateKey, claimsToVerify, options){
        this.validateRequiredVerificationClaims(claimsToVerify);
        this.validateRequiredNonStandardVerificationClaims(claimsToVerify);
        return jwtDecoder.decode(signedJWT,secretOrPrivateKey, this, options);
};

GoogleIdToken.prototype.getStandardClaims = function(){
    GoogleIdToken.prototype.standard_claims = {"name": this.name, "email" : this.email, "picture": this.picture,  "iss" : this.iss, "sub" : this.sub, "iat": this.iat};
    return GoogleIdToken.prototype.standard_claims;         
};

/* Throws error if missing required standard verification claims */
GoogleIdToken.prototype.validateRequiredVerificationClaims = function(claimsToVerify)
{
    Object.keys(GoogleIdToken.prototype.claims_to_verify).forEach(function (key) {
        if (!claimsToVerify[key]) {
            throw new Error('Missing required verification claim: ' + key);
        }
      });  
    GoogleIdToken.prototype.verification_claims = claimsToVerify;
};

/* Throws error if missing required non standard verification claims */
GoogleIdToken.prototype.validateRequiredNonStandardVerificationClaims = function(claimsToVerify)
{
    if (GoogleIdToken.prototype.non_standard_verification_claims['exp']){
        this.nonStandardVerificationClaimsCheck('clockTolerance', claimsToVerify);
    }
    if (GoogleIdToken.prototype.non_standard_verification_claims['aud']){
        this.nonStandardVerificationClaimsCheck('aud', claimsToVerify);
    }
};


GoogleIdToken.prototype.nonStandardVerificationClaimsCheck = function(key, claimsToVerify){
    if (!claimsToVerify[key]) {
        throw new Error('Missing required verification claim: ' + key);
    }else{
        GoogleIdToken.prototype.verification_claims[key] = claimsToVerify[key];
        if (key == "aud"){
            GoogleIdToken.prototype.claims_to_verify['aud'] = 'aud';
        }
    }
}

module.exports = GoogleIdToken;

