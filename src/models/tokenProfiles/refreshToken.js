'use strict';

var BasicIdToken = require('./basicIdToken');  
var jwtDecoder = require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');
var jwtSigner = require('../../controllers/messageTypes/jwt/jsonwebtoken/sign');

/* Init token using standard claims */ 
function RefreshToken(refresh_token, access_token){
    this.initData();        
    this.refresh_token = refresh_token;
    this.access_token = access_token;
    this.validateRequiredFields();
};

RefreshToken.prototype = Object.create(BasicIdToken.prototype);
RefreshToken.prototype.constructor = RefreshToken;

/* Provided standard claims */
RefreshToken.prototype.standard_claims = {};

/* Provided non standard claims */ 
RefreshToken.prototype.non_standard_claims = {};

RefreshToken.prototype.verification_claims = {};

/* Expected non standard verification claims that are known */
RefreshToken.prototype.non_standard_verification_claims = {};

RefreshToken.prototype.NoneAlgorithm = false;

/* Required standard claims */ 
RefreshToken.prototype.options_to_payload = {
    'refresh_token': 'refresh_token',
    'access_token': 'access_token',
};
  
/* Other option values */ 
RefreshToken.prototype.options_for_objects = [
    'expiresIn',
    'notBefore',
    'noTimestamp',
    'audience',
    'issuer',
    'subject',
    'jwtid',
];

/* Known non standard claims that need to be verified */ 
RefreshToken.prototype.knownNonStandardClaims = {
    'knownNonStandardClaim' : 'knownNonStandardClaim',
};

/* Required standard claims to be verified */
RefreshToken.prototype.claims_to_verify = {
    'refresh_token': 'refresh_token',
    'access_token': 'access_token',
};

RefreshToken.prototype.initData = function(){
    RefreshToken.prototype.non_standard_verification_claims = {};    
    RefreshToken.prototype.NoneAlgorithm = false;
};

RefreshToken.prototype.validateRequiredFields = function(){
    if (this.refresh_token && this.access_token){
        console.log("Validated all standard fields")
    }else {
        throw new Error("You are missing a required parameter");
    }
};

RefreshToken.prototype.getStandardClaims = function(){
    RefreshToken.prototype.standard_claims = { "refresh_token" : this.refresh_token, "access_token" : this.access_token};
    return RefreshToken.prototype.standard_claims;         
};

RefreshToken.prototype.addNonStandardClaims = function(nonStandardClaims){
    RefreshToken.prototype.non_standard_claims = nonStandardClaims;

    RefreshToken.prototype.non_standard_verification_claims = {};
    Object.keys(nonStandardClaims).forEach(function (key) {
        if (RefreshToken.prototype.knownNonStandardClaims[key]) {
            RefreshToken.prototype.non_standard_verification_claims[key] = nonStandardClaims[key];
        }
    });  
};

RefreshToken.prototype.getNonStandardClaims = function(nonStandardClaims){
    return RefreshToken.prototype.non_standard_claims;
};


/* Check for required verification claims that need to be verified */
RefreshToken.prototype.validateRequiredVerificationClaims = function(claimsToVerify)
{
    Object.keys(RefreshToken.prototype.claims_to_verify).forEach(function (key) {
        if (!claimsToVerify[key]) {
            throw new Error('Missing required verification claim: ' + key);
        }
      });  
      RefreshToken.prototype.verification_claims = claimsToVerify;
};

/* Check for required non standard verification claims that need to be verified */
RefreshToken.prototype.validateRequiredNonStandardVerificationClaims = function(claimsToVerify)
{
    if (RefreshToken.prototype.non_standard_verification_claims['exp']){
        this.nonStandardVerificationClaimsCheck('clockTolerance', claimsToVerify);
    }
    if (RefreshToken.prototype.non_standard_verification_claims['aud']){
        this.nonStandardVerificationClaimsCheck('aud', claimsToVerify);
    }

};

RefreshToken.prototype.nonStandardVerificationClaimsCheck = function(key, claimsToVerify){
    if (!claimsToVerify[key]) {
        throw new Error('Missing required verification claim: ' + key);
    }else{
        RefreshToken.prototype.verification_claims[key] = claimsToVerify[key];
        if (key == "aud"){
            RefreshToken.prototype.claims_to_verify['aud'] = 'aud';
        }
    }
}

/* Serialization of JWT type */
RefreshToken.prototype.toJWT = function(secretOrPrivateKey, options, callback){
    return jwtSigner.sign(this, secretOrPrivateKey, options, callback);
};

/* Deserialization of JWT type */
RefreshToken.prototype.fromJWT = function(signedJWT, secretOrPrivateKey, claimsToVerify, options){
    this.validateRequiredVerificationClaims(claimsToVerify);
    this.validateRequiredNonStandardVerificationClaims(claimsToVerify);
    return jwtDecoder.decode(signedJWT,secretOrPrivateKey, this, options);
};


RefreshToken.prototype.getVerificationClaims = function(){
    return RefreshToken.prototype.verification_claims;
}; 

module.exports = RefreshToken;

