'use strict';

var BasicIdToken = require('./basicIdToken');  
var jwtDecoder = require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');
var jwtSigner = require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');

/**
 * ImplicitAccessToken
 * Init token using standard claims 
 * @class
 * @constructor
 * @extends BasicIdToken
 * @param {*} iss
 * @param {*} sub
 * @param {*} iat
 */
function ImplicitAccessToken(iss, sub, iat){
    this.iss = iss;
    this.sub = sub;
    this.iat = iat;
    this.validateRequiredFields();
};

ImplicitAccessToken.prototype = Object.create(BasicIdToken.prototype);
ImplicitAccessToken.prototype.constructor = ImplicitAccessToken;

/** Required standard claims */
ImplicitAccessToken.prototype.options_to_payload = {
    'iss': 'iss',
    'sub': 'sub',
    'iat': 'iat',
};
  
/** Other option values */
ImplicitAccessToken.prototype.options_for_objects = [
    'expiresIn',
    'notBefore',
    'noTimestamp',
    'audience',
    'issuer',
    'subject',
    'jwtid',
];

/** Known non standard claims that need to be verified */
ImplicitAccessToken.prototype.knownNonStandardClaims = {
    'aud' : 'aud',
};

/** Required standard claims that need to be verified */ 
ImplicitAccessToken.prototype.claims_to_verify = {
    'iss': 'iss',
    'sub': 'sub',
    'maxAge' : 'maxAge',
};

/** Check for missing required claims */
ImplicitAccessToken.prototype.validateRequiredFields = function(){
    if (this.iss && this.sub && this.iat){
        console.log("Validated all standard fields")
    }else {
        throw new Error("You are missing a required parameter");
    }
};

ImplicitAccessToken.prototype.getStandardClaims = function(){
    ImplicitAccessToken.prototype.standard_claims = { "iss" : this.iss, "sub" : this.sub, "iat": this.iat};
    return ImplicitAccessToken.prototype.standard_claims;         
};

ImplicitAccessToken.prototype.initData = function(){
    ImplicitAccessToken.prototype.non_standard_verification_claims = {};    
    ImplicitAccessToken.prototype.NoneAlgorithm = false;
};

ImplicitAccessToken.prototype.addNonStandardClaims = function(nonStandardClaims){
    ImplicitAccessToken.prototype.non_standard_claims = nonStandardClaims;

    ImplicitAccessToken.prototype.non_standard_verification_claims = {};
    Object.keys(nonStandardClaims).forEach(function (key) {
        if (ImplicitAccessToken.prototype.knownNonStandardClaims[key]) {
            ImplicitAccessToken.prototype.non_standard_verification_claims[key] = nonStandardClaims[key];
        }
    });  
};

ImplicitAccessToken.prototype.getNonStandardClaims = function(nonStandardClaims){
    return ImplicitAccessToken.prototype.non_standard_claims;
}; 

ImplicitAccessToken.prototype.getVerificationClaims = function(){
    return ImplicitAccessToken.prototype.verification_claims;
}; 

ImplicitAccessToken.prototype.getNonStandardVerificationClaims = function(){
    return ImplicitAccessToken.prototype.non_standard_verification_claims;
}; 

ImplicitAccessToken.prototype.setNoneAlgorithm = function(boolVal){
    ImplicitAccessToken.prototype.NoneAlgorithm = boolVal;
};

ImplicitAccessToken.prototype.getNoneAlgorithm = function(boolVal){
    return ImplicitAccessToken.prototype.NoneAlgorithm;
};

ImplicitAccessToken.prototype.fromJWT = function(signedJWT, secretOrPrivateKey, claimsToVerify, options){

    this.validateRequiredVerificationClaims(claimsToVerify);
    this.validateRequiredNonStandardVerificationClaims(claimsToVerify);
    return jwtDecoder.decode(signedJWT,secretOrPrivateKey, this, options);
};

/** Throws error if missing required verification claims */
ImplicitAccessToken.prototype.validateRequiredVerificationClaims = function(claimsToVerify)
{
    Object.keys(ImplicitAccessToken.prototype.claims_to_verify).forEach(function (key) {
        if (!claimsToVerify[key]) {
            throw new Error('Missing required verification claim: ' + key);
        }
      });  
      ImplicitAccessToken.prototype.verification_claims = claimsToVerify;
};

/** Throws error if missing required non standard claims */
ImplicitAccessToken.prototype.validateRequiredNonStandardVerificationClaims = function(claimsToVerify)
{
    if (ImplicitAccessToken.prototype.non_standard_verification_claims['aud']){
        this.nonStandardVerificationClaimsCheck('aud', claimsToVerify);
    }
};

ImplicitAccessToken.prototype.nonStandardVerificationClaimsCheck = function(key, claimsToVerify){
    if (!claimsToVerify[key]) {
        throw new Error('Missing required verification claim: ' + key);
    }else{
        ImplicitAccessToken.prototype.verification_claims[key] = claimsToVerify[key];
        if (key == "aud"){
            ImplicitAccessToken.prototype.claims_to_verify['aud'] = 'aud';
        }
    }
}

module.exports = ImplicitAccessToken;

