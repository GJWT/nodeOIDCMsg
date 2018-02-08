'use strict';

var BasicIdToken = require('./basicIdToken');  
var jwtDecoder = require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');
var jwtSigner = require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');

/**
 * @fileoverview 
 * ImplicitAccessToken
 * Required claims : iss, sub, iat
 * Optional claims : aud
 */
/**
 * ImplicitAccessToken
 * Init token using required claims 
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

/** Required claims */
ImplicitAccessToken.prototype.optionsToPayload = {
    'iss': 'iss',
    'sub': 'sub',
    'iat': 'iat',
};
  
/** Other option values */
ImplicitAccessToken.prototype.optionsForObjects = [
    'expiresIn',
    'notBefore',
    'noTimestamp',
    'audience',
    'issuer',
    'subject',
    'jwtid',
];

/** Known optional claims that need to be verified */
ImplicitAccessToken.prototype.knownOptionalClaims = {
    'aud' : 'aud',
};

/** Required claims that need to be verified */ 
ImplicitAccessToken.prototype.claimsForVerification = {
    'iss': 'iss',
    'sub': 'sub',
    'maxAge' : 'maxAge',
};

/** Check for missing required claims */
ImplicitAccessToken.prototype.validateRequiredFields = function(){
    if (this.iss && this.sub && this.iat){
        console.log("Validated all required fields")
    }else {
        throw new Error("You are missing a required parameter");
    }
};

ImplicitAccessToken.prototype.getRequiredClaims = function(){
    ImplicitAccessToken.prototype.requiredClaims = { "iss" : this.iss, "sub" : this.sub, "iat": this.iat};
    return ImplicitAccessToken.prototype.requiredClaims;         
};

ImplicitAccessToken.prototype.initData = function(){
    ImplicitAccessToken.prototype.optionalVerificationClaims = {};    
    ImplicitAccessToken.prototype.noneAlgorithm = false;
};

ImplicitAccessToken.prototype.addOptionalClaims = function(optionalClaims){
    ImplicitAccessToken.prototype.optionalClaims = optionalClaims;

    ImplicitAccessToken.prototype.optionalVerificationClaims = {};
    Object.keys(optionalClaims).forEach(function (key) {
        if (ImplicitAccessToken.prototype.knownOptionalClaims[key]) {
            ImplicitAccessToken.prototype.optionalVerificationClaims[key] = optionalClaims[key];
        }
    });
};

ImplicitAccessToken.prototype.getOptionalClaims = function(optionalClaims){
    return ImplicitAccessToken.prototype.optionalClaims;
}; 

ImplicitAccessToken.prototype.getVerificationClaims = function(){
    return ImplicitAccessToken.prototype.verificationClaims;
}; 

ImplicitAccessToken.prototype.getOptionalVerificationClaims = function(){
    return ImplicitAccessToken.prototype.optionalVerificationClaims;
}; 

ImplicitAccessToken.prototype.setNoneAlgorithm = function(boolVal){
    ImplicitAccessToken.prototype.noneAlgorithm = boolVal;
};

ImplicitAccessToken.prototype.getNoneAlgorithm = function(boolVal){
    return ImplicitAccessToken.prototype.noneAlgorithm;
};

ImplicitAccessToken.prototype.fromJWT = function(signedJWT, secretOrPrivateKey, claimsToVerify, options){

    this.validateRequiredVerificationClaims(claimsToVerify);
    this.validateOptionalVerificationClaims(claimsToVerify);
    return jwtDecoder.decode(signedJWT,secretOrPrivateKey, this, options);
};

/** Throws error if missing required verification claims */
ImplicitAccessToken.prototype.validateRequiredVerificationClaims = function(claimsToVerify)
{
    Object.keys(ImplicitAccessToken.prototype.claimsForVerification).forEach(function (key) {
        if (!claimsToVerify[key]) {
            throw new Error('Missing required verification claim: ' + key);
        }
      });  
      ImplicitAccessToken.prototype.verificationClaims = claimsToVerify;
};

/** Throws error if missing optional claims */
ImplicitAccessToken.prototype.validateOptionalVerificationClaims = function(claimsToVerify)
{
    if (ImplicitAccessToken.prototype.optionalVerificationClaims['aud']){
        this.optionalVerificationClaimsCheck('aud', claimsToVerify);
    }
};

ImplicitAccessToken.prototype.optionalVerificationClaimsCheck = function(key, claimsToVerify){
    if (!claimsToVerify[key]) {
        throw new Error('Missing required verification claim: ' + key);
    }else{
        ImplicitAccessToken.prototype.verificationClaims[key] = claimsToVerify[key];
        if (key == "aud"){
            ImplicitAccessToken.prototype.claimsForVerification['aud'] = 'aud';
        }
    }
}

module.exports = ImplicitAccessToken;