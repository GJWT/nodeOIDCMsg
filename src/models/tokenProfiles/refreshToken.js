'use strict';

var BasicIdToken = require('./basicIdToken');  
var jwtDecoder = require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');
var jwtSigner = require('../../controllers/messageTypes/jwt/jsonwebtoken/sign');

/**
 * @fileoverview
 * RefreshToken
 * Required claims : refresh_token, access_token
 */
/**
 * RefreshToken
 * Init token using required claims
 * @class
 * @constructor
 * @extends BasicIdToken
 * @param {*} refreshToken
 * @param {*} accessToken
 */
function RefreshToken(refreshToken, accessToken){
    this.initData();        
    this.refreshToken = refreshToken;
    this.accessToken = accessToken;
    this.validateRequiredFields();
};

RefreshToken.prototype = Object.create(BasicIdToken.prototype);
RefreshToken.prototype.constructor = RefreshToken;

/** Required claims */
RefreshToken.prototype.requiredClaims = {};

/** Optional claims */ 
RefreshToken.prototype.optionalClaims = {};

RefreshToken.prototype.verificationClaims = {};

/** Expected optional verification claims that are known */
RefreshToken.prototype.optionalVerificationClaims = {};

RefreshToken.prototype.noneAlgorithm = false;

/** Required claims */ 
RefreshToken.prototype.optionsToPayload = {
    'refreshToken': 'refreshToken',
    'accessToken': 'accessToken',
};

/** Other option values */ 
RefreshToken.prototype.optionsForObjects = [
    'expiresIn',
    'notBefore',
    'noTimestamp',
    'audience',
    'issuer',
    'subject',
    'jwtid',
];

/** Known optional claims that need to be verified */ 
RefreshToken.prototype.knownOptionalClaims = {
    'knownOptionalClaim' : 'knownOptionalClaim',
};

/** Required claims to be verified */
RefreshToken.prototype.claimsForVerification = {
    'refreshToken': 'refreshToken',
    'accessToken': 'accessToken',
};

RefreshToken.prototype.initData = function(){
    RefreshToken.prototype.optionalVerificationClaims = {};    
    RefreshToken.prototype.noneAlgorithm = false;
};

/** Check for missing required claims */
RefreshToken.prototype.validateRequiredFields = function(){
    if (this.refreshToken && this.accessToken){
        console.log("Validated all required fields")
    }else {
        throw new Error("You are missing a required parameter");
    }
};

RefreshToken.prototype.getRequiredClaims = function(){
    RefreshToken.prototype.requiredClaims = { "refreshToken" : this.refreshToken, "accessToken" : this.accessToken};
    return RefreshToken.prototype.requiredClaims;         
};

RefreshToken.prototype.addOptionalClaims = function(optionalClaims){
    RefreshToken.prototype.optionalClaims = optionalClaims;

    RefreshToken.prototype.optionalVerificationClaims = {};
    Object.keys(optionalClaims).forEach(function (key) {
        if (RefreshToken.prototype.knownOptionalClaims[key]) {
            RefreshToken.prototype.optionalVerificationClaims[key] = optionalClaims[key];
        }
    });  
};

RefreshToken.prototype.getOptionalClaims = function(optionalClaims){
    return RefreshToken.prototype.optionalClaims;
};

/** Check for required verification claims that need to be verified */
RefreshToken.prototype.validateRequiredVerificationClaims = function(claimsToVerify)
{
    Object.keys(RefreshToken.prototype.claimsForVerification).forEach(function (key) {
        if (!claimsToVerify[key]) {
            throw new Error('Missing required verification claim: ' + key);
        }
      });  
      RefreshToken.prototype.verificationClaims = claimsToVerify;
};

/** Check for optional verification claims that need to be verified */
RefreshToken.prototype.validateOptionalVerificationClaims = function(claimsToVerify)
{
    if (RefreshToken.prototype.optionalVerificationClaims['exp']){
        this.optionalVerificationClaims('clockTolerance', claimsToVerify);
    }
    if (RefreshToken.prototype.optionalVerificationClaims['aud']){
        this.optionalVerificationClaims('aud', claimsToVerify);
    }
};

RefreshToken.prototype.optionalVerificationClaims = function(key, claimsToVerify){
    if (!claimsToVerify[key]) {
        throw new Error('Missing required verification claim: ' + key);
    }else{
        RefreshToken.prototype.verificationClaims[key] = claimsToVerify[key];
        if (key == "aud"){
            RefreshToken.prototype.claimsForVerification['aud'] = 'aud';
        }
    }
}

RefreshToken.prototype.toJWT = function(secretOrPrivateKey, options, callback){
    return jwtSigner.sign(this, secretOrPrivateKey, options, callback);
};

RefreshToken.prototype.fromJWT = function(signedJWT, secretOrPrivateKey, claimsToVerify, options){
    this.validateRequiredVerificationClaims(claimsToVerify);
    this.validateOptionalVerificationClaims(claimsToVerify);
    return jwtDecoder.decode(signedJWT,secretOrPrivateKey, this, options);
};


RefreshToken.prototype.getVerificationClaims = function(){
    return RefreshToken.prototype.verificationClaims;
}; 

module.exports = RefreshToken;