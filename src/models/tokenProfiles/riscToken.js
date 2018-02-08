'use strict';

var RiscToken = require('./basicIdToken');  
var jwtDecoder = require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');
var jwtSigner = require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');

/**
 * @fileoverview 
 * RiscToken
 * Required claims : jti, iss, sub, iat
 * Optional claims : aud, nbf, exp
 */
/**
 * RiscToken
 * Init token using required claims 
 * @class
 * @constructor
 * @extends BasicIdToken
 * @param {*} jti
 * @param {*} iss
 * @param {*} sub
 * @param {*} iat
 */
function RiscToken(jti, iss, sub, iat){
    this.jti = jti;
    this.iss = iss;
    this.sub = sub;
    this.iat = iat;
    this.validateRequiredFields();
};

RiscToken.prototype = Object.create(BasicIdToken.prototype);
RiscToken.prototype.constructor = RiscToken;

/** Required claims */ 
RiscToken.prototype.optionsToPayload = {
    'jti': 'jti',
    'iss': 'iss',
    'sub': 'sub',
    'iat': 'iat',
};
  
/** Other option values */
RiscToken.prototype.optionsForObjects = [
    'expiresIn',
    'notBefore',
    'noTimestamp',
    'audience',
    'issuer',
    'subject',
    'jwtid',
];

/** Required known optional claims */ 
RiscToken.prototype.knownOptionalClaims = {
    'aud' : 'aud',
    'nbf' : 'nbf',
    'exp' : 'exp',
};

/** Required claims that need to be verified */ 
RiscToken.prototype.claimsForVerification = {
    'jti': 'jti',
    'iss': 'iss',
    'sub': 'sub',
    'maxAge' : 'maxAge',
};

RiscToken.prototype.validateRequiredFields = function(){
    if (this.jti && this.iss && this.sub && this.iat){
        console.log("Validated all required fields")
    }else {
        throw new Error("You are missing a required parameter");
    }
};

RiscToken.prototype.getRequiredClaims = function(){
    RiscToken.prototype.requiredClaims = { "jti": this.jti, "iss" : this.iss, "sub" : this.sub, "iat": this.iat};
    return RiscToken.prototype.requiredClaims;         
};

RiscToken.prototype.initData = function(){
    RiscToken.prototype.optionalVerificationClaims = {};    
    RiscToken.prototype.noneAlgorithm = false;
};


RiscToken.prototype.addOptionalClaims = function(optionalClaims){
    RiscToken.prototype.optionalClaims = optionalClaims;

    RiscToken.prototype.optionalVerificationClaims = {};
    Object.keys(optionalClaims).forEach(function (key) {
        if (RiscToken.prototype.knownOptionalClaims[key]) {
            RiscToken.prototype.optionalVerificationClaims[key] = optionalClaims[key];
        }
    });  
};

RiscToken.prototype.getOptionalClaims = function(optionalClaims){
    return RiscToken.prototype.optionalClaims;
}; 

RiscToken.prototype.getVerificationClaims = function(){
    return RiscToken.prototype.verificationClaims;
}; 

RiscToken.prototype.getOptionalVerificationClaims = function(){
    return RiscToken.prototype.optionalVerificationClaims;
}; 

/** User explicitly wants to set None Algorithm attribute */
RiscToken.prototype.setNoneAlgorithm = function(boolVal){
    RiscToken.prototype.noneAlgorithm = boolVal;
};

RiscToken.prototype.getNoneAlgorithm = function(boolVal){
    return RiscToken.prototype.noneAlgorithm;
};

/** Deserialization of JWT type */ 
RiscToken.prototype.fromJWT = function(signedJWT, secretOrPrivateKey, claimsToVerify, options){

    this.validateRequiredVerificationClaims(claimsToVerify);
    this.validateOptionalVerificationClaims(claimsToVerify);
    return jwtDecoder.decode(signedJWT,secretOrPrivateKey, this, options);
};

/** Throws error if required claims are missing */ 
RiscToken.prototype.validateRequiredVerificationClaims = function(claimsToVerify)
{
    Object.keys(RiscToken.prototype.claimsForVerification).forEach(function (key) {
        if (!claimsToVerify[key]) {
            throw new Error('Missing required verification claim: ' + key);
        }
      });  
      RiscToken.prototype.verificationClaims = claimsToVerify;
};

/** Throws error if optional verification claims are missing */ 
RiscToken.prototype.validateOptionalVerificationClaims = function(claimsToVerify)
{
    if (RiscToken.prototype.optionalVerificationClaims['nbf'] || BasicIdToken.prototype.optionalVerificationClaims['exp']){
        this.optionalVerificationClaimsCheck('clockTolerance', claimsToVerify);
    }
    if (RiscToken.prototype.optionalVerificationClaims['aud']){
        this.optionalVerificationClaimsCheck('aud', claimsToVerify);
    }
};

RiscToken.prototype.optionalVerificationClaimsCheck = function(key, claimsToVerify){
    if (!claimsToVerify[key]) {
        throw new Error('Missing required verification claim: ' + key);
    }else{
        RiscToken.prototype.verificationClaims[key] = claimsToVerify[key];
        if (key == "aud"){
            RiscToken.prototype.claimsForVerification['aud'] = 'aud';
        }
    }
}

module.exports = RiscToken;