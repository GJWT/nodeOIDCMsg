'use strict';

var RiscToken = require('./basicIdToken');  
var jwtDecoder = require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');
var jwtSigner = require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');

/**
 * RiscToken
 * Init token using standard claims 
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

/** Required standard claims */ 
RiscToken.prototype.options_to_payload = {
    'jti': 'jti',
    'iss': 'iss',
    'sub': 'sub',
    'iat': 'iat',
};
  
/** Other option values */
RiscToken.prototype.options_for_objects = [
    'expiresIn',
    'notBefore',
    'noTimestamp',
    'audience',
    'issuer',
    'subject',
    'jwtid',
];

/** Required known non standard claims */ 
RiscToken.prototype.knownNonStandardClaims = {
    'aud' : 'aud',
    'nbf' : 'nbf',
    'exp' : 'exp',
};

/** Standard claims that need to be verified */ 
RiscToken.prototype.claims_to_verify = {
    'jti': 'jti',
    'iss': 'iss',
    'sub': 'sub',
    'maxAge' : 'maxAge',
};

RiscToken.prototype.validateRequiredFields = function(){
    if (this.jti && this.iss && this.sub && this.iat){
        console.log("Validated all standard fields")
    }else {
        throw new Error("You are missing a required parameter");
    }
};

RiscToken.prototype.getStandardClaims = function(){
    RiscToken.prototype.standard_claims = { "jti": this.jti, "iss" : this.iss, "sub" : this.sub, "iat": this.iat};
    return RiscToken.prototype.standard_claims;         
};

RiscToken.prototype.initData = function(){
    RiscToken.prototype.non_standard_verification_claims = {};    
    RiscToken.prototype.NoneAlgorithm = false;
};


RiscToken.prototype.addNonStandardClaims = function(nonStandardClaims){
    RiscToken.prototype.non_standard_claims = nonStandardClaims;

    RiscToken.prototype.non_standard_verification_claims = {};
    Object.keys(nonStandardClaims).forEach(function (key) {
        if (RiscToken.prototype.knownNonStandardClaims[key]) {
            RiscToken.prototype.non_standard_verification_claims[key] = nonStandardClaims[key];
        }
    });  
};

RiscToken.prototype.getNonStandardClaims = function(nonStandardClaims){
    return RiscToken.prototype.non_standard_claims;
}; 

RiscToken.prototype.getVerificationClaims = function(){
    return RiscToken.prototype.verification_claims;
}; 

RiscToken.prototype.getNonStandardVerificationClaims = function(){
    return RiscToken.prototype.non_standard_verification_claims;
}; 

/** User explicitly wants to set None Algorithm attribute */
RiscToken.prototype.setNoneAlgorithm = function(boolVal){
    RiscToken.prototype.NoneAlgorithm = boolVal;
};

RiscToken.prototype.getNoneAlgorithm = function(boolVal){
    return RiscToken.prototype.NoneAlgorithm;
};

/** Deserialization of JWT type */ 
RiscToken.prototype.fromJWT = function(signedJWT, secretOrPrivateKey, claimsToVerify, options){

    this.validateRequiredVerificationClaims(claimsToVerify);
    this.validateRequiredNonStandardVerificationClaims(claimsToVerify);
    return jwtDecoder.decode(signedJWT,secretOrPrivateKey, this, options);
};

/** Throws error if required standard claims are missing */ 
RiscToken.prototype.validateRequiredVerificationClaims = function(claimsToVerify)
{
    Object.keys(RiscToken.prototype.claims_to_verify).forEach(function (key) {
        if (!claimsToVerify[key]) {
            throw new Error('Missing required verification claim: ' + key);
        }
      });  
      RiscToken.prototype.verification_claims = claimsToVerify;
};

/** Throws error if required non standard verification claims are missing */ 
RiscToken.prototype.validateRequiredNonStandardVerificationClaims = function(claimsToVerify)
{
    if (RiscToken.prototype.non_standard_verification_claims['nbf'] || BasicIdToken.prototype.non_standard_verification_claims['exp']){
        this.nonStandardVerificationClaimsCheck('clockTolerance', claimsToVerify);
    }
    if (RiscToken.prototype.non_standard_verification_claims['aud']){
        this.nonStandardVerificationClaimsCheck('aud', claimsToVerify);
    }
};

RiscToken.prototype.nonStandardVerificationClaimsCheck = function(key, claimsToVerify){
    if (!claimsToVerify[key]) {
        throw new Error('Missing required verification claim: ' + key);
    }else{
        RiscToken.prototype.verification_claims[key] = claimsToVerify[key];
        if (key == "aud"){
            RiscToken.prototype.claims_to_verify['aud'] = 'aud';
        }
    }
}

module.exports = RiscToken;

