'use strict';

var jwtDecoder = require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');
var jwtSigner = require('../../controllers/messageTypes/jwt/jsonwebtoken/sign');

/**
 * @fileoverview 
 * BasicIdToken
 * Required claims : iss, sub, iat, jti
 * Optional claims : aud, exp, nbf
 */

/**
 * BasicIdToken
 * Init token using required claims
 * @class
 * @constructor
 * @param {*} iss
 * @param {*} sub
 * @param {*} iat
 * @param {*} jti
 */
function BasicIdToken(iss, sub, iat, jti){
    this.initData();    
    this.iss = iss;
    this.sub = sub;
    this.iat = iat;
    this.jti = jti
    this.validateRequiredFields();
};

/** Provided required claims */
BasicIdToken.prototype.requiredClaims = {};

/** Provided optional claims */ 
BasicIdToken.prototype.optionalClaims = {};

/** Expected required verification claims */
BasicIdToken.prototype.verificationClaims = {};

/** Expected optional verification claims that are known */
BasicIdToken.prototype.optionalVerificationClaims = {};

BasicIdToken.prototype.noneAlgorithm = false;

/** Required claims */
BasicIdToken.prototype.optionsToPayload = {
    'iss': 'iss',
    'sub': 'sub',
    'iat': 'iat',
    'jti': 'jti',
};
  
/** Other option values */ 
BasicIdToken.prototype.optionsForObjects = [
    'expiresIn',
    'notBefore',
    'noTimestamp',
    'audience',
    'issuer',
    'subject',
    'jwtid',
];

/** Known required claims */
BasicIdToken.prototype.knownOptionalClaims = {
    'aud': 'aud',
    'exp': 'exp',
    'nbf': 'nbf',
};

/** Required verification claims */
BasicIdToken.prototype.claimsForVerification = {
    'iss': 'iss',
    'sub': 'sub',
    'maxAge' : 'maxAge',
    'jti': 'jti',
};

BasicIdToken.prototype.initData = function(){
    BasicIdToken.prototype.optionalVerificationClaims = {};    
    BasicIdToken.prototype.noneAlgorithm = false;
};

/** Check for missing required claims */
BasicIdToken.prototype.validateRequiredFields = function(){

    if (this.iss && this.sub && this.iat && this.jti){
        console.log("Validated all required fields")
    }else {
        throw new Error("You are missing a required parameter");
    }
};

/** Add optional claims */
BasicIdToken.prototype.addOptionalClaims = function(optionalClaims){
    BasicIdToken.prototype.optionalClaims = optionalClaims;

    BasicIdToken.prototype.optionalVerificationClaims = {};
    Object.keys(optionalClaims).forEach(function (key) {
        if (BasicIdToken.prototype.knownOptionalClaims[key]) {
            BasicIdToken.prototype.optionalVerificationClaims[key] = optionalClaims[key];
        }
    });  
};

/** Fetch required claims */
BasicIdToken.prototype. getRequiredClaims = function(){
    BasicIdToken.prototype.requiredClaims = { "iss" : this.iss, "sub" : this.sub, "iat": this.iat, "jti": this.jti};
    return BasicIdToken.prototype.requiredClaims;         
};

/** Fetch optional claims */
BasicIdToken.prototype.getOptionalClaims = function(optionalClaims){
    return BasicIdToken.prototype.optionalClaims;
}; 

BasicIdToken.prototype.getVerificationClaims = function(){
    return BasicIdToken.prototype.verificationClaims;
}; 

BasicIdToken.prototype.getOptionalVerificationClaims = function(){
    return BasicIdToken.prototype.optionalVerificationClaims;
}; 

/** User explicitly wants to set None Algorithm attribute */
BasicIdToken.prototype.setNoneAlgorithm = function(boolVal){
    BasicIdToken.prototype.noneAlgorithm = boolVal;
};

BasicIdToken.prototype.getNoneAlgorithm = function(boolVal){
    return BasicIdToken.prototype.noneAlgorithm;
};

/** Serialization of JWT type */
BasicIdToken.prototype.toJWT = function(secretOrPrivateKey, options, callback){
    return jwtSigner.sign(this, secretOrPrivateKey, options, callback);
};

/** Deserialization of JWT type */
BasicIdToken.prototype.fromJWT = function(signedJWT, secretOrPrivateKey, claimsToVerify, options, callback){

    this.validateRequiredVerificationClaims(claimsToVerify);
    this.validateOptionalVerificationClaims(claimsToVerify);
    return jwtDecoder.decode(signedJWT,secretOrPrivateKey, this, options, callback);
};

/** Throws error if required verification claims are not present */ 
BasicIdToken.prototype.validateRequiredVerificationClaims = function(claimsToVerify)
{
    Object.keys(BasicIdToken.prototype.claimsForVerification).forEach(function (key) {
        if (!claimsToVerify[key]) {
            throw new Error('Missing required verification claim: ' + key);
        }
      });  
    BasicIdToken.prototype.verificationClaims = claimsToVerify;
};

/** Throws error if optional verification claims are not present */ 
BasicIdToken.prototype.validateOptionalVerificationClaims = function(claimsToVerify)
{
    if (BasicIdToken.prototype.optionalVerificationClaims['nbf'] || BasicIdToken.prototype.optionalVerificationClaims['exp']){
        this.optionalVerificationClaimsCheck('clockTolerance', claimsToVerify);
    }
    if (BasicIdToken.prototype.optionalVerificationClaims['aud']){
        this.optionalVerificationClaimsCheck('aud', claimsToVerify);
    }
};

BasicIdToken.prototype.optionalVerificationClaimsCheck = function(key, claimsToVerify){
    if (!claimsToVerify[key]) {
        throw new Error('Missing required verification claim: ' + key);
    }else{
        BasicIdToken.prototype.verificationClaims[key] = claimsToVerify[key];
        if (key == "aud"){
            BasicIdToken.prototype.claimsForVerification['aud'] = 'aud';
        }
    }
}

/** Serialization of JSON type */
BasicIdToken.prototype.toJSON = function(){
    var obj = Object.assign({}, this. getRequiredClaims(), this.getOptionalClaims());
    return JSON.stringify(obj);
};

/** Deserialization of JSON type */
BasicIdToken.prototype.fromJSON = function(jsonString){
    return JSON.parse(jsonString);
};

/** Serialization of URL Encoded type */
BasicIdToken.prototype.toUrlEncoded = function(){
    var obj = Object.assign({}, this. getRequiredClaims(), this.getOptionalClaims());
    var str = [];
    for(var p in obj)
        str.push(encodeURIComponent(p) + "=" + encodeURIComponent(obj[p]));
    return str.join("&");
}

/** Deserialization of URL Encoded type */
BasicIdToken.prototype.fromUrlEncoded = function(urlEncodedString){
    var obj = {}; 
    urlEncodedString.replace(/([^=&]+)=([^&]*)/g, function(m, key, value) {
        obj[decodeURIComponent(key)] = decodeURIComponent(value);
    }); 
    return obj;
};

module.exports = BasicIdToken;