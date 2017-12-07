'use strict';

var BasicIdToken = require('./basicIdToken');  
var jwtDecoder = require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');
var jwtSigner = require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');

/* Init token using standard claims */ 
function AccessToken(iss, sub, iat){
    this.iss = iss;
    this.sub = sub;
    this.iat = iat;
    this.validateRequiredFields();
};

AccessToken.prototype = Object.create(BasicIdToken.prototype);
AccessToken.prototype.constructor = AccessToken;

/* Required standard claims */
AccessToken.prototype.options_to_payload = {
    'iss': 'iss',
    'sub': 'sub',
    'iat': 'iat',
};
  
/* Other option values */
AccessToken.prototype.options_for_objects = [
    'expiresIn',
    'notBefore',
    'noTimestamp',
    'audience',
    'issuer',
    'subject',
    'jwtid',
];

/* Known non standard claims */
AccessToken.prototype.knownNonStandardClaims = {
    'aud': 'aud',
    'exp': 'exp',
};

AccessToken.prototype.validateRequiredFields = function(){
    if (this.iss && this.sub && this.iat){
        console.log("Validated all standard fields")
    }else {
        throw new Error("You are missing a required parameter");
    }
};

AccessToken.prototype.getStandardClaims = function(){
    AccessToken.prototype.standard_claims = { "iss" : this.iss, "sub" : this.sub, "iat": this.iat};
    return AccessToken.prototype.standard_claims;         
};

module.exports = AccessToken;

