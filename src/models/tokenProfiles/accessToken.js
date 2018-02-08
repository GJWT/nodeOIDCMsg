'use strict';

var BasicIdToken = require('./basicIdToken');  
var jwtDecoder = require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');
var jwtSigner = require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');


/**
 * @fileoverview 
 * AccessToken
 * Required claims : iss, sub, iat
 * Optional claims : aud, exp
 */

/**
 * AccessToken
 * Init token using required claims
 * @class
 * @constructor
 * @extends BasicIdToken
 * @param {*} iss
 * @param {*} sub
 * @param {*} iat
 */
function AccessToken(iss, sub, iat){
    this.iss = iss;
    this.sub = sub;
    this.iat = iat;
    this.validateRequiredFields();
};

AccessToken.prototype = Object.create(BasicIdToken.prototype);
AccessToken.prototype.constructor = AccessToken;

/** Required claims */
AccessToken.prototype.optionsToPayload = {
    'iss': 'iss',
    'sub': 'sub',
    'iat': 'iat',
};
  
/** Other option values */
AccessToken.prototype.optionsForObjects = [
    'expiresIn',
    'notBefore',
    'noTimestamp',
    'audience',
    'issuer',
    'subject',
    'jwtid',
];

/** Known optional claims */
AccessToken.prototype.knownOptionalClaims = {
    'aud': 'aud',
    'exp': 'exp',
};

/** Validate required claims */
AccessToken.prototype.validateRequiredFields = function(){
    if (this.iss && this.sub && this.iat){
        console.log("Validated all standard fields")
    }else {
        throw new Error("You are missing a required parameter");
    }
};

AccessToken.prototype.getRequiredClaims = function(){
    AccessToken.prototype.requiredClaims = { "iss" : this.iss, "sub" : this.sub, "iat": this.iat};
    return AccessToken.prototype.requiredClaims;         
};

module.exports = AccessToken;