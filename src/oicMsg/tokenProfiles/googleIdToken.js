'use strict';
const Message = require('../message');
const Token = require('./token');

/**
 * @fileoverview
 * GoogleIdToken
 * Required claims : name, email, picture, iss, sub, iat
 * Optional claims : exp, aud
 */

/**
 * GoogleIdToken
 * Init token using required claims
 * @class
 * @constructor
 * @extends Message
 * @param {*} name
 * @param {*} email
 * @param {*} picture
 * @param {*} iss
 * @param {*} sub
 * @param {*} iat
 */
class GoogleIdToken extends Message {
  constructor({name, email, picture, iss, sub, iat}={}) {
    super();
    this.name = name;
    this.email = email;
    this.picture = picture;
    this.iss = iss;
    this.sub = sub;
    this.iat = iat;
    this.validateRequiredFields();

     /** Required claims */
    this.optionsToPayload = [
      'name',
      'email',
      'picture',
      'iss',
      'sub',
      'iat',
    ];

    /** Known optional claims */
    this.knownOptionalClaims = [
      'exp',
      'aud',
    ];

    /** Required claims that need to be verified */
    this.claimsForVerification = [
      'name',
      'email',
      'picture',
      'iss',
      'sub',
      'maxAge',
    ];

    /** Other option values */
    this.optionsForObjects = [
      'expiresIn',
      'notBefore',
      'noTimestamp',
      'audience',
      'issuer',
      'subject',
      'jwtid',
    ];
  }

  static init(payload, options){
    const googleIdToken = new GoogleIdToken(payload);
    let optionalClaims = {};
    Object.keys(googleIdToken.knownOptionalClaims).forEach(key => {
      if (payload[key]){
        optionalClaims[key] = payload[key];
      }
    });
    googleIdToken.addOptionalClaims(optionalClaims);
    if (options && Object.keys(options).indexOf('algorithm')!== -1 && options['algorithm'] === 'none'){
      googleIdToken.setNoneAlgorithmAttr(true);
    }
    return googleIdToken;
  }

  static toJWT(payload, key, options){
    let googleIdToken = this.init(payload, options);
    return googleIdToken.toJWT(key, options);
  }

  static fromJWT(jwt, key, verificationClaims, options){
    let token = new Token();
    let decodedPayload = token.decode(jwt, key, options);
    let googleIdToken = this.init(decodedPayload);
    decodedPayload = googleIdToken.verify(decodedPayload, verificationClaims, options);
    return decodedPayload;
  }
}

module.exports = GoogleIdToken;