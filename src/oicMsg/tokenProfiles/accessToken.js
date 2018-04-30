'use strict';

const Message = require('../message');
const Token = require('./token');

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
 * @extends Message
 * @param {*} iss
 * @param {*} sub
 * @param {*} iat
 */
class AccessToken extends Message {
  constructor({iss, sub, iat}={}) {
    super();
    this.iss = iss;
    this.sub = sub;
    this.iat = iat;
    this.validateRequiredFields();

    /** Required claims */
    this.optionsToPayload = {
      iss: 'iss',
      sub: 'sub',
      iat: 'iat',
    };

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

    /** Known optional claims */
    this.knownOptionalClaims = {
      aud: 'aud',
      exp: 'exp',
    };
  }

  /** Validate required claims */
  validateRequiredFields() {
    if (!(this.iss && this.sub && this.iat)) {
      throw new Error('You are missing a required parameter');
    }
  }

  getRequiredClaims() {
    AccessToken.prototype
        .requiredClaims = {'iss': this.iss, 'sub': this.sub, 'iat': this.iat};
    return AccessToken.prototype.requiredClaims;
  }
  
  static init(payload, options){
    const accessToken = new AccessToken(payload);
    let optionalClaims = {};
    Object.keys(accessToken.knownOptionalClaims).forEach(key => {
      if (payload[key]){
        optionalClaims[key] = payload[key];
      }
    });
    accessToken.addOptionalClaims(optionalClaims);
    if (options && Object.keys(options).indexOf('algorithm')!== -1 && options['algorithm'] === 'none'){
      accessToken.setNoneAlgorithmAttr(true);
    }
    return accessToken;
  }

  static toJWT(payload, key, options){
    let accessToken = this.init(payload, options);
    return accessToken.toJWT(key, options);
  }

  static fromJWT(jwt, key, verificationClaims, options){
    let token = new Token();
    let decodedPayload = token.decode(jwt, key, options);
    let accessToken = this.init(decodedPayload);
    decodedPayload = accessToken.verify(decodedPayload, verificationClaims, options);
    return decodedPayload;
  }
}

module.exports = AccessToken;