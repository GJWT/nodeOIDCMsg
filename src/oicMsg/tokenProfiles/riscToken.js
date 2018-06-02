'use strict';
const Token = require('./token');
const Message = require('../message');

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
 * @extends Message
 * @param {*} jti
 * @param {*} iss
 * @param {*} sub
 * @param {*} iat
 */
class RiscToken extends Message {
  constructor({jti, iss, sub, iat}={}) {
    super();
    this.jti = jti;
    this.iss = iss;
    this.sub = sub;
    this.iat = iat;
    this.validateRequiredFields();

    this.optionsToPayload = [
      'jti',
      'iss',
      'sub',
      'iat',
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

    this.knownOptionalClaims = [
      'aud',
      'nbf',
      'exp',
    ];

    this.claimsForVerification = [
      'jti',
      'iss',
      'sub',
      'maxAge',
    ];
  }

  static init(payload, options){
    const riscToken = new RiscToken(payload);
    let optionalClaims = {};
    Object.keys(riscToken.knownOptionalClaims).forEach(key => {
      if (payload[key]){
        optionalClaims[key] = payload[key];
      }
    });
    riscToken.addOptionalClaims(optionalClaims);
    if (options && Object.keys(options).indexOf('algorithm')!== -1 && options['algorithm'] === 'none'){
      riscToken.setNoneAlgorithmAttr(true);
    }
    return riscToken;
  }

  static toJWT(payload, key, options){
    let riscToken = this.init(payload, options);
    return riscToken.toJWT(key, options);
  }

  static fromJWT(jwt, key, verificationClaims, options){
    let token = new Token();
    let decodedPayload = token.decode(jwt, key, options);
    let riscToken = this.init(decodedPayload);
    decodedPayload = riscToken.verify(decodedPayload, verificationClaims, options);
    return decodedPayload;
  }
}

module.exports = RiscToken;