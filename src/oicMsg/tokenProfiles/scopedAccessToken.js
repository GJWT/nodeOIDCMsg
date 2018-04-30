'use strict';
const Message = require('../message');
const Token = require('./token');

/**
 * @fileoverview
 * Required claims : iss, sub, iat, scope
 * Optional claims : aud, exp
 */

/**
 * ScopedAccessToken
 * Init token using required claims
 * @class
 * @constructor
 * @extends AccessToken
 * @param {*} iss
 * @param {*} sub
 * @param {*} iat
 * @param {*} scope
 */
class ScopedAccessToken extends Message {
  constructor({iss, sub, iat, scope}={}) {
    super();
    this.iss = iss;
    this.sub = sub;
    this.iat = iat;
    this.scope = scope;
    this.validateRequiredFields();

    /** optional claims */
    this.optionsToPayload = {
      iss: 'iss',
      sub: 'sub',
      iat: 'iat',
      scope: 'scope',
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

    /** optional verification claims */
    this.claimsForVerification = {
      iss: 'iss',
      sub: 'sub',
      scope: 'scope',
      maxAge: 'maxAge',
    };
  }

  static init(payload, options){
    const scopedAccessToken = new ScopedAccessToken(payload);
    let optionalClaims = {};
    Object.keys(scopedAccessToken.knownOptionalClaims).forEach(key => {
      if (payload[key]){
        optionalClaims[key] = payload[key];
      }
    });
    scopedAccessToken.addOptionalClaims(optionalClaims);
    if (options && Object.keys(options).indexOf('algorithm')!== -1 && options['algorithm'] === 'none'){
      scopedAccessToken.setNoneAlgorithmAttr(true);
    }
    return scopedAccessToken;
  }

  static toJWT(payload, key, options){
    let scopedAccessToken = this.init(payload, options);
    return scopedAccessToken.toJWT(key, options);
  }

  static fromJWT(jwt, key, verificationClaims, options){
    let token = new Token();
    let decodedPayload = token.decode(jwt, key, options);
    let scopedAccessToken = this.init(decodedPayload);
    decodedPayload = scopedAccessToken.verify(decodedPayload, verificationClaims, options);
    return decodedPayload;
  }
}

module.exports = ScopedAccessToken;