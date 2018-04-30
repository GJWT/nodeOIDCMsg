'use strict';
const Token = require('./token');
const Message = require('../message');

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
 * @extends Message
 * @param {*} refreshToken
 * @param {*} accessToken
 */
class RefreshToken extends Message {
  constructor({refreshToken, accessToken}={}) {
    super();
    this.refreshToken = refreshToken;
    this.accessToken = accessToken;
    this.validateRequiredFields();

    /** Required claims */
    this.optionsToPayload = {
      refreshToken: 'refreshToken',
      accessToken: 'accessToken',
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

    /** Known optional claims that need to be verified */
    this.knownOptionalClaims = {
      knownOptionalClaim: 'knownOptionalClaim',
    };

    /** Required claims to be verified */
    this.claimsForVerification = {
      refreshToken: 'refreshToken',
      accessToken: 'accessToken',
    };
  }

  static init(payload, options){
    const refreshToken = new RefreshToken(payload);
    let optionalClaims = {};
    Object.keys(RefreshToken.knownOptionalClaims).forEach(key => {
      if (payload[key]){
        optionalClaims[key] = payload[key];
      }
    });
    refreshToken.addOptionalClaims(optionalClaims);
    if (options && Object.keys(options).indexOf('algorithm')!== -1 && options['algorithm'] === 'none'){
      refreshToken.setNoneAlgorithmAttr(true);
    }
    return refreshToken;
  }

  static toJWT(payload, key, options){
    let refreshToken = this.init(payload, options);
    return refreshToken.toJWT(key, options);
  }

  static fromJWT(jwt, key, verificationClaims, options){
    let token = new Token();
    let decodedPayload = token.decode(jwt, key, options);
    let refreshToken = this.init(decodedPayload);
    decodedPayload = refreshToken.verify(decodedPayload, verificationClaims, options);
    return decodedPayload;
  }
}

module.exports = RefreshToken;