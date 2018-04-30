'use strict';
const Message = require('../message');
const Token = require('./token');

/**
 * @fileoverview
 * FacebookIdToken
 * Required claims : user_id, app_id, issued_at
 * Optional claims : expired_at
 */
/**
 * FacebookIdToken
 * Init token using required claims
 * @class
 * @constructor
 * @extends Message
 * @param {*} userId
 * @param {*} appId
 * @param {*} issuedAt
 */
class FacebookIdToken extends Message {
  constructor({userId, appId, iat}={}) {
    super();
    this.userId = userId;
    this.appId = appId;
    this.iat = iat;
    this.validateRequiredFields();

    /** Required claims */
    this.optionsToPayload = {
      userId: 'userId',
      appId: 'appId',
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

    /** Required verification claims */
    this.claimsForVerification = {
      userId: 'userId',
      appId: 'appId',
      maxAge: 'maxAge',
    };

    /** Known optional claims */
    this.knownOptionalClaims = {
      expiredAt: 'expiredAt',
    };
  }

  static init(payload, options){
    const facebookIdToken = new FacebookIdToken(payload);
    let optionalClaims = {};
    Object.keys(facebookIdToken.knownOptionalClaims).forEach(key => {
      if (payload[key]){
        optionalClaims[key] = payload[key];
      }
    });
    facebookIdToken.addOptionalClaims(optionalClaims);
    if (options && Object.keys(options).indexOf('algorithm')!== -1 && options['algorithm'] === 'none'){
      facebookIdToken.setNoneAlgorithmAttr(true);
    }
    return facebookIdToken;
  }

  static toJWT(payload, key, options){
    let facebookIdToken = this.init(payload, options);
    return facebookIdToken.toJWT(key, options);
  }

  static fromJWT(jwt, key, verificationClaims, options){
    let token = new Token();
    let decodedPayload = token.decode(jwt, key, options);
    let facebookIdToken = this.init(decodedPayload);
    decodedPayload = facebookIdToken.verify(decodedPayload, verificationClaims, options);
    return decodedPayload;
  }
}

module.exports = FacebookIdToken;