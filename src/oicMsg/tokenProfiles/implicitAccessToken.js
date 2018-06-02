'use strict';
const AccessToken = require('./accessToken');
const Token = require('./token');

/**
 * @fileoverview
 * ImplicitAccessToken
 * Required claims : iss, sub, iat
 * Optional claims : aud
 */
/**
 * ImplicitAccessToken
 * Init token using required claims
 * @class
 * @constructor
 * @extends AccessToken
 * @param {*} iss
 * @param {*} sub
 * @param {*} iat
 */
class ImplicitAccessToken extends AccessToken {
  constructor({iss, sub, iat}={}) {
    super({iss, sub, iat});

    /** Required claims */
    this.optionsToPayload = [
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

    /** Known optional claims that need to be verified */
    this.knownOptionalClaims = [
      'aud',
    ];

    /** Required claims that need to be verified */
    this.claimsForVerification = [
      'iss',
      'sub',
      'maxAge',
    ];
  }

  static init(payload, options){
    const implicitAccessToken = new ImplicitAccessToken(payload);
    let optionalClaims = {};
    Object.keys(implicitAccessToken.knownOptionalClaims).forEach(key => {
      if (payload[key]){
        optionalClaims[key] = payload[key];
      }
    });
    implicitAccessToken.addOptionalClaims(optionalClaims);
    if (options && Object.keys(options).indexOf('algorithm')!== -1 && options['algorithm'] === 'none'){
      implicitAccessToken.setNoneAlgorithmAttr(true);
    }
    return implicitAccessToken;
  }

  static toJWT(payload, key, options){
    let implicitAccessToken = this.init(payload, options);
    return implicitAccessToken.toJWT(key, options);
  }

  static fromJWT(jwt, key, verificationClaims, options){
    let token = new Token();
    let decodedPayload = token.decode(jwt, options);
    let implicitAccessToken = this.init(decodedPayload);
    decodedPayload = implicitAccessToken.verify(decodedPayload, verificationClaims, options);
    return decodedPayload;
  }
}

module.exports = ImplicitAccessToken;