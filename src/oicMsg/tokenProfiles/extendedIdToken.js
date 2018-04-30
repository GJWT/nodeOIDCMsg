'use strict';

const GoogleIdToken = require('./googleIdToken');
const Token = require('./token');

/**
 * @fileoverview
 * AccessToken
 * Required claims : name, email, picture, iss, sub, iat
 * Optional claims : aud, exp, nbf
 */

/**
 * ExtendedIdToken
 * Init token using required claims
 * @class
 * @constructor
 * @extends GoogleIdToken
 * @param {*} name
 * @param {*} email
 * @param {*} picture
 * @param {*} iss
 * @param {*} sub
 * @param {*} iat
 */
class ExtendedIdToken extends GoogleIdToken {
  constructor({name, email, picture, iss, sub, iat}={}) {
    super({name, email, picture, iss, sub, iat});

    /** Required claims */
    this.optionsToPayload = {
      name: 'name',
      email: 'email',
      picture: 'picture',
      iss: 'iss',
      sub: 'sub',
      iat: 'iat',
    };

    /** Other options values */
    this.optionsForObjects = [
      'expiresIn',
      'notBefore',
      'noTimestamp',
      'audience',
      'issuer',
      'subject',
      'jwtid',
    ];

    /** Known optional claims to be verified */
    this.knownOptionalClaims = {
      aud: 'aud',
      exp: 'exp',
      nbf: 'nbf',
    };

    /** Required claims to be verified */
    this.claimsForVerification = {
      name: 'name',
      email: 'email',
      picture: 'picture',
      iss: 'iss',
      sub: 'sub',
      maxAge: 'maxAge',
    };
  }

  static init(payload, options){
    const extendedIdToken = new ExtendedIdToken(payload);
    let optionalClaims = {};
    Object.keys(extendedIdToken.knownOptionalClaims).forEach(key => {
      if (payload[key]){
        optionalClaims[key] = payload[key];
      }
    });
    extendedIdToken.addOptionalClaims(optionalClaims);
    if (options && Object.keys(options).indexOf('algorithm')!== -1 && options['algorithm'] === 'none'){
      extendedIdToken.setNoneAlgorithmAttr(true);
    }
    return extendedIdToken;
  }

  static toJWT(payload, key, options){
    let extendedIdToken = this.init(payload, options);
    return extendedIdToken.toJWT(key, options);
  }

  static fromJWT(jwt, key, verificationClaims, options){
    let token = new Token();
    let decodedPayload = token.decode(jwt, key, options);
    let extendedIdToken = this.init(decodedPayload);
    decodedPayload = extendedIdToken.verify(decodedPayload, verificationClaims, options);
    return decodedPayload;
  }
}

module.exports = ExtendedIdToken;