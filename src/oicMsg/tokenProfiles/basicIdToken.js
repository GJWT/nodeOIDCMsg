'use strict';
const Message = require('../message');
const Token = require('./token');

/**
 * @fileoverview
 * BasicIdToken
 * Required claims : iss, sub, iat, jti
 * Optional claims : aud, exp, nbf
 */

/**
 * BasicIdToken
 * Init token using required claims
 * @class
 * @constructor
 * @extends Message
 * @param {*} iss
 * @param {*} sub
 * @param {*} iat
 * @param {*} jti
 */
class BasicIdToken extends Message {
  constructor({iss, sub, iat, jti}={}) {
    super();
    this.iss = iss;
    this.sub = sub;
    this.iat = iat;
    this.jti = jti;
    this.validateRequiredFields();

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

    /** Known required claims */
    this.knownOptionalClaims = {
      aud: 'aud',
      exp: 'exp',
      nbf: 'nbf',
    };

    /** Required verification claims */
    this.claimsForVerification = {
      iss: 'iss',
      sub: 'sub',
      maxAge: 'maxAge',
      jti: 'jti',
    };

    /** Required claims */
    this.optionsToPayload = {
      'iss': 'iss',
      'sub': 'sub',
      'iat': 'iat',
      'jti': 'jti',
    };
  }
  
  
  static init(payload, options){
    const basicIdToken = new BasicIdToken(payload);
    let optionalClaims = {};
    Object.keys(basicIdToken.knownOptionalClaims).forEach(key => {
      if (payload[key]){
        optionalClaims[key] = payload[key];
      }
    });
    basicIdToken.addOptionalClaims(optionalClaims);
    if (options && Object.keys(options).indexOf('algorithm')!== -1 && options['algorithm'] === 'none'){
      basicIdToken.setNoneAlgorithmAttr(true);
    }
    return basicIdToken;
  }

  static toJWT(payload, key, options){
    let basicIdToken = this.init(payload, options);
    return basicIdToken.toJWT(key, options);
  }

  static fromJWT(jwt, key, verificationClaims, options){
    return new Promise((resolve, reject) => { 
      try{
        let token = new Token();
        let decodedPayload = token.decode(jwt, key, options);
        let basicIdToken = this.init(decodedPayload);
        decodedPayload = basicIdToken.verify(decodedPayload, verificationClaims, options);
        resolve(decodedPayload);
      }catch(err){
        reject(err);
      }
    });
  }
}

module.exports = BasicIdToken;