'use strict';

const jwtDecoder =
    require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');
const jwtSigner =
    require('../../controllers/messageTypes/jwt/jsonwebtoken/sign');
const Message = require('./message');

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
  constructor(iss, sub, iat, jti) {
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
}

module.exports = BasicIdToken;