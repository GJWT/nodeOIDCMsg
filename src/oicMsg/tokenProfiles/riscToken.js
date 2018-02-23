'use strict';

const RiscToken = require('./basicIdToken');
const jwtDecoder = require('../../oicMsg/jose/jwt/decode');
const jwtSigner = require('../../oicMsg/jose/jwt/decode');

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
  constructor(jti, iss, sub, iat) {
    super();
    this.jti = jti;
    this.iss = iss;
    this.sub = sub;
    this.iat = iat;
    this.validateRequiredFields();

    /** Required claims */
    this.optionsToPayload = {
      jti: 'jti',
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

    /** Required known optional claims */
    this.knownOptionalClaims = {
      aud: 'aud',
      nbf: 'nbf',
      exp: 'exp',
    };

    /** Required claims that need to be verified */
    this.claimsForVerification = {
      jti: 'jti',
      iss: 'iss',
      sub: 'sub',
      maxAge: 'maxAge',
    };
  }
}

module.exports = RiscToken;