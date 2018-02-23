'use strict';

const Message = require('../message');
const jwtDecoder = require('../../oicMsg/jose/jwt/decode');
const jwtSigner = require('../../oicMsg/jose/jwt/sign');

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
  constructor(iss, sub, iat, scope) {
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
}

module.exports = ScopedAccessToken;