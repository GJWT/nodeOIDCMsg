'use strict';

const GoogleIdToken = require('./googleIdToken');
const jwtDecoder = require('../../oicMsg/jose/jwt/decode');
const jwtSigner = require('../../oicMsg/jose/jwt/decode');

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
  constructor(name, email, picture, iss, sub, iat) {
    super(name, email, picture, iss, sub, iat);

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
}

module.exports = ExtendedIdToken;