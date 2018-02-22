'use strict';

const Message = require('./message');
const jwtDecoder =
    require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');
const jwtSigner =
    require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');

/**
 * @fileoverview
 * AccessToken
 * Required claims : iss, sub, iat
 * Optional claims : aud, exp
 */

/**
 * AccessToken
 * Init token using required claims
 * @class
 * @constructor
 * @extends Message
 * @param {*} iss
 * @param {*} sub
 * @param {*} iat
 */
class AccessToken extends Message {
  constructor(iss, sub, iat) {
    super();
    this.iss = iss;
    this.sub = sub;
    this.iat = iat;
    this.validateRequiredFields();

    /** Required claims */
    this.optionsToPayload = {
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

    /** Known optional claims */
    this.knownOptionalClaims = {
      aud: 'aud',
      exp: 'exp',
    };
  }

  /** Validate required claims */
  validateRequiredFields() {
    if (this.iss && this.sub && this.iat) {
      console.log('Validated all standard fields')
    } else {
      throw new Error('You are missing a required parameter');
    }
  }

  getRequiredClaims() {
    AccessToken.prototype
        .requiredClaims = {'iss': this.iss, 'sub': this.sub, 'iat': this.iat};
    return AccessToken.prototype.requiredClaims;
  }
}

module.exports = AccessToken;