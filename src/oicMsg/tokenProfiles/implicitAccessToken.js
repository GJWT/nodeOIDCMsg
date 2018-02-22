'use strict';

const AccessToken = require('./accessToken');
const jwtDecoder =
    require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');
const jwtSigner =
    require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');

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
  constructor(iss, sub, iat) {
    super(iss, sub, iat);

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

    /** Known optional claims that need to be verified */
    this.knownOptionalClaims = {
      aud: 'aud',
    };

    /** Required claims that need to be verified */
    this.claimsForVerification = {
      iss: 'iss',
      sub: 'sub',
      maxAge: 'maxAge',
    };
  }
}

module.exports = ImplicitAccessToken;