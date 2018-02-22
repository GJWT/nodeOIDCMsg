'use strict';

const Message = require('./message');
const jwtDecoder =
    require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');
const jwtSigner =
    require('../../controllers/messageTypes/jwt/jsonwebtoken/sign');

/**
 * @fileoverview
 * RefreshToken
 * Required claims : refresh_token, access_token
 */

/**
 * RefreshToken
 * Init token using required claims
 * @class
 * @constructor
 * @extends Message
 * @param {*} refreshToken
 * @param {*} accessToken
 */
class RefreshToken extends Message {
  constructor(refreshToken, accessToken) {
    super();
    this.refreshToken = refreshToken;
    this.accessToken = accessToken;
    this.validateRequiredFields();

    /** Required claims */
    this.optionsToPayload = {
      refreshToken: 'refreshToken',
      accessToken: 'accessToken',
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
      knownOptionalClaim: 'knownOptionalClaim',
    };

    /** Required claims to be verified */
    this.claimsForVerification = {
      refreshToken: 'refreshToken',
      accessToken: 'accessToken',
    };
  }
}

module.exports = RefreshToken;