'use strict';

const Message = require('../message');
const jwtDecoder = require('../../oicMsg/jose/jwt/decode');
const jwtSigner = require('../../oicMsg/jose/jwt/sign');

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