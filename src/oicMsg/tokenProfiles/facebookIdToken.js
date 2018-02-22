'use strict';

const Message = require('./message');
const jwtDecoder =
    require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');
const jwtSigner =
    require('../../controllers/messageTypes/jwt/jsonwebtoken/sign');

/**
 * @fileoverview
 * FacebookIdToken
 * Required claims : user_id, app_id, issued_at
 * Optional claims : expired_at
 */
/**
 * FacebookIdToken
 * Init token using required claims
 * @class
 * @constructor
 * @extends Message
 * @param {*} userId
 * @param {*} appId
 * @param {*} issuedAt
 */
class FacebookIdToken extends Message {
  constructor(userId, appId, issuedAt) {
    super();
    this.userId = userId;
    this.appId = appId;
    this.iat = issuedAt;
    this.validateRequiredFields();

    /** Required claims */
    this.optionsToPayload = {
      userId: 'userId',
      appId: 'appId',
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

    /** Required verification claims */
    this.claimsForVerification = {
      userId: 'userId',
      appId: 'appId',
      maxAge: 'maxAge',
    };

    /** Known optional claims */
    this.knownOptionalClaims = {
      expiredAt: 'expiredAt',
    };
  }
}

module.exports = FacebookIdToken;