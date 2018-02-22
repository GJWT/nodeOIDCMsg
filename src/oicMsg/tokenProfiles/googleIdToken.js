'use strict';

const jwtDecoder =
    require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');
const jwtSigner =
    require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');
const Message = require('./message');
const BasicIdToken = require('./basicIdToken');

/**
 * @fileoverview
 * GoogleIdToken
 * Required claims : name, email, picture, iss, sub, iat
 * Optional claims : exp, aud
 */

/**
 * GoogleIdToken
 * Init token using required claims
 * @class
 * @constructor
 * @extends Message
 * @param {*} name
 * @param {*} email
 * @param {*} picture
 * @param {*} iss
 * @param {*} sub
 * @param {*} iat
 */
class GoogleIdToken extends Message {
  constructor(name, email, picture, iss, sub, iat) {
    super();
    this.name = name;
    this.email = email;
    this.picture = picture;
    this.iss = iss;
    this.sub = sub;
    this.iat = iat;
    this.validateRequiredFields();

    /** Required claims */
    this.optionsToPayload = {
      name: 'name',
      email: 'email',
      picture: 'picture',
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
      exp: 'exp',
      aud: 'aud',
    };

    /** Required claims that need to be verified */
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

module.exports = GoogleIdToken;