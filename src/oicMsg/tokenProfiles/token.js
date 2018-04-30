'use strict';
const Message = require('../message');

/**
 * @fileoverview
 * Token
 * Required claims : iss, sub, iat, jti
 * Optional claims : aud, exp, nbf
 */

/**
 * Token
 * Init token using required claims
 * @class
 * @constructor
 * @extends Message
 * @param {*} iss
 * @param {*} sub
 * @param {*} iat
 * @param {*} jti
 */
class Token extends Message {
  constructor() {
    super();
    this.validateRequiredFields();

    /** Other option values */
    this.optionsForObjects = [
    ];

    /** Known required claims */
    this.knownOptionalClaims = {
    };

    /** Required verification claims */
    this.claimsForVerification = {
    };

    /** Required claims */
    this.optionsToPayload = {
    };
  }
}

module.exports = Token;