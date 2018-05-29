'use strict';
const Message = require('../message');

/**
 * @class
 * @constructor
 * @extends Message
 */
class Token extends Message {
  constructor() {
    super();
    this.validateRequiredFields();

    /** Other option values */
    this.optionsForObjects = [];

    /** Known required claims */
    this.knownOptionalClaims = [];

    /** Required verification claims */
    this.claimsForVerification = [];

    /** Required claims */
    this.optionsToPayload = [];
  }
}

module.exports = Token;