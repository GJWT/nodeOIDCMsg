var JsonWebTokenError = require('../../lib/JsonWebTokenError');
var NotBeforeError = require('../../lib/NotBeforeError');
var TokenExpiredError = require('../../lib/TokenExpiredError');
var decode = require('./decode');
var timespan = require('../../lib/timespan');
var xtend = require('xtend');
var MessageVerifier = require('../../msgVerifier');

/**
 * @fileoverview Handles common verification functionality for JWT message type
 */

/**
 * JWTVerifer
 * @class
 * @extends MessageVerifier
 * @constructor
 */
class JWTVerifier extends MessageVerifier {
  /** Calls super class' verification method */
  constructor() {
    super();
  }
};

module.exports = JWTVerifier;