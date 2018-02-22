const timespan = require('./lib/timespan');
const xtend = require('xtend');
const jws = require('../messageTypes/jwt/lib/jws');
const includes = require('lodash.includes');
const isBoolean = require('lodash.isboolean');
const isInteger = require('lodash.isinteger');
const isNumber = require('lodash.isnumber');
const isPlainObject = require('lodash.isplainobject');
const isString = require('lodash.isstring');
const once = require('lodash.once');

/**
 * @fileoverview Handles the common signing functionality for all message protocols
 */

const signOptionsSchema = {
  expiresIn: { isValid(value) { return isInteger(value) || isString(value); }, message: '"expiresIn" should be a number of seconds or string representing a timespan' },
  notBefore: { isValid(value) { return isInteger(value) || isString(value); }, message: '"notBefore" should be a number of seconds or string representing a timespan' },
  audience: { isValid(value) { return isString(value) || Array.isArray(value); }, message: '"audience" must be a string or array' },
  algorithm: { isValid: includes.bind(null, ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'HS256', 'HS384', 'HS512', 'none']), message: '"algorithm" must be a valid string enum value' },
  header: { isValid: isPlainObject, message: '"header" must be an object' },
  encoding: { isValid: isString, message: '"encoding" must be a string' },
  issuer: { isValid: isString, message: '"issuer" must be a string' },
  subject: { isValid: isString, message: '"subject" must be a string' },
  jwtid: { isValid: isString, message: '"jwtid" must be a string' },
  noTimestamp: { isValid: isBoolean, message: '"noTimestamp" must be a boolean' },
  keyid: { isValid: isString, message: '"keyid" must be a string' },
  baseEncoding: { isValid: isString, message: '"baseEncoding" must be a string' },
};

const registeredClaimsSchema = {
  iat: { isValid: isNumber, message: '"iat" should be a number of seconds' },
  exp: { isValid: isNumber, message: '"exp" should be a number of seconds' },
  nbf: { isValid: isNumber, message: '"nbf" should be a number of seconds' },
  aud: { isValid(value) { return isString(value) || Array.isArray(value); }, message: '"audience" must be a string or array' },
  sub: { isValid: isString, message: '"subject" must be a string' },
  jti: { isValid: isString, message: '"jwtid" must be a string' },
};

/**
 * MessageSigner
 * @class
 * @constructor
 */
class MessageSigner {

  constructor(){
  }
  /** 
   * Check if the input format type matches the schema. 
   * @memberof MessageSigner
   * @param schema
   * @param allowUnknown
   * @param object
   * @param parameterName
   * */
  validate(schema, allowUnknown, object, parameterName) {
    if (!isPlainObject(object)) {
      throw new Error(`Expected "${parameterName}" to be a plain object.`);
    }
    Object.keys(object)
      .forEach(key => {
        const validator = schema[key];
        if (!validator) {
          if (!allowUnknown) {
            throw new Error(`"${key}" is not allowed in "${parameterName}"`);
          }
          return;
        }
        if (!validator.isValid(object[key])) {
          throw new Error(validator.message);
        }
      });
  }

  /** 
   * Checks format type of other options 
   * @param {dictionary} options
   * @memberof MessageSigner.prototype
   */
  validateOptions(options) {
    return this.validate(signOptionsSchema, false, options, 'options');
  }

  /** 
   * Checks format type of payload values
   * @param {dictionary} payload
   * @memberof MessageSigner
   */
  validatePayload(payload) {
    return this.validate(registeredClaimsSchema, true, payload, 'payload');
  }

  /** 
   * Signs message and checks for valid input.
   * 
   * @param {Token} tokenProfile - Contains the token properties, required, optional and verification claims.
   * @param {string} secretOrPublicKey - String or buffer containing either the secret for HMAC algorithms, or the PEM encoded public key for RSA and ECDSA.
   * @param {dictionary} options - Consists of other inputs that are not part of the payload, for ex : 'algorithm'.
   * @param {function} callback - Called with the decoded payload if the signature is valid and optional expiration, audience, or issuer are valid. If not, it 
      will be called with the error. When supplied, the function acts asynchronously.
   * @returns {dictionary} - Contains the header, payload and options info.
   * @throws JsonWebToken error if options does not match expected claims.
   * @memberof MessageSigner.prototype
   */
  sign(tokenProfile, secretOrPrivateKey, options, callback) {
    let payload = Object.assign({}, tokenProfile.getRequiredClaims(), tokenProfile.getOptionalClaims());
    
    // Init options
    options = this.initOptions(options);

    if (options){
      var isObjectPayload = typeof payload === 'object' &&
                          !Buffer.isBuffer(payload);
    }

    // Init header
    const header = xtend({
      alg: options.algorithm || 'HS256',
      typ: isObjectPayload ? 'JWT' : undefined,
      kid: options.keyid
    }, options.header);

    function failure(err) {
      if (callback) {
        return callback(err);
      }
      throw err;
    }

    /** Check for undefined payload or invalid options */ 
    if (typeof payload === 'undefined') {
      return failure(new Error('payload is required'));
    } else if (isObjectPayload) {
      try {
        this.validatePayload(payload);
      }
      catch (error) {
        return failure(error);
      }
      payload = xtend(payload);
    } else {
      const invalidOptions = optionsForObjects.filter(opt => typeof options[opt] !== 'undefined');

      if (invalidOptions.length > 0) {
        return failure(new Error(`invalid ${invalidOptions.join(',')} option for ${typeof payload} payload`));
      }
    }

    try {
      this.validateOptions(options);
    }
    catch (error) {
      return failure(error);
    }

    payload = this.checkOtherOptions(secretOrPrivateKey, options, tokenProfile, payload, failure);
    payload = this.checkOptions(tokenProfile.optionsToPayload, options, payload, failure);
    payload = this.checkOptions(tokenProfile.knownOptionalClaims, options, payload, failure);
   
    const messageInfo = { "header": header, "payload": payload, "options": options};
    return messageInfo;
  }

  /** Initialize options
   * @param {dictionary} options
   */
  initOptions(options) {
    if (typeof options === 'function') {
      callback = options;
      options = {};
    } else {
      options = options || {};
    }
    return options;
  }

  /**
   * Check for other options values and for duplicates
   * 
   * @param {string} secretOrPublicKey A string or buffer containing either the secret for HMAC algorithms, or the PEM encoded public key for RSA and ECDSA.
   * @param {dictionary} options Other inputs that are not part of the payload, for ex : 'algorithm'.
   * @param {Token} tokenProfile Contains the token properties, required, optional and verification claim.
   * @param {dictionary} payload Could be an object literal, buffer or string, containing claims. Please note that exp is only set if the payload is an object literal.
   * @returns {dictionary} payload
   * @throws Error if duplicate options values provided or does not match expected value.
   * @memberof MessageSigner.prototype
   */
  checkOtherOptions(secretOrPrivateKey, options, tokenProfile, payload, failure) {

    const timestamp = payload.iat || Math.floor(Date.now() / 1000);
    
      if (!options.noTimestamp) {
        payload.iat = timestamp;
      } else {
        delete payload.iat;
      }

    if (!secretOrPrivateKey && options.algorithm !== 'none') {
      return failure(new Error('secretOrPrivateKey must have a value'));
    }

     // Check none algorithm status
     if (options.algorithm == 'none' && tokenProfile.getNoneAlgorithm() == false){
      return failure(new Error('Cannot use none algorithm unless specified'));
    } 

    if (typeof payload.exp !== 'undefined' && typeof options.expiresIn !== 'undefined') {
      return failure(new Error('Bad "options.expiresIn" option the payload already has an "exp" property.'));
    }

    if (typeof payload.nbf !== 'undefined' && typeof options.notBefore !== 'undefined') {
      return failure(new Error('Bad "options.notBefore" option the payload already has an "nbf" property.'));
    }

    
    if (typeof options.notBefore !== 'undefined') {
      payload.nbf = timespan(options.notBefore);
      if (typeof payload.nbf === 'undefined') {
        return failure(new Error('"notBefore" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'));
      }
    }

    if (typeof options.expiresIn !== 'undefined' && typeof payload === 'object') {
      payload.exp = timespan(options.expiresIn, timestamp);
      if (typeof payload.exp === 'undefined') {
        return failure(new Error('"expiresIn" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'));
      }
    }

    return payload;
  }

  /** 
   * Check if the payload and options have a duplicate property 
   * @param {dictionary} tokenProfileKnownClaims
   * @param {dictionary} options
   * @param {dictionary} payload
   * @param {function} failure
   * */
  checkOptions(tokenProfileKnownClaims, options, payload, failure) {
    Object.keys(tokenProfileKnownClaims).forEach(key => {
      const claim = tokenProfileKnownClaims[key];
      if (typeof options[key] !== 'undefined') {
        if (typeof payload[claim] !== 'undefined') {
          return failure(new Error(`Bad "options.${key}" option. The payload already has an "${claim}" property.`));
        }
        payload[claim] = options[key];
      }
    });
    return payload;
  }
}

module.exports = MessageSigner;