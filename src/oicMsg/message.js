'use strict';

const jwtDecoder =
    require('../../controllers/messageTypes/jwt/jsonwebtoken/decode');
const jwtSigner =
    require('../../controllers/messageTypes/jwt/jsonwebtoken/sign');

/**
 * @fileoverview
 * Message is the top layer class that handles common functionality among the
 * different serialization and deserialization types, such as claim
 * verification. When sending request, it must be possible to serialize the
 * information to a format that can be transmitted over-the-wire. Likewise, when
 * receiving responses it must be possible to de-serialize these into an
 * internal representation. Because of this a number of methods have been added
 * to the token profile to support serialization to and deserialization from a
 * number of representations that are used in the OAuth2 and OIDC protocol
 * exchange.
 */

/**
 * Message
 * @class
 * @constructor
 */
class Message {
  constructor(claims) {
    this.initData();

    /** Provided required claims */
    this.requiredClaims = {};

    /** Provided optional claims */
    this.optionalClaims = {};

    /** Expected required claim values */
    this.verificationClaims = {};

    /** Expected optional verification claims that are known */
    this.optionalVerificationClaims = {};

    /** None algorithm type */
    this.noneAlgorithm = false;

    /** Required claims */
    this.optionsToPayload = {};

    /** Other option values */
    this.optionsForObjects = [];

    /** Known required claims */
    this.knownOptionalClaims = {};

    /** Required verification claims */
    this.claimsForVerification = {};

    /** Key value map of claims that make up the payload of a Message */
    this.cParam = {};

    /** Map of allowed values for each claim of Message */
    this.cAllowedValues = {};

    return claims;
  }

  initData() {
    this.noneAlgorithm = false;
  }

  /** 
   * Add optional claims
   * @param {?Object<string, string>} optionalClaims Claims that are not required
   * */
  addOptionalClaims(optionalClaims) {
    this.optionalClaims = optionalClaims;
    this.optionalVerificationClaims = {};
    Object.keys(optionalClaims).forEach(key => {
      if (this.knownOptionalClaims[key]) {
        this.optionalVerificationClaims[key] = optionalClaims[key];
      }
    });
  }

  /** Check for missing required claims */
  validateRequiredFields() {
    Object.keys(this.optionsToPayload).forEach(key => {
      if (!this[key]) {
        throw new Error('You are missing a required parameter');
      }
    });
  }

  /** Fetch Required claims */
  getRequiredClaims() {
    this.requiredClaims = {};
    Object.keys(this.optionsToPayload).forEach(key => {
      this.requiredClaims[key] = this[key];
    });
    return this.requiredClaims;
  }


  /** 
   * Fetch optional claims 
   * @param {?Object<string, string>} optionalClaims Claims that are not required
   */
  getOptionalClaims(optionalClaims) {
    return this.optionalClaims;
  }

  /** Fetch expected verification values for required claims */
  getVerificationClaims() {
    return this.verificationClaims;
  }

  /** Fetch expected verification values for optional claims */
  getOptionalVerificationClaims() {
    return this.optionalVerificationClaims;
  }

  /** 
   * User explicitly wants to set None Algorithm attribute
   * @param {?boolean} boolVal Bool value that determines none algorithm setting
   * */
  setNoneAlgorithm(boolVal) {
    this.noneAlgorithm = boolVal;
  }

  /** Fetch current none algorithm bool value */
  getNoneAlgorithm() {
    return this.noneAlgorithm;
  }

  /** 
   * Throws error if required verification claims are not present
   * @param {?Object<string, string>} claimsToVerify Claims that need to be verified
   * */
  validateRequiredVerificationClaims(claimsToVerify) {
    Object.keys(this.claimsForVerification).forEach(key => {
      if (!claimsToVerify[key]) {
        throw new Error(`Missing required verification claim: ${key}`);
      }
    });
    this.verificationClaims = claimsToVerify;
  }

  /** 
   * Throws error if required non Required verification claims are not present
   * @param {?Object<string, string>} claimsToVerify Claims that need to be verified
   */
  validateOptionalVerificationClaims(claimsToVerify) {
    if (this.optionalVerificationClaims['nbf'] ||
        this.optionalVerificationClaims['exp']) {
      this.optionalVerificationClaimsCheck('clockTolerance', claimsToVerify);
    }
    if (this.optionalVerificationClaims['aud']) {
      this.optionalVerificationClaimsCheck('aud', claimsToVerify);
    }
  }

  optionalVerificationClaimsCheck(key, claimsToVerify) {
    console.log(claimsToVerify);
    console.log(key);
    console.log("****************************");
    if (!claimsToVerify[key]) {
      throw new Error(`Missing required verification claim: ${key}`);
    } else {
      this.verificationClaims[key] = claimsToVerify[key];
      if (key == 'aud') {
        this.claimsForVerification['aud'] = 'aud';
      }
    }
  }

  /** 
   * Serialization of JWT type 
   * Signs JWT and checks for valid input
   * @param secretOrPublicKey is a string or buffer containing either the secret for HMAC algorithms, or the PEM encoded public key for RSA and ECDSA
   * @param options consists of other inputs that are not part of the payload, for ex : 'algorithm'
   * @param callback is called with the decoded payload if the signature is valid and optional expiration, audience, or issuer are valid. If not, it 
      will be called with the error. When supplied, the function acts asynchronously.
   **/
  toJWT(secretOrPrivateKey, options, callback) {
    return jwtSigner.prototype.sign(this, secretOrPrivateKey, options, callback);
  }

  /** 
   * Deserialization of JWT type 
   * Signs JWT and checks for valid input
   * @param {string} signedJWT Signed JWT string 
   * @param {*} secretOrPublicKey String or buffer containing either the secret for HMAC algorithms, or the PEM encoded public key for RSA and ECDSA
   * @param {?Object<string, string>} claimsToVerify Dictionary contains claims that need to be verified
   * @param {?Object<string, string>} options Consists of other inputs that are not part of the payload, for ex : 'algorithm'
   * @param {*} callback Called with the decoded payload if the signature is valid and optional expiration, audience, or issuer are valid. If not, it 
      will be called with the error. When supplied, the function acts asynchronously.
   **/
  fromJWT(signedJWT, secretOrPrivateKey, claimsToVerify, options, callback) {
    this.validateRequiredVerificationClaims(claimsToVerify);
    this.validateOptionalVerificationClaims(claimsToVerify);
    return jwtDecoder.prototype.decode(
        signedJWT, secretOrPrivateKey, this, options, callback);
  }

  /** 
   * Serialization of JSON type 
   * @param {?Object<string, string>} obj Object that needs to be converted to JSON
  */
  toJSON(obj) {
    if (!obj) {
      obj = Object.assign(
          {}, this.getRequiredClaims(), this.getOptionalClaims());
    }
    return JSON.stringify(obj);
  }

  /** 
   * Deserialization of JSON type
   * @param {string} jsonString Json object that needs to be deserialized
   * */
  fromJSON(jsonString) {
    return JSON.parse(jsonString);
  }

  /** 
   * Serialization of URL Encoded type
   * @param {?Object<string, string>} obj Object that needs to be URL encoded
   */
  toUrlEncoded(obj) {
    if (!obj) {
      obj = Object.assign(
          {}, this.getRequiredClaims(), this.getOptionalClaims());
    }
    const str = [];
    for (const p in obj)
      str.push(`${encodeURIComponent(p)}=${encodeURIComponent(obj[p])}`);
    return str.join('&');
  }

  /** 
   * Deserialization of URL Encoded string
   * @param {string} obj Url encoded string that needs to be deserialized
   * */
  fromUrlEncoded(urlEncodedString) {
    if (typeof urlEncodedString == 'string') {
      const obj = {};
      urlEncodedString.replace(/([^=&]+)=([^&]*)/g, (m, key, value) => {
        obj[decodeURIComponent(key)] = decodeURIComponent(value);
      });
      return obj;
    } else {
      return urlEncodedString;
    }
  }

  /** Boolean that tells if the required values are there and that the values
   *  are of the correct type 
   * @param {?Object<string, string>} args Claims that need to be checked for type
   * */
  verify(args){
  }

  /**
   * @param {*} location A URL
   * @param {*} inFragment Whether the information should be placed in a fragment (true) or in a query part (false)
   */
  request(location, inFragment){
  }

  /**
   * Convert this instance to another representation. Which representation 
   * is given by the choice of serialization method.
   * @param {*} method A serialization method. Presently 'urlencoded', 'json',
      'jwt' and 'dict' is supported.
   * @param {*} lev 
   * @param {*} kwargs Extra key word arguments
   * @return The content of this message serialized using a chosen method
   */
  serialize(method, lev, kwargs){
  }

  /**
   * Convert from an external representation to an internal.
   * @param {*} info Information that needs to be deserialized
   * @param {*} method Deserialization method
   * @param {*} kwargs 
   */
  deserialize(info, method, kwargs){
  }
}

module.exports = Message;