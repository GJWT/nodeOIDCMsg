var JsonWebTokenError = require('../../lib/JsonWebTokenError');
var NotBeforeError    = require('../../lib/NotBeforeError');
var TokenExpiredError = require('../../lib/TokenExpiredError');
var decode            = require('./decode');
var timespan          = require('../../lib/timespan');
var jws               = require('../jws');
var xtend             = require('xtend');
var jwtVerifier       = require('./verify');
var jwkToPem          = require('jwk-to-pem');
var forge = require('node-forge');

/**
 * @fileoverview Handles common decoding functionality for JWT message type
 */

/**
 * JWTDecoder
 * @class
 * @constructor
 */
class JWTDecoder {
  /** 
   * Decodes Jwt string after verifying if payload matches expected claim values 
   * @param {string} jwtString The signed Jwt string
   * @param {string} secretOrPublicKey A string or buffer containing either the secret for HMAC algorithms, or the PEM encoded public key for RSA and ECDSA
   * @param {Token} tokenProfile Contains the token properties, required, optional and verification claims
   * @param {dictionary} otherOptions Other inputs that are not part of the payload, for ex : 'algorithm'
   * @param {function} callback If a callback is supplied, function acts asynchronously. The callback is called with the decoded payload if the 
        signature is valid and optional expiration, audience, or issuer are valid. If not, it will be called with the error.
   * @throws JsonWebToken error if inputted claims does not match expected claims
   * @memberof JWTDecoder
   */
  decode(jwtSig, secretOrPublicKey, tokenProfile, otherOptions, callback) {
    // Verifications of other options and jwt string signature
    jwtVerifier.prototype.verifyOptions(jwtSig, secretOrPublicKey, otherOptions, callback);

    // Decodes type jwt and returns header, payload & signature
    const decoded = jws.decode(jwtSig, secretOrPublicKey, tokenProfile, otherOptions, callback);
    var done = this.initCallback(callback);
    
    if (!decoded) { return done(new JsonWebTokenError('invalid token')); }
    const header = decoded.header;

    var done = this.initCallback(callback);

    this.verifyHeaderAlgorithm(otherOptions, header, done)

    const baseEncoding = otherOptions.baseEncoding || "base64";  

    this.validateJws(jwtSig, header.alg, secretOrPublicKey, baseEncoding, done)

    var payload = decoded.payload;
    this.parsePayload(payload);

    // verify payload values matches expected values
    var payload =  jwtVerifier.prototype.verifyPayload(payload, tokenProfile,otherOptions, callback);

    //return header if `complete` option is enabled.  header includes claims
    //such as `kid` and `alg` used to select the key within a JWKS needed to
    //verify the signature
    if (otherOptions && otherOptions.complete === true) {
      return {
        header: decoded.header,
        payload,
        signature: decoded.signature
      };
    }
    
    return payload;
  }

  /**
   * Initialize callback
   * @param {function} callback
   * @memberof JWTDecoder
   */
  initCallback(callback) {
    let done;
    
    if (callback) {
      done = callback;
    } else {
      done = (err, data) => {
        if (err) throw err;
        return data;
      };
    }
    return done;
  }

  /**
   * Algorithms check based on decoded header
   * 
   * @param {dictionary} otherOptions
   * @param {dictionary} header
   * @param {function} done
   * 
   * @memberof JWTDecoder
   */
  verifyHeaderAlgorithm(otherOptions, header, done) {
    if (otherOptions && otherOptions.algorithms){
      if (!~otherOptions.algorithms.indexOf(header.alg)) {
        return done(new JsonWebTokenError('invalid algorithm'));
      }
    
      if (otherOptions.algorithms.includes('none') && tokenProfile.getNoneAlgorithm() == false) {
        return done(new JsonWebTokenError('Cannot use none algorithm unless explicitly set'));
      }
    }
  }

  /** 
   * Verifies signed Jwt
   * @param {string} jwtSig
   * @param {string} algorithm
   * @param {string} secretOrPublicKey
   * @param {string} baseEncoding
   * @param {function} done
   * 
   * @memberof JWTDecoder
   */
  validateJws(jwtSig, algorithm, secretOrPublicKey, baseEncoding, done) {
    let valid;
    
    try {
      valid = jws.verify(jwtSig, algorithm, secretOrPublicKey, baseEncoding);
    } catch (e) {
      return done(e);
    }
    
    if (!valid)
      return done(new JsonWebTokenError('invalid signature'));
  }

  /**
   * Parse payload
   * @param {dictionary} payload
   * 
   * @memberof JWTDecoder
   */
  parsePayload(payload) {
    if(typeof payload === 'string') {
      try {
        const obj = JSON.parse(payload);
        if(typeof obj === 'object') {
          payload = obj;
        }
      } catch (e) { }
    }
  }

  verifyJwtSign(
    token,
    secretOrPublicKey,
    tokenProfile,
    otherOptions,
    baseEncoding,
    callback) {
    const jwt = jws.decode(token, secretOrPublicKey, tokenProfile, otherOptions, callback);
    if (!jwt.signature) {
      return false;
    } else {
      let valid = null;
      try {
        valid = jws.verify(token, jwt.header.alg, secretOrPublicKey, baseEncoding);
      } catch (e) {
        return done(e);
      }
              
      if (!valid) {
        console.log('invalid signature');
        return false;
      } else {
        return true;
      }
    }
  }

  verifyJwtSignature(
    token,
    secretOrPublicKey,
    tokenProfile,
    otherOptions,
    certs,
    baseEncoding,
    callback) {
    const jwt = jws.decode(token, secretOrPublicKey, tokenProfile, otherOptions, callback);
    if (!jwt.signature) {
      return false;
    } else {
      if (JSON.parse(certs).keys.length <= 0) {
        return false;
      } else {
        // find the cert
        const header = jwt.header;
        if (header.kid) {
          // a kid is being used
          const kids = JSON.parse(certs).keys.filter(key => key.kid === header.kid);
          if (kids.length > 0) {
            // we have a key
            return jws.verify(token, jwt.header.alg, jwkToPem(kids[0]), baseEncoding);
          } else {
            // no matching kid 
            return false;
          }
        } else {
          // try using the first key
          const first = JSON.parse(certs).keys[0];
          const pemFromX509 = this.convertX509ToPem(first);
          console.log(pemFromX509);
          let valid = null;
          try {
            valid = jws.verify(token, jwt.header.alg, pemFromX509, baseEncoding);
          } catch (e) {
            return done(e);
          }
              
          if (!valid) {
            console.log('invalid signature');
            return false;
          } else {
            return true;
          }
        }
      }
    }
  }

  convertX509ToPem(jwk) {
    // this string format is base64-encoded DER bytes
     const certString = jwk.x5c[0];
    // base64-decode DER bytes
    const certDerBytes = forge.util.decode64(certString);
    // parse DER to an ASN.1 object
    const obj = forge.asn1.fromDer(certDerBytes);
    // convert ASN.1 object to forge certificate object
    const cert = forge.pki.certificateFromAsn1(obj);
    // get forge public key object
    const publicKey = cert.publicKey;
    // if you did want to convert it to PEM format for transport:
    const pem = forge.pki.publicKeyToPem(publicKey);
    return pem;
  }
}

module.exports = JWTDecoder;