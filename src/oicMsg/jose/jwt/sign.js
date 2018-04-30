var jws = require('../jws');
var once = require('lodash.once');
var MessageSigner = require('../../msgSigner');
const await = require('asyncawait/await');

/**
 * @fileoverview Handles common signing functionality for JWT message type
 */

/**
 * JWTSigner.prototype
 * @class
 * @extends MessageSigner
 * @constructor
 */
class JWTSigner extends MessageSigner {
  /**
   * Signs JWT and checks for valid input
   * @param tokenProfile contains the token properties,required, optional and
   verification claims
   * @param secretOrPublicKey is a string or buffer containing either the secret
   for HMAC algorithms, or the PEM encoded public key for RSA and ECDSA
   * @param options consists of other inputs that are not part of the payload,
   for ex : 'algorithm'
   * @throws JsonWebToken error if options does not match expected claims.
   *
   * @memberof JWTSigner.prototype
   */
  sign(tokenProfile, secretOrPrivateKey, options) {
    // Calls super class's method
    const messageInfo = super.sign(tokenProfile, secretOrPrivateKey, options);
    const header = messageInfo['header'];
    const payload = messageInfo['payload'];
    var options = messageInfo['options'];

    options = options || {};

    const encoding = options.encoding || 'utf8';
    const baseEncoding = options.baseEncoding || 'base64';

    // Performs JWT related signing
    /*if (typeof callback === 'function') {*/
    return new Promise((resolve, reject) => {
      if (!header) {
        // callback = callback && once(callback);
        return jws
            .createSign({
              header,
              privateKey: secretOrPrivateKey,
              payload,
              encoding,
              baseEncoding,
            })
            .once('error', reject)
            .once('done', signature => {
              resolve(null, signature);
            });
      } else {
        resolve(jws.sign({
          header,
          payload,
          secret: secretOrPrivateKey,
          encoding,
          baseEncoding
        }));
      }
    });
  }
}

module.exports = JWTSigner;