var jws = require('../lib/jws');
var once = require('lodash.once');
var MessageSigner = require('../../../message/sign');

/**
 * @fileoverview Handles common signing functionality for JWT message type
 */

/**
 * JWTSigner.prototype
 * @class
 * @extends MessageSigner
 * @constructor
 */
class JWTSigner extends MessageSigner{
  /**
   * Signs JWT and checks for valid input
   * @param tokenProfile contains the token properties,required, optional and verification claims
   * @param secretOrPublicKey is a string or buffer containing either the secret for HMAC algorithms, or the PEM encoded public key for RSA and ECDSA
   * @param options consists of other inputs that are not part of the payload, for ex : 'algorithm'
   * @param callback is called with the decoded payload if the signature is valid and optional expiration, audience, or issuer are valid. If not, it 
      will be called with the error. When supplied, the function acts asynchronously.
   * @throws JsonWebToken error if options does not match expected claims.
   * 
   * @memberof JWTSigner.prototype
   */
  sign(tokenProfile, secretOrPrivateKey, options, callback) {

    // Calls super class's method
    const messageInfo = super.sign(tokenProfile, secretOrPrivateKey, options, callback);
    const header = messageInfo["header"];
    const payload = messageInfo["payload"];
    var options = messageInfo["options"]

    const encoding = options.encoding || 'utf8';
    const baseEncoding = options.baseEncoding || "base64";

    // Performs JWT related signing
    if (typeof callback === 'function') {
      callback = callback && once(callback);

      jws.createSign({
        header,
        privateKey: secretOrPrivateKey,
        payload,
        encoding, 
        baseEncoding,
      }).once('error', callback)
        .once('done', signature => {
          callback(null, signature);
        });
    } else {
      return jws.sign({header, payload, secret: secretOrPrivateKey, encoding, baseEncoding});
    }
  }
}

module.exports = JWTSigner;
