var jws = require('../lib/jws');
var once = require('lodash.once');
var messageSigner = require('../../../message/sign');

var jwtSigner = JWTSigner.prototype;
jwtSigner = Object.create(messageSigner);
jwtSigner.constructor = JWTSigner;

function JWTSigner(){
};

/* Signs JWT and checks for valid input
    * @param tokenProfile contains the token properties, standard, non standard and verification claims
    * @param secretOrPublicKey is a string or buffer containing either the secret for HMAC algorithms, or the PEM encoded public key for RSA and ECDSA
    * @param options consists of other inputs that are not part of the payload, for ex : 'algorithm'
    * @param callback is called with the decoded payload if the signature is valid and optional expiration, audience, or issuer are valid. If not, it 
    will be called with the error. When supplied, the function acts asynchronously.
    * @throws JsonWebToken error if options does not match expected claims. */ 
    
jwtSigner.sign = function (tokenProfile, secretOrPrivateKey, options, callback) {

  // Calls super class's method
  var messageInfo = messageSigner.sign.call(this, tokenProfile, secretOrPrivateKey, options, callback);
  var header = messageInfo["header"];
  var payload = messageInfo["payload"];
  var options = messageInfo["options"]

  var encoding = options.encoding || 'utf8';
  var baseEncoding = options.baseEncoding || "base64";

  // Performs JWT related signing
  if (typeof callback === 'function') {
    callback = callback && once(callback);

    jws.createSign({
      header: header,
      privateKey: secretOrPrivateKey,
      payload: payload,
      encoding: encoding, 
      baseEncoding : baseEncoding,
    }).once('error', callback)
      .once('done', function (signature) {
        callback(null, signature);
      });
  } else {
    return jws.sign({header: header, payload: payload, secret: secretOrPrivateKey, encoding: encoding, baseEncoding: baseEncoding});
  }
};

module.exports = jwtSigner;
