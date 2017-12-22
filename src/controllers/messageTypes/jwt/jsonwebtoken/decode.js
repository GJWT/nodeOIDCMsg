var JsonWebTokenError = require('./lib/JsonWebTokenError');
var NotBeforeError    = require('./lib/NotBeforeError');
var TokenExpiredError = require('./lib/TokenExpiredError');
var decode            = require('./decode');
var timespan          = require('./lib/timespan');
var jws               = require('../lib/jws');
var xtend             = require('xtend');
var jwtVerifier       = require('./verify')
var jwkToPem          = require('jwk-to-pem');
var forge = require('node-forge');

var jwtDecoder = JWTDecoder.prototype;

function JWTDecoder(){
};

/* Decodes Jwt string after verifying if payload matches expected claim values 
    * @param jwtString, the signed Jwt string
    * @param secretOrPublicKey is a string or buffer containing either the secret for HMAC algorithms, or the PEM encoded public key for RSA and ECDSA
    * @param tokenProfile contains the token properties, standard, non standard and verification claims
    * @param otherOptions, other inputs that are not part of the payload, for ex : 'algorithm'
    * @param callback, If a callback is supplied, function acts asynchronously. The callback is called with the decoded payload if the 
      signature is valid and optional expiration, audience, or issuer are valid. If not, it will be called with the error.
    * @throws JsonWebToken error if inputted claims does not match expected claims
*/ 
jwtDecoder.decode = function (jwtSig, secretOrPublicKey, tokenProfile, otherOptions, callback) {
  // Verifications of other options and jwt string signature
  jwtVerifier.verifyOptions(jwtSig, secretOrPublicKey, otherOptions, callback);

  // Decodes type jwt and returns header, payload & signature
  var decoded = jws.decode(jwtSig, secretOrPublicKey, tokenProfile, otherOptions, callback);
  var done = this.initCallback(callback);
  
  if (!decoded) { return done(new JsonWebTokenError('invalid token')); }
  var header = decoded.header;

  var done = this.initCallback(callback);

  this.verifyHeaderAlgorithm(otherOptions, header, done)

  var baseEncoding = otherOptions.baseEncoding || "base64";  

  this.validateJws(jwtSig, header.alg, secretOrPublicKey, baseEncoding, done)

  var payload = decoded.payload;
  this.parsePayload(payload);

  // verify payload values matches expected values
  var payload =  jwtVerifier.verifyPayload(payload, tokenProfile,otherOptions, callback);

  //return header if `complete` option is enabled.  header includes claims
  //such as `kid` and `alg` used to select the key within a JWKS needed to
  //verify the signature
  if (otherOptions && otherOptions.complete === true) {
    return {
      header: decoded.header,
      payload: payload,
      signature: decoded.signature
    };
  }
  
  return payload;
};

/* Initialize callback */
jwtDecoder.initCallback = function(callback){
  var done;
  
  if (callback) {
    done = callback;
  } else {
    done = function(err, data) {
      if (err) throw err;
      return data;
    };
  }
  return done;
}

/* Algorithms check based on decoded header */
jwtDecoder.verifyHeaderAlgorithm = function(otherOptions, header, done){
  if (otherOptions && otherOptions.algorithms){
    if (!~otherOptions.algorithms.indexOf(header.alg)) {
      return done(new JsonWebTokenError('invalid algorithm'));
    }
  
    if (otherOptions.algorithms.indexOf('none') != -1 && tokenProfile.getNoneAlgorithm() == false) {
      return done(new JsonWebTokenError('Cannot use none algorithm unless explicitly set'));
    }
  }
}

/* Verifies signed Jwt */
jwtDecoder.validateJws = function(jwtSig, algorithm, secretOrPublicKey, baseEncoding, done){
  var valid;
  
  try {
    valid = jws.verify(jwtSig, algorithm, secretOrPublicKey, baseEncoding);
  } catch (e) {
    return done(e);
  }
  
  if (!valid)
    return done(new JsonWebTokenError('invalid signature'));
}

/* Parse payload */
jwtDecoder.parsePayload = function(payload){
  if(typeof payload === 'string') {
    try {
      var obj = JSON.parse(payload);
      if(typeof obj === 'object') {
        payload = obj;
      }
    } catch (e) { }
  }
}

jwtDecoder.verifyJwtSign = function(token, secretOrPublicKey, tokenProfile, otherOptions, baseEncoding, callback){
  var jwt = jws.decode(token, secretOrPublicKey, tokenProfile, otherOptions, callback);
    if (!jwt.signature) {
      return false;
    } else {
      var valid = null;
      try {
        valid = jws.verify(token, jwt.header.alg, secretOrPublicKey, baseEncoding);
      } catch (e) {
        return done(e);
      }
            
      if (!valid){
        console.log('invalid signature');
        return false;
      } else {
        return true;
      }
    }
}

jwtDecoder.verifyJwtSignature = function(token, secretOrPublicKey, tokenProfile, otherOptions, certs, baseEncoding, callback){
  var jwt = jws.decode(token, secretOrPublicKey, tokenProfile, otherOptions, callback);
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
            var pemFromX509 = this.convertX509ToPem(first);
            console.log(pemFromX509);
            //return jws.verify(token, jwt.header.alg, secretOrPublicKey, baseEncoding);
            //return jws.verify(token, jwt.header.alg, jwkToPem(first), baseEncoding);
            var valid = null;
            try {
              valid = jws.verify(token, jwt.header.alg, pemFromX509, baseEncoding);
            } catch (e) {
              return done(e);
            }
            
            if (!valid){
              console.log('invalid signature');
              return false;
            } else {
              return true;
            }
          }
        }
    }
}

jwtDecoder.convertX509ToPem = function(jwk){
  // this string format is base64-encoded DER bytes
   var certString = jwk.x5c[0];
  // base64-decode DER bytes
  var certDerBytes = forge.util.decode64(certString);
  // parse DER to an ASN.1 object
  var obj = forge.asn1.fromDer(certDerBytes);
  // convert ASN.1 object to forge certificate object
  var cert = forge.pki.certificateFromAsn1(obj);
  // get forge public key object
  var publicKey = cert.publicKey;
  // if you did want to convert it to PEM format for transport:
  var pem = forge.pki.publicKeyToPem(publicKey);
  return pem;
}

module.exports = jwtDecoder;