var fs = require('fs');
var path = require('path');
var assert = require('chai').assert;

var BasicIdToken = require('../src/oicMsg/tokenProfiles/basicIdToken');

function loadKey(filename) {
  return fs.readFileSync(path.join(__dirname, filename));
}

var algorithms = {
  RS256: {
    pub_key: loadKey('pub.pem'),
    priv_key: loadKey('priv.pem'),
    invalid_pub_key: loadKey('invalid_pub.pem')
  },
  ES256: {
    // openssl ecparam -name secp256r1 -genkey -param_enc explicit -out
    // ecdsa-private.pem
    priv_key: loadKey('ecdsa-private.pem'),
    // openssl ec -in ecdsa-private.pem -pubout -out ecdsa-public.pem
    pub_key: loadKey('ecdsa-public.pem'),
    invalid_pub_key: loadKey('ecdsa-public-invalid.pem')
  }
};

describe('Asymmetric Algorithms', function() {

  Object.keys(algorithms).forEach(function(algorithm) {
    describe(algorithm, function() {
      var clockTimestamp = 1000000000;

      describe('when signing a token with wrong type values', function() {
        it('should throw error for incorrect type format of audience',
           function(done) {
             try {
               var basicIdToken2 = new BasicIdToken({
                 iss: 'issuer',
                 sub: 'subject',
                 iat: clockTimestamp,
                 jti: 'jti'
               });
               basicIdToken2.addOptionalClaims({
                 'aud': 1,
                 'nbf': clockTimestamp + 2,
                 'exp': clockTimestamp + 3
               });
               basicIdToken2.setNoneAlgorithm(true);
               basicIdToken2.toJWT('shhhh');
             } catch (err) {
               assert.isNotNull(err);
             }
             done();
           });

        it('should throw error for incorrect type format of subject',
           function(done) {
             try {
               var basicIdToken2 = new BasicIdToken(
                   {iss: 'issuer', sub: 1, iat: clockTimestamp, jti: 'jti'});
               basicIdToken2.addOptionalClaims({
                 'aud': 'audience',
                 'nbf': clockTimestamp + 2,
                 'exp': clockTimestamp + 3
               });
               basicIdToken2.setNoneAlgorithm(true);
               basicIdToken2.toJWT('shhhh');
             } catch (err) {
               assert.isNotNull(err);
             }
             done();
           });

        it('should throw error for incorrect type format of jti',
           function(done) {
             try {
               var basicIdToken2 = new BasicIdToken({
                 iss: 'issuer',
                 sub: 'subject',
                 iat: clockTimestamp,
                 jti: 1
               });
               basicIdToken2.addOptionalClaims({
                 'aud': 'audience',
                 'nbf': clockTimestamp + 2,
                 'exp': clockTimestamp + 3
               });
               basicIdToken2.setNoneAlgorithm(true);
               basicIdToken2.toJWT('shhhh');
             } catch (err) {
               assert.isNotNull(err);
             }
             done();
           });
      });
    });
  });
});