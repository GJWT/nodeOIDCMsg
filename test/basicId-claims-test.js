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

      describe(
          'when signing a basic id token with a known non standard claim',
          function() {
            var basicIdToken2 = new BasicIdToken({
              iss: 'issuer',
              sub: 'subject',
              iat: clockTimestamp,
              jti: 'jti'
            });
            basicIdToken2.addOptionalClaims({
              'aud': 'audience',
              'nbf': clockTimestamp + 2,
              'exp': clockTimestamp + 3
            });
            basicIdToken2.setNoneAlgorithm(true);

            it('should check known non standard claim', function(done) {
              basicIdToken2.toJWT('shhhh').then(function(signedJWT) {
                try {
                  let decodedPayload = basicIdToken2.fromJWT(
                      signedJWT, 'shhhh', {
                        'iss': 'issuer',
                        'sub': 'subject',
                        'aud': 'audience',
                        'maxAge': '1d',
                        'clockTolerance': 10,
                        'jti': 'jti'
                      },
                      {'clockTimestamp': clockTimestamp})
                } catch (err) {
                  assert.isNull(err);
                }
                done();
              });
            });

            it('should throw when invalid known non standard claim',
               function(done) {
                 basicIdToken2.toJWT('shhhh').then(function(signedJWT) {
                   try {
                     let decodedPayload = basicIdToken2.fromJWT(
                         signedJWT, 'shhhh', {
                           'iss': 'issuer',
                           'sub': 'subject',
                           'aud': 'wrong-audience',
                           'maxAge': '1d',
                           'clockTolerance': 10,
                           'jti': 'jti'
                         },
                         {'clockTimestamp': clockTimestamp});
                   } catch (err) {
                     assert.isNotNull(err);
                   }
                   done();
                 });
               });
          });


      describe('when signing a token without standard claim', function() {
        it('should throw error and require standard claim', function(done) {
          try {
            var basicIdToken =
                new BasicIdToken({iss: 'issuer', sub: 'subject'});
            basicIdToken.addOptionalClaims({'jti': 'test'});
            basicIdToken.setNoneAlgorithm(true);
            basicIdToken.toJWT('shhhh');
          } catch (err) {
            assert.isNotNull(err);
            assert.instanceOf(err, Error);
          }
          done();
        });
      });

      describe('when adding claims to token profile', function() {
        var clockTimestamp = 1000000000;

        var basicIdToken2 = new BasicIdToken({
          'iss': 'issuer',
          'sub': 'subject',
          'iat': clockTimestamp,
          'jti': 'jti'
        });
        basicIdToken2.addOptionalClaims({
          'aud': 'audience',
          'nbf': clockTimestamp + 2,
          'exp': clockTimestamp + 3
        });
        basicIdToken2.setNoneAlgorithm(true);

        it('should be able to access all standard claims', function(done) {
          try {
            var standardClaims = basicIdToken2.getRequiredClaims();
            assert.deepEqual(standardClaims, {
              'iss': 'issuer',
              'sub': 'subject',
              'iat': clockTimestamp,
              'jti': 'jti'
            });
          } catch (err) {
            assert.isNull(err);
          }
          done();
        });

        it('should be able to access non standard claims separately',
           function(done) {
             try {
               var nonStandardClaims = basicIdToken2.getOptionalClaims();
               assert.deepEqual(nonStandardClaims, {
                 'aud': 'audience',
                 'nbf': clockTimestamp + 2,
                 'exp': clockTimestamp + 3
               });
             } catch (err) {
               assert.isNull(err);
             }
             done();
           });
      });

      describe('when signing a token with standard claim', function() {
        let signedJWT = null;
        let basicIdToken = null;
        let clockTimestamp = 1000000000;

        it('should check standard claim', function(done) {
          basicIdToken = new BasicIdToken(
              {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
          basicIdToken.addOptionalClaims({
            'aud': 'audience',
            'nbf': clockTimestamp + 2,
            'exp': clockTimestamp + 3
          });
          basicIdToken.setNoneAlgorithm(true);
          basicIdToken.toJWT('shhhh').then(function(jws) {
            signedJWT = jws;
            basicIdToken
                .fromJWT(
                    signedJWT, 'shhhh', {
                      'iss': 'issuer',
                      'sub': 'subject',
                      'maxAge': '1d',
                      'clockTolerance': 10,
                      'aud': 'audience',
                      'jti': 'jti'
                    },
                    {'clockTimestamp': clockTimestamp})
                .then(function(decodedPayload) {
                  assert.isNotNull(decodedPayload);
                })
                .catch(function(err) {
                  assert.isNull(err);
                });
            done();
          })
          done();
        });

        it('should throw when invalid standard claim', function(done) {
          basicIdToken = new BasicIdToken(
              {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
          basicIdToken.addOptionalClaims({
            'aud': 'audience',
            'nbf': clockTimestamp + 2,
            'exp': clockTimestamp + 3
          });
          basicIdToken.setNoneAlgorithm(true);
          basicIdToken.toJWT('shhhh').then(function(jws) {
            signedJWT = jws;
            basicIdToken
                .fromJWT(
                    signedJWT, 'shhhh', {
                      'iss': 'wrong-issuer',
                      'sub': 'subject',
                      'aud': 'audience',
                      'maxAge': '1d',
                      'clockTolerance': 10,
                      'jti': 'jti'
                    },
                    {'clockTimestamp': clockTimestamp})
                .catch(function(err) {
                  assert.isNotNull(err);
                  assert.equal(err.name, 'JsonWebTokenError');
                  done();
                });
            done();
          });
          done();
        });
      });
    })
  });
});
