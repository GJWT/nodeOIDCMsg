var fs = require('fs');
var path = require('path');
var assert = require('chai').assert;
var ImplicitAccessToken =
    require('../src/oicMsg/tokenProfiles/implicitAccessToken');

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
          'when signing a token with a known non standard claim', function() {
            var implicitAccessToken = new ImplicitAccessToken(
                {iss: 'issuer', sub: 'subject', iat: clockTimestamp});
            implicitAccessToken.addOptionalClaims({'aud': 'audience'});
            implicitAccessToken.setNoneAlgorithm(true);

            it('should check known non standard claim', function(done) {
              implicitAccessToken.toJWT('shhhh').then(function(signedJWT) {
              implicitAccessToken
                                .fromJWT(
                                    signedJWT, 'shhhh', {
                                      'iss': 'issuer',
                                      'sub': 'subject',
                                      'aud': 'audience',
                                      'maxAge': '1d'
                                    },
                                    {'clockTimestamp': clockTimestamp})
                                .then(function(decodedPayload) {
                                  assert.isNotNull(decodedPayload);
                                })
                                .catch(function(err) {
                                  assert.isNull(err);
                                });
              });
              done();
            });

            it('should throw when invalid known non standard claim',
               function(done) {
                 implicitAccessToken.toJWT('shhhh').then(function(signedJWT) {
                  implicitAccessToken
                      .fromJWT(
                          signedJWT, 'shhhh', {
                            'iss': 'issuer',
                            'sub': 'subject',
                            'aud': 'wrong-audience',
                            'maxAge': '1d'
                          },
                          {'clockTimestamp': clockTimestamp})
                      .then(function(decodedPayload) {
                        assert.isNotNull(decodedPayload);
                      })
                      .catch(function(err) {
                        assert.isNull(err);
                      });
                 });
                 done();
               });
          });

      describe('when signing a token without standard claim', function() {
        it('should throw error and require standard claim', function(done) {
          try {
            var implicitAccessToken =
                new ImplicitAccessToken({iss: 'issuer', sub: 'subject'});
            implicitAccessToken.addOptionalClaims({'jti': 'test'});
            implicitAccessToken.setNoneAlgorithm(true);
            implicitAccessToken.toJWT('shhhh');
          } catch (err) {
            assert.isNotNull(err);
            assert.instanceOf(err, Error);
          }
          done();
        });
      });

      describe('when adding claims to token profile', function() {
        var implicitAccessToken = new ImplicitAccessToken(
            {iss: 'issuer', sub: 'subject', iat: clockTimestamp});
        implicitAccessToken.addOptionalClaims({'aud': 'audience'});
        implicitAccessToken.setNoneAlgorithm(true);

        it('should be able to access all standard claims', function(done) {
          try {
            var standardClaims = implicitAccessToken.getRequiredClaims();
            assert.deepEqual(
                standardClaims,
                {'iss': 'issuer', 'sub': 'subject', 'iat': clockTimestamp});
          } catch (err) {
            assert.isNull(err);
          }
          done();
        });

        it('should be able to access non standard claims separately',
           function(done) {
             try {
               var nonStandardClaims = implicitAccessToken.getOptionalClaims();
               assert.deepEqual(nonStandardClaims, {'aud': 'audience'});
             } catch (err) {
               assert.isNull(err);
             }
             done();
           });
      });

      describe('when signing a token with standard claim', function() {
        var implicitAccessToken = new ImplicitAccessToken(
            {iss: 'issuer', sub: 'subject', iat: clockTimestamp});
        implicitAccessToken.addOptionalClaims({'aud': 'audience'});
        implicitAccessToken.setNoneAlgorithm(true);

        it('should check standard claim', function(done) {
          implicitAccessToken.toJWT('shhhh').then(function(signedJWT) {
          implicitAccessToken.fromJWT(signedJWT, 'shhhh', {
                                      'iss': 'issuer',
                                      'sub': 'subject',
                                      'aud': 'audience',
                                      'maxAge': '1d'
                                    },
                                    {'clockTimestamp': clockTimestamp})
                                .then(function(decodedPayload) {
                                  assert.isNotNull(decodedPayload);
                                })
                                .catch(function(err) {
                                  assert.isNull(err);
                                });
          });
          done();
        });

        it('should throw when invalid standard claim', function(done) {
          implicitAccessToken.toJWT('shhhh').then(function(signedJWT) {
            implicitAccessToken
                .fromJWT(
                    signedJWT, 'shhhh', {
                      'iss': 'wrong-issuer',
                      'sub': 'subject',
                      'aud': 'audience',
                      'maxAge': '1d'
                    },
                    {'clockTimestamp': clockTimestamp})
                .catch(function(err) {
                  assert.isNotNull(err);
                  assert.equal(err.name, 'JsonWebTokenError');
                });
          });
          done();
        });
      });
    });
  });
});