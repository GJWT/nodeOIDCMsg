var fs = require('fs');
var path = require('path');

var expect = require('chai').expect;
var assert = require('chai').assert;
var ms = require('ms');
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
      var pub = algorithms[algorithm].pub_key;
      var priv = algorithms[algorithm].priv_key;

      // "invalid" means it is not the public key for the loaded "priv" key
      var invalid_pub = algorithms[algorithm].invalid_pub_key;

      describe('when signing a token', function() {
        var clockTimestamp = 1000000000;

        var basicIdToken = new BasicIdToken(
            {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
        basicIdToken.addOptionalClaims({'foo': 'bar', 'aud': 'audience'});
        basicIdToken.setNoneAlgorithm(true);

        it('should be syntactically valid', function() {
          basicIdToken.toJWT(priv, {algorithm: algorithm})
              .then(function(token) {

                expect(token).to.be.a('string');
                expect(token.split('.')).to.have.length(3);
              });
        });

        context('asynchronous', function() {
          it('should validate with public key', function(done) {
            basicIdToken.toJWT(priv, {algorithm: algorithm})
                .then(function(token) {

                  basicIdToken
                      .fromJWT(
                          token, pub, {
                            'foo': 'bar',
                            'iss': 'issuer',
                            'sub': 'subject',
                            'aud': 'audience',
                            'maxAge': '3s',
                            'clockTolerance': 10,
                            'jti': 'jti'
                          },
                          {'clockTimestamp': clockTimestamp})
                      .then(function(decoded) {
                        assert.ok(decoded.iss);
                        assert.equal('issuer', decoded.iss);
                      });
                });
            done();
          });

          it('should throw with invalid public key', function(done) {
            basicIdToken.toJWT(priv, {algorithm: algorithm})
                .then(function(token) {

                  basicIdToken
                      .fromJWT(
                          token, invalid_pub, {
                            'foo': 'bar',
                            'iss': 'issuer',
                            'sub': 'subject',
                            'aud': 'audience',
                            'maxAge': '3s',
                            'clockTolerance': 10,
                            'jti': 'jti'
                          },
                          {'clockTimestamp': clockTimestamp})
                      .then(function(decoded) {
                        assert.isUndefined(decoded);
                      })
                      .catch(function(err) {
                        assert.isNotNull(err);
                      });
                });
            done();
          });
        });

        context('synchronous', function() {
          it('should validate with public key', function(done) {
            basicIdToken.toJWT(priv, {algorithm: algorithm})
                .then(function(token) {

                  basicIdToken
                      .fromJWT(
                          token, pub, {
                            'foo': 'bar',
                            'iss': 'issuer',
                            'sub': 'subject',
                            'aud': 'audience',
                            'maxAge': '3s',
                            'clockTolerance': 10,
                            'jti': 'jti'
                          },
                          {'clockTimestamp': clockTimestamp})
                      .then(function(decoded) {
                        assert.ok(decoded.iss);
                        assert.equal('issuer', decoded.iss);
                      });
                });
            done();
          });

          it('should throw with invalid public key synchronous',
             function(done) {
               basicIdToken.toJWT(priv, {algorithm: algorithm})
                   .then(function(token) {
                     basicIdToken
                         .fromJWT(
                             token, invalid_pub, {
                               'foo': 'bar',
                               'iss': 'issuer',
                               'sub': 'subject',
                               'aud': 'audience',
                               'maxAge': '3s',
                               'clockTolerance': 10,
                               'jti': 'jti'
                             },
                             {'clockTimestamp': clockTimestamp})
                         .then(function(decoded) {
                           assert.isUndefined(decoded);
                         })
                         .catch(function(err) {
                           assert.isNotNull(err);
                         });
                   });
                   done();
             });
        });
      });


      describe('when signing a token with expiration', function() {
        var clockTimestamp = 1000000000;

        var basicIdToken = new BasicIdToken(
            {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
        basicIdToken.addOptionalClaims({'foo': 'bar', 'aud': 'audience'});
        basicIdToken.setNoneAlgorithm(true);

        it('should be valid expiration', function(done) {
          basicIdToken.toJWT(priv, {expiresIn: '10m', algorithm: algorithm})
              .then(function(token) {
                basicIdToken
                    .fromJWT(
                        token, pub, {
                          'foo': 'bar',
                          'iss': 'issuer',
                          'sub': 'subject',
                          'aud': 'audience',
                          'maxAge': '3s',
                          'clockTolerance': 10,
                          'jti': 'jti'
                        },
                        {'clockTimestamp': clockTimestamp})
                    .then(function(decoded) {
                      assert.isNotNull(decoded);
                    })
                    .catch(function(err) {
                      assert.isNull(err);
                    });
              });
          done();
        });

        it('should be invalid', function(done) {

          basicIdToken = new BasicIdToken(
              {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
          basicIdToken.addOptionalClaims({'foo': 'bar', 'aud': 'audience'});
          basicIdToken.setNoneAlgorithm(true);
          basicIdToken
              .toJWT(priv, {expiresIn: -1 * ms('10m'), algorithm: algorithm})
              .then(function(token) {
                basicIdToken
                    .fromJWT(
                        token, pub, {
                          'foo': 'bar',
                          'iss': 'issuer',
                          'sub': 'subject',
                          'aud': 'audience',
                          'maxAge': '3s',
                          'clockTolerance': 10,
                          'jti': 'jti'
                        },
                        {'clockTimestamp': clockTimestamp})
                    .then(function(decoded) {
                      assert.isUndefined(decoded);
                    })
                    .catch(function(err) {
                      assert.isNotNull(err);
                      assert.equal(err.name, 'TokenExpiredError');
                      assert.instanceOf(err.expiredAt, Date);
                    });
              });
          done();
        });

        it('should NOT be invalid', function(done) {
          basicIdToken = new BasicIdToken(
              {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
          basicIdToken.addOptionalClaims({'foo': 'bar', 'aud': 'audience'});
          basicIdToken.setNoneAlgorithm(true);
          basicIdToken
              .toJWT(priv, {expiresIn: -1 * ms('10m'), algorithm: algorithm})
              .then(function(token) {
                basicIdToken
                    .fromJWT(
                        token, pub, {
                          'foo': 'bar',
                          'iss': 'issuer',
                          'sub': 'subject',
                          'aud': 'audience',
                          'maxAge': '3s',
                          'clockTolerance': 10,
                          'jti': 'jti'
                        },
                        {
                          'clockTimestamp': clockTimestamp,
                          ignoreExpiration: true
                        })
                    .then(function(decoded) {
                      assert.ok(decoded.iss);
                      assert.equal('issuer', decoded.iss);
                    });
              });
          done();
        });
      });

      describe('when signing a token with not before', function() {
        var clockTimestamp = 1000000000;        
        var basicIdToken = new BasicIdToken(
            {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
        basicIdToken.addOptionalClaims({'foo': 'bar', 'aud': 'audience'});
        basicIdToken.setNoneAlgorithm(true);

        it('should be valid expiration', function(done) {
          basicIdToken
              .toJWT('shhh', {notBefore: -10 * 3600, algorithm: 'HS256'})
              .then(function(token) {
                basicIdToken
                    .fromJWT(
                        token, 'shhh', {
                          'foo': 'bar',
                          'iss': 'issuer',
                          'sub': 'subject',
                          'aud': 'audience',
                          'maxAge': '3s',
                          'clockTolerance': 500,
                          'jti': 'jti'
                        },
                        {'clockTimestamp': clockTimestamp})
                    .then(function(decoded) {
                      assert.isNotNull(decoded);
                    })
                    .catch(function(err) {
                      assert.isNull(err);
                    });
              });
          done();
        });



        it('should be invalid', function(done) {
          basicIdToken = new BasicIdToken(
              {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
          basicIdToken.addOptionalClaims({'foo': 'bar', 'aud': 'audience'});
          basicIdToken.setNoneAlgorithm(true);
          basicIdToken.toJWT(priv, {notBefore: '10m', algorithm: algorithm})
              .then(function(token) {
                basicIdToken
                    .fromJWT(
                        token, pub, {
                          'foo': 'bar',
                          'iss': 'issuer',
                          'sub': 'subject',
                          'aud': 'audience',
                          'maxAge': '3s',
                          'clockTolerance': 10,
                          'jti': 'jti'
                        },
                        {'clockTimestamp': clockTimestamp})
                    .then(function(decoded) {
                      assert.isUndefined(decoded);
                    })
                    .catch(function(err) {
                      assert.isNotNull(err);
                      assert.equal(err.name, 'NotBeforeError');
                      assert.instanceOf(err.date, Date);
                    });
              });
          done();
        });

        it('should be valid when date are equals', function(done) {
          basicIdToken = new BasicIdToken(
              {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
          basicIdToken.addOptionalClaims({'foo': 'bar', 'aud': 'audience'});
          basicIdToken.setNoneAlgorithm(true);
          basicIdToken.toJWT('shh', {notBefore: 0, algorithm: 'HS256'})
              .then(function(token) {
                basicIdToken
                    .fromJWT(
                        token, 'shh', {
                          'foo': 'bar',
                          'iss': 'issuer',
                          'sub': 'subject',
                          'aud': 'audience',
                          'maxAge': '3s',
                          'clockTolerance': 10,
                          'jti': 'jti'
                        },
                        {'clockTimestamp': clockTimestamp})
                    .then(function(decoded) {
                      assert.isNotNull(decoded);
                    })
                    .catch(function(err) {
                      assert.isNull(err);
                    });
              });
          done();
        });

        it('should NOT be invalid', function(done) {
          basicIdToken = new BasicIdToken(
              {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
          basicIdToken.addOptionalClaims({'foo': 'bar', 'aud': 'audience'});
          basicIdToken.setNoneAlgorithm(true);
          basicIdToken.toJWT(priv, {notBefore: 0, algorithm: algorithm})
              .then(function(token) {
                basicIdToken
                    .fromJWT(
                        token, pub, {
                          'foo': 'bar',
                          'iss': 'issuer',
                          'sub': 'subject',
                          'aud': 'audience',
                          'maxAge': '3s',
                          'clockTolerance': 10,
                          'jti': 'jti'
                        },
                        {
                          'clockTimestamp': clockTimestamp,
                          ignoreNotBefore: true
                        })
                    .then(function(decoded) {
                      assert.ok(decoded.iss);
                      assert.equal('issuer', decoded.iss);
                    });
              });
          done();
        });
      });


      describe('when signing a token without audience', function() {
        var clockTimestamp = 1511783267;

        var basicIdToken = new BasicIdToken(
            {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
        basicIdToken.addOptionalClaims({'foo': 'bar', 'aud': 'urn:foo'});
        basicIdToken.setNoneAlgorithm(true);

        it('should check audience using RegExp', function(done) {
          basicIdToken.toJWT('shh', {algorithm: 'HS256'})
              .then(function(token) {
                basicIdToken
                            .fromJWT(
                                token, 'shh', {
                                  'foo': 'bar',
                                  'aud': /urn:f[o]{2}/,
                                  'iss': 'issuer',
                                  'sub': 'subject',
                                  'maxAge': '3s',
                                  'clockTolerance': 10,
                                  'jti': 'jti'
                                },
                                {'clockTimestamp': clockTimestamp})
                            .catch(function(err) {
                              assert.isNull(err);
                            });
              });
          done();
        });

        it('should throw invalid audience using RegExp', function(done) {

          basicIdToken.toJWT('shh', {algorithm: 'HS256'})
              .then(function(token) {
              basicIdToken
                          .fromJWT(
                              token, 'shh', {
                                'foo': 'bar',
                                'aud': /urn:wrong/,
                                'iss': 'issuer',
                                'sub': 'subject',
                                'maxAge': '3s',
                                'clockTolerance': 10,
                                'jti': 'jti'
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



      describe('when signing a token with jwt id', function() {

        var clockTimestamp = 1511783267;

        var basicIdToken = new BasicIdToken(
            {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jwtid'});
        basicIdToken.addOptionalClaims({'foo': 'bar', 'aud': 'audience'});
        basicIdToken.setNoneAlgorithm(true);
        it('should check jwt id', function(done) {
          basicIdToken.toJWT('shh', {algorithm: 'HS256'}).then(function(token) {
            basicIdToken
                .fromJWT(
                    token, 'shh', {
                      'foo': 'bar',
                      'aud': 'audience',
                      'iss': 'issuer',
                      'sub': 'subject',
                      'maxAge': '3s',
                      'clockTolerance': 10,
                      'jti': 'jwtid'
                    },
                    {'clockTimestamp': clockTimestamp, jwtid: 'jwtid'})
                .then(function(decoded) {
                  assert.isNotNull(decoded);
                })
                .catch(function(err) {
                  assert.isNull(err);
                });
          });
          done();
        });

        it('should throw when invalid jwt id', function(done) {
          basicIdToken.toJWT('shh', {algorithm: 'HS256'}).then(function(token) {
            basicIdToken
                .fromJWT(
                    token, pub, {
                      'foo': 'bar',
                      'aud': 'audience',
                      'iss': 'issuer',
                      'sub': 'subject',
                      'maxAge': '3s',
                      'clockTolerance': 10,
                      'jti': 'jti'
                    },
                    {'clockTimestamp': clockTimestamp, jwtid: 'wrongJwtid'})
                .then(function(decoded) {
                  assert.isUndefined(decoded);
                })
                .catch(function(err) {
                  assert.isNotNull(err);
                  assert.equal(err.name, 'JsonWebTokenError');
                });
          });
          done();
        });
      });

      describe('when verifying a malformed token', function() {

        var clockTimestamp = 1511783267;

        var basicIdToken = new BasicIdToken(
            {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jwtid'});

        it('should throw', function(done) {

          basicIdToken
              .fromJWT(
                  'fruit.fruit.fruit', pub, {
                    'foo': 'bar',
                    'aud': 'audience',
                    'iss': 'issuer',
                    'sub': 'subject',
                    'maxAge': '3s',
                    'clockTolerance': 10,
                    'jti': 'jwtid'
                  },
                  {'clockTimestamp': clockTimestamp, jwtid: 'jwtid'})
              .then(function(decoded) {
                assert.isUndefined(decoded);
              })
              .catch(function(err) {
                assert.isNotNull(err);
                assert.equal(err.name, 'JsonWebTokenError');
              });
          done();
        });
      });


      describe('when decoding a jwt token with additional parts', function() {

        var clockTimestamp = 1511783267;

        var basicIdToken = new BasicIdToken(
            {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jwtid'});
        basicIdToken.addOptionalClaims({'foo': 'bar', 'aud': 'audience'});
        basicIdToken.setNoneAlgorithm(true);
        it('should throw', function(done) {
          basicIdToken.toJWT(priv, {algorithm: algorithm})
              .then(function(token) {
                basicIdToken
                    .fromJWT(
                        token + '.foo', pub, {
                          'foo': 'bar',
                          'aud': 'audience',
                          'iss': 'issuer',
                          'sub': 'subject',
                          'maxAge': '3s',
                          'clockTolerance': 10,
                          'jti': 'jwtid'
                        },
                        {'clockTimestamp': clockTimestamp, jwtid: 'jwtid'})
                    .then(function(decoded) {
                      assert.isUndefined(decoded);
                    })
                    .catch(function(err) {
                      assert.isNotNull(err);
                      assert.equal(err.name, 'JsonWebTokenError');
                    });
              });
          done();
        });
      });



      describe('when decoding a invalid jwt token', function() {
        var clockTimestamp = 1511783267;

        var basicIdToken = new BasicIdToken(
            {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jwtid'});

        it('should return null', function(done) {
          basicIdToken
              .fromJWT(
                  'whatever.token', pub, {
                    'foo': 'bar',
                    'aud': 'audience',
                    'iss': 'issuer',
                    'sub': 'subject',
                    'maxAge': '3s',
                    'clockTolerance': 10,
                    'jti': 'jwtid'
                  },
                  {'clockTimestamp': clockTimestamp, jwtid: 'jwtid'})
              .then(function(decoded) {
                assert.isUndefined(decoded);
              })
              .catch(function(err) {
                assert.isNotNull(err);
                assert.equal(err.name, 'JsonWebTokenError');
              });
          done();
        });
      });
    });
  });
});