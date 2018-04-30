var expect = require('chai').expect;
var assert = require('chai').assert;
var BasicIdToken = require('../src/oicMsg/tokenProfiles/basicIdToken');

describe('HS256', function() {
  var secret = 'shhhhhh';
  var clockTimestamp = 1000000000;

  describe('when signing a token', function() {
    var basicIdToken = new BasicIdToken(
        {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
    basicIdToken.addOptionalClaims({
      'foo': 'bar',
      'aud': 'audience',
      'nbf': clockTimestamp + 2,
      'exp': clockTimestamp + 3
    });
    basicIdToken.setNoneAlgorithm(true);

    it('should be syntactically valid', function() {
      basicIdToken.toJWT(secret, {algorithm: 'HS256'})
          .then(function(token) {
            expect(token).to.be.a('string');
            expect(token.split('.')).to.have.length(3);
          });
    });

    it('should validate with secret', function(done) {
      basicIdToken.toJWT(secret, {algorithm: 'HS256'}).then(function(token) {
        basicIdToken
            .fromJWT(
                token, secret, {
                  'iss': 'issuer',
                  'sub': 'subject',
                  'aud': 'audience',
                  'maxAge': '1d',
                  'clockTolerance': 10,
                  'jti': 'jti'
                },
                {'clockTimestamp': clockTimestamp})
            .then(function(decoded) {
              assert.ok(decoded.foo);
              assert.equal('bar', decoded.foo);
            });
      });
      done();
    });

    it('should throw with invalid secret', function(done) {
      basicIdToken.toJWT(secret, {algorithm: 'HS256'}).then(function(token) {
        basicIdToken
            .fromJWT(
                token, 'invalid-secret', {
                  'iss': 'issuer',
                  'sub': 'subject',
                  'aud': 'audience',
                  'maxAge': '1d',
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

    it('should throw with secret and token not signed', function(done) {
      basicIdToken = new BasicIdToken(
          {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
      basicIdToken.addOptionalClaims({
        'foo': 'bar',
        'aud': 'audience',
        'nbf': clockTimestamp + 2,
        'exp': clockTimestamp + 3
      });
      basicIdToken.setNoneAlgorithm(true);
      basicIdToken.toJWT(secret, {algorithm: 'none'}).then(function(signed) {
        var unsigned = signed.split('.')[0] + '.' + signed.split('.')[1] + '.';
        basicIdToken
            .fromJWT(
                unsigned, secret, {
                  'iss': 'issuer',
                  'sub': 'subject',
                  'aud': 'audience',
                  'maxAge': '1d',
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

    it('should work with falsy secret and token not signed', function(done) {
      basicIdToken = new BasicIdToken(
          {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
      basicIdToken.addOptionalClaims({
        'foo': 'bar',
        'aud': 'audience',
        'nbf': clockTimestamp + 2,
        'exp': clockTimestamp + 3
      });
      basicIdToken.setNoneAlgorithm(true);
      basicIdToken.toJWT(null, {algorithm: 'none'}).then(function(signed) {
        var unsigned = signed.split('.')[0] + '.' + signed.split('.')[1] + '.';
        basicIdToken
            .fromJWT(
                unsigned, secret, {
                  'iss': 'issuer',
                  'sub': 'subject',
                  'aud': 'audience',
                  'maxAge': '1d',
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

    it('should throw when verifying null', function(done) {
      basicIdToken
          .fromJWT(
              null, secret, {
                'iss': 'issuer',
                'sub': 'subject',
                'aud': 'audience',
                'maxAge': '1d',
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
      done();
    });

    it('should return an error when the token is expired', function(done) {
      basicIdToken = new BasicIdToken(
          {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
      basicIdToken.addOptionalClaims({
        'foo': 'bar',
        'aud': 'audience',
        'nbf': clockTimestamp + 2,
        'exp': 1
      });
      basicIdToken.setNoneAlgorithm(true);
      basicIdToken.toJWT(secret, {algorithm: 'HS256'}).then(function(token) {
        basicIdToken
            .fromJWT(
                token, secret, {
                  'iss': 'issuer',
                  'sub': 'subject',
                  'aud': 'audience',
                  'maxAge': '1d',
                  'clockTolerance': 10,
                  'jti': 'jti'
                },
                {'clockTimestamp': clockTimestamp, algorithm: 'HS256'})
            .then(function() {
              basicIdToken
                  .fromJWT(
                      token, secret, {
                        'iss': 'issuer',
                        'sub': 'subject',
                        'aud': 'audience',
                        'maxAge': '1d',
                        'clockTolerance': 10,
                        'jti': 'jti'
                      },
                      {'clockTimestamp': clockTimestamp, algorithm: 'HS256'})
                  .then(function(decoded) {
                    assert.isUndefined(decoded);
                  })
                  .catch(function(err) {
                    assert.isNotNull(err);
                  });
            });
      });
      done();
    });

    it('should NOT return an error when the token is expired with "ignoreExpiration"',
       function(done) {
         basicIdToken = new BasicIdToken(
             {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
         basicIdToken.addOptionalClaims({
           'foo': 'bar',
           'aud': 'audience',
           'nbf': clockTimestamp + 2,
           'exp': 1
         });
         basicIdToken.setNoneAlgorithm(true);
         basicIdToken.toJWT(secret, {algorithm: 'HS256'}).then(function(token) {
           basicIdToken
               .fromJWT(
                   token, secret, {
                     'iss': 'issuer',
                     'sub': 'subject',
                     'aud': 'audience',
                     'maxAge': '1d',
                     'clockTolerance': 10,
                     'jti': 'jti'
                   },
                   {
                     'clockTimestamp': clockTimestamp,
                     algorithm: 'HS256',
                     ignoreExpiration: true
                   })
               .then(function(decoded) {
                 assert.isNotNull(decoded);
               })
               .catch(function(err) {
                 assert.isNull(err);
               });
         });
         done();
       });

    basicIdToken = new BasicIdToken(
        {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
    it('should default to HS256 algorithm when no options are passed',
       function() {
         basicIdToken.addOptionalClaims({
           'foo': 'bar',
           'aud': 'audience',
           'nbf': clockTimestamp + 2,
           'exp': clockTimestamp + 3
         });
         basicIdToken.setNoneAlgorithm(true);
         basicIdToken.toJWT(secret).then(function(token) {
           basicIdToken
               .fromJWT(
                   token, secret, {
                     'iss': 'issuer',
                     'sub': 'subject',
                     'aud': 'audience',
                     'maxAge': '1d',
                     'clockTolerance': 10,
                     'jti': 'jti'
                   },
                   {'clockTimestamp': clockTimestamp})
               .then(function(verifiedToken) {
                 assert.ok(verifiedToken.foo);
                 assert.equal('bar', verifiedToken.foo);
               });
         });
       });
  });

  describe(
      'should fail verification gracefully with trailing space in the jwt',
      function() {
        var basicIdToken = new BasicIdToken(
            {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
        basicIdToken.addOptionalClaims({
          'foo': 'bar',
          'aud': 'audience',
          'nbf': clockTimestamp + 2,
          'exp': 1
        });
        basicIdToken.setNoneAlgorithm(true);

        it('should return the "invalid token" error', function(done) {
          basicIdToken.toJWT(secret, {algorithm: 'HS256'})
              .then(function(token) {
                var malformedToken =
                    token + ' ';  // corrupt the token by adding a space
                basicIdToken
                    .fromJWT(
                        malformedToken, secret, {
                          'iss': 'issuer',
                          'sub': 'subject',
                          'aud': 'audience',
                          'maxAge': '1d',
                          'clockTolerance': 10,
                          'jti': 'jti'
                        },
                        {
                          'clockTimestamp': clockTimestamp,
                          algorithm: 'HS256',
                          ignoreExpiration: true
                        })
                    .catch(function(err) {
                      assert.isNotNull(err);
                      assert.equal('JsonWebTokenError', err.name);
                      assert.equal('invalid token', err.message);
                    });
              });
          done();
        });
      });

});