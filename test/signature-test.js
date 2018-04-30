var assert = require('chai').assert;

var BasicIdToken = require('../src/oicMsg/tokenProfiles/basicIdToken');

describe('HS256', function() {

  describe('when signing a token', function() {
    var clockTimestamp = 1000000000;

    var basicIdToken = new BasicIdToken(
        {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
    basicIdToken.addOptionalClaims({'foo': 'bar', 'aud': 'audience'});
    basicIdToken.setNoneAlgorithm(true);

    it('should validate with secret', function(done) {
      basicIdToken.toJWT('shhhh', {algorithm: 'HS256'})
          .then(function(signedJWT) {
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
                .then(function() {})
                .catch(function(err) {
                  assert.isNull(err);
                });
          });
      done();
    });

    it('should throw with invalid secret', function(done) {
      basicIdToken.toJWT('shhhh', {algorithm: 'HS256'})
          .then(function(signedJWT) {
            basicIdToken
                .fromJWT(
                    signedJWT, 'wrong-secret', {
                      'iss': 'issuer',
                      'sub': 'subject',
                      'maxAge': '1d',
                      'clockTolerance': 10,
                      'jti': 'jti'
                    },
                    {'clockTimestamp': clockTimestamp})
                .then(function() {})
                .catch(function(err) {
                  assert.isNotNull(err);
                });
          });
      done();
    });

    it('should throw when verifying null', function(done) {
      basicIdToken.toJWT('shhhh', {algorithm: 'HS256'})
          .then(function() {
            basicIdToken.fromJWT(
                null, 'shhhh', {
                  'iss': 'issuer',
                  'sub': 'subject',
                  'aud': 'audience',
                  'maxAge': '1d',
                  'clockTolerance': 10,
                  'jti': 'jti'
                },
                {'clockTimestamp': clockTimestamp});
          })
          .then(function() {})
          .catch(function(err) {
            assert.isNotNull(err);
          });
      done();
    });
  });
});