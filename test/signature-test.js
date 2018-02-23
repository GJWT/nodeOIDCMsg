var jwt = require('../index');

var expect = require('chai').expect;
var assert = require('chai').assert;

var BasicIdToken = require('../src/oicMsg/tokenProfiles/basicIdToken');

describe('HS256', function() {

  describe('when signing a token', function() {
    var secret = 'shhhhhh';
    var clockTimestamp = 1000000000;

    var basicIdToken =
        new BasicIdToken('issuer', 'subject', clockTimestamp, 'jti');
    basicIdToken.addOptionalClaims({'foo': 'bar', 'aud': 'audience'});
    basicIdToken.setNoneAlgorithm(true);
    var signedJWT = basicIdToken.toJWT('shhhh', {algorithm: 'HS256'});

    it('should validate with secret', function(done) {
      try {
        var decodedPayload = basicIdToken.fromJWT(
            signedJWT, 'shhhh', {
              'iss': 'issuer',
              'sub': 'subject',
              'maxAge': '1d',
              'clockTolerance': 10,
              'aud': 'audience',
              'jti': 'jti'
            },
            {'clockTimestamp': clockTimestamp});
      } catch (err) {
        assert.isNull(err);
      }
      done();
    });

    it('should throw with invalid secret', function(done) {
      try {
        var decodedPayload = basicIdToken.fromJWT(
            signedJWT, 'wrong-secret', {
              'iss': 'issuer',
              'sub': 'subject',
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

    it('should throw when verifying null', function(done) {
      try {
        var decodedPayload = basicIdToken.fromJWT(
            null, 'shhhh', {
              'iss': 'issuer',
              'sub': 'subject',
              'aud': 'audience',
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
