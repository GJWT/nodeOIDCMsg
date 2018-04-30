var assert = require('chai').assert;
var BasicIdToken = require('../src/oicMsg/tokenProfiles/basicIdToken');

describe('invalid expiration', function() {
  var clockTimestamp = 1000000000;

  it('should fail with string', function(done) {
    try {
      var basicIdToken = new BasicIdToken(
          {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
      basicIdToken.addOptionalClaims({'aud': 'audience', 'exp': 'string'});
      basicIdToken.setNoneAlgorithm(true);
      var signedJWT = basicIdToken.toJWT('shhhh');
      basicIdToken.fromJWT(
          signedJWT, 'shhhh', {
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

  it('should fail with 0', function(done) {
    try {
      var basicIdToken = new BasicIdToken(
          {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
      basicIdToken.addOptionalClaims(
          {'aud': 'audience', 'nbf': clockTimestamp + 2, 'exp': 0});
      basicIdToken.setNoneAlgorithm(true);
      var signedJWT = basicIdToken.toJWT('shhhh');
      basicIdToken.fromJWT(
          signedJWT, 'shhhh', {
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

  it('should fail with false', function(done) {
    try {
      var basicIdToken = new BasicIdToken(
          {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
      basicIdToken.addOptionalClaims(
          {'aud': 'audience', 'nbf': clockTimestamp + 2, 'exp': false});
      basicIdToken.setNoneAlgorithm(true);
      var signedJWT = basicIdToken.toJWT('shhhh');
      basicIdToken.fromJWT(
          signedJWT, 'shhhh', {
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

  it('should fail with true', function(done) {
    try {
      var basicIdToken = new BasicIdToken(
          {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
      basicIdToken.addOptionalClaims(
          {'aud': 'audience', 'nbf': clockTimestamp + 2, 'exp': true});
      basicIdToken.setNoneAlgorithm(true);
      var signedJWT = basicIdToken.toJWT('shhhh');
      basicIdToken.fromJWT(
          signedJWT, 'shhhh', {
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

  it('should fail with object', function(done) {
    try {
      var basicIdToken = new BasicIdToken(
          {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
      basicIdToken.addOptionalClaims(
          {'aud': 'audience', 'nbf': clockTimestamp + 2, 'exp': {}});
      basicIdToken.setNoneAlgorithm(true);
      let signedJWT = basicIdToken.toJWT('shhhh');
      basicIdToken.fromJWT(
          signedJWT, 'shhhh', {
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