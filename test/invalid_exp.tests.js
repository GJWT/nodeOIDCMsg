var jwt = require('../index');
var expect = require('chai').expect;
var assert = require('chai').assert;
var BasicIdToken = require('../src/oicMsg/tokenProfiles/basicIdToken');

describe('invalid expiration', function() {
  var clockTimestamp = 1000000000;

  it('should fail with string', function(done) {
    var broken_token =
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOiIxMjMiLCJmb28iOiJhZGFzIn0.cDa81le-pnwJMcJi3o3PBwB7cTJMiXCkizIhxbXAKRg';
    var clockTimestamp = 1000000000;
    try {
      var basicIdToken =
          new BasicIdToken('issuer', 'subject', clockTimestamp, 'jti');
      basicIdToken.addOptionalClaims({'aud': 'audience', 'exp': 'string'});
      basicIdToken.setNoneAlgorithm(true);
      var signedJWT = basicIdToken.toJWT('shhhh');
      var decodedPayload = basicIdToken.fromJWT(
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
      done();
    }
  });

  it('should fail with 0', function(done) {
    try {
      var basicIdToken =
          new BasicIdToken('issuer', 'subject', clockTimestamp, 'jti');
      basicIdToken.addOptionalClaims(
          {'aud': 'audience', 'nbf': clockTimestamp + 2, 'exp': 0});
      basicIdToken.setNoneAlgorithm(true);
      var signedJWT = basicIdToken.toJWT('shhhh');
      var decodedPayload = basicIdToken.fromJWT(
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
      done();
    }

  });

  it('should fail with false', function(done) {
    try {
      var basicIdToken =
          new BasicIdToken('issuer', 'subject', clockTimestamp, 'jti');
      basicIdToken.addOptionalClaims(
          {'aud': 'audience', 'nbf': clockTimestamp + 2, 'exp': false});
      basicIdToken.setNoneAlgorithm(true);
      var signedJWT = basicIdToken.toJWT('shhhh');
      var decodedPayload = basicIdToken.fromJWT(
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
      done();
    }

  });

  it('should fail with true', function(done) {
    try {
      var basicIdToken =
          new BasicIdToken('issuer', 'subject', clockTimestamp, 'jti');
      basicIdToken.addOptionalClaims(
          {'aud': 'audience', 'nbf': clockTimestamp + 2, 'exp': true});
      basicIdToken.setNoneAlgorithm(true);
      var signedJWT = basicIdToken.toJWT('shhhh');
      var decodedPayload = basicIdToken.fromJWT(
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
      done();
    }
  });

  it('should fail with object', function(done) {
    try {
      var basicIdToken =
          new BasicIdToken('issuer', 'subject', clockTimestamp, 'jti');
      basicIdToken.addOptionalClaims(
          {'aud': 'audience', 'nbf': clockTimestamp + 2, 'exp': {}});
      basicIdToken.setNoneAlgorithm(true);
      var signedJWT = basicIdToken.toJWT('shhhh');
      var decodedPayload = basicIdToken.fromJWT(
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
      done();
    }

  });

});