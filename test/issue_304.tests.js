var BasicIdToken = require('../src/oicMsg/tokenProfiles/basicIdToken');
var assert = require('chai').assert;

describe('issue 304 - verifying values other than strings', function() {
  var clockTimestamp = 1000000000;

  var basicIdToken = new BasicIdToken(
      {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
  basicIdToken.addOptionalClaims({
    'hello': 'hello',
    'aud': 'audience',
    'nbf': clockTimestamp + 2,
    'exp': clockTimestamp + 3
  });
  basicIdToken.setNoneAlgorithm(true);
  it('should fail with numbers', function(done) {
    basicIdToken.toJWT('123', {algorithm: 'HS256', 'keyid': '1234'})
        .then(function() {
          basicIdToken
              .fromJWT(
                  123, '123', {
                    'iss': 'issuer',
                    'sub': 'subject',
                    'aud': 'audience',
                    'maxAge': '1d',
                    'clockTolerance': 10,
                    'jti': 'jti'
                  },
                  {'clockTimestamp': clockTimestamp, 'complete': true})
              .catch(function(err) {
                assert.isNotNull(err);
              });
        });
    done();
  });

  it('should fail with objects', function(done) {
    basicIdToken.toJWT('123', {algorithm: 'HS256', 'keyid': '1234'})
        .then(function() {
          basicIdToken
              .fromJWT(
                  {foo: 'bar'}, '123', {
                    'iss': 'issuer',
                    'sub': 'subject',
                    'aud': 'audience',
                    'maxAge': '1d',
                    'clockTolerance': 10,
                    'jti': 'jti'
                  },
                  {'clockTimestamp': clockTimestamp, 'complete': true})
              .catch(function(err) {
                assert.isNotNull(err);
              });
        });
    done();
  });

  it('should fail with arrays', function(done) {
    basicIdToken.toJWT('123', {algorithm: 'HS256', 'keyid': '1234'})
        .then(function() {
          basicIdToken
              .fromJWT(
                  ['foo'], '123', {
                    'iss': 'issuer',
                    'sub': 'subject',
                    'aud': 'audience',
                    'maxAge': '1d',
                    'clockTolerance': 10,
                    'jti': 'jti'
                  },
                  {'clockTimestamp': clockTimestamp, 'complete': true})
              .catch(function(err) {
                assert.isNotNull(err);
              });
        });
    done();
  });

  it('should fail with functions', function(done) {
    basicIdToken.toJWT('123', {algorithm: 'HS256', 'keyid': '1234'})
        .then(function() {
          basicIdToken
              .fromJWT(
                  function() {}, '123', {
                    'iss': 'issuer',
                    'sub': 'subject',
                    'aud': 'audience',
                    'maxAge': '1d',
                    'clockTolerance': 10,
                    'jti': 'jti'
                  },
                  {'clockTimestamp': clockTimestamp, 'complete': true})
              .catch(function(err) {
                assert.isNotNull(err);
              });
        });
    done();
  });

  it('should fail with booleans', function(done) {
    basicIdToken.toJWT('123', {algorithm: 'HS256', 'keyid': '1234'})
        .then(function() {
          basicIdToken
              .fromJWT(
                  true, '123', {
                    'iss': 'issuer',
                    'sub': 'subject',
                    'aud': 'audience',
                    'maxAge': '1d',
                    'clockTolerance': 10,
                    'jti': 'jti'
                  },
                  {'clockTimestamp': clockTimestamp, 'complete': true})
              .catch(function(err) {
                assert.isNotNull(err);
              });
        });
    done();
  });

});