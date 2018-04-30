var expect = require('chai').expect;
var BasicIdToken = require('../src/oicMsg/tokenProfiles/basicIdToken');

describe('non_object_values values', function() {

  it('should work with string', function() {
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
    basicIdToken.toJWT('123', {algorithm: 'HS256'}).then(function(signedJWT) {
      basicIdToken
          .fromJWT(
              signedJWT, '123', {
                'iss': 'issuer',
                'sub': 'subject',
                'aud': 'audience',
                'maxAge': '1d',
                'clockTolerance': 10,
                'jti': 'jti'
              },
              {'clockTimestamp': clockTimestamp})
          .then(function(result) {
            expect(result.hello).to.equal('hello');
          });
    });
  });

  it('should work with number', function() {
    var clockTimestamp = 1000000000;

    var basicIdToken = new BasicIdToken(
        {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
    basicIdToken.addOptionalClaims({
      'data': 123,
      'aud': 'audience',
      'nbf': clockTimestamp + 2,
      'exp': clockTimestamp + 3
    });
    basicIdToken.setNoneAlgorithm(true);
    basicIdToken.toJWT('123', {algorithm: 'HS256'}).then(function(signedJWT) {
      basicIdToken
          .fromJWT(
              signedJWT, '123', {
                'iss': 'issuer',
                'sub': 'subject',
                'aud': 'audience',
                'maxAge': '1d',
                'clockTolerance': 10,
                'jti': 'jti'
              },
              {'clockTimestamp': clockTimestamp})
          .then(function(result) {
            expect(result.data).to.equal(123);
          });
    });
  });
});