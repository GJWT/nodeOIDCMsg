var expect = require('chai').expect;
var BasicIdToken = require('../src/oicMsg/tokenProfiles/basicIdToken');

describe('set header', function() {

  it('should add the header', function() {

    var clockTimestamp = 1000000000;

    var basicIdToken = new BasicIdToken(
        {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
    basicIdToken.addOptionalClaims({
      'aud': 'audience',
      'nbf': clockTimestamp + 2,
      'exp': clockTimestamp + 3
    });
    basicIdToken.setNoneAlgorithm(true);
    basicIdToken.toJWT('123', {header: {foo: 'bar'}}).then(function(signedJWT) {
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
              {'clockTimestamp': clockTimestamp, complete: true})
          .then(function(decoded) {
            expect(decoded.header.foo).to.equal('bar');
          });
    });
  });

  it('should allow overriding header', function() {
    var clockTimestamp = 1000000000;

    var basicIdToken = new BasicIdToken(
        {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
    basicIdToken.addOptionalClaims({
      'aud': 'audience',
      'nbf': clockTimestamp + 2,
      'exp': clockTimestamp + 3
    });
    basicIdToken.setNoneAlgorithm(true);
    basicIdToken.toJWT('123', {header: {alg: 'HS512'}})
        .then(function(signedJWT) {
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
                  {'clockTimestamp': clockTimestamp, complete: true})
              .then(function(decoded) {
                expect(decoded.header.alg).to.equal('HS512');
              });
        });
  });
});