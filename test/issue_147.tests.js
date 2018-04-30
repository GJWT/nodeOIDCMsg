var expect = require('chai').expect;
var BasicIdToken = require('../src/oicMsg/tokenProfiles/basicIdToken');
var clockTimestamp = 1000000000;

describe('issue 147 - signing with a sealed payload', function() {

  it('should put the expiration claim', function() {
    var basicIdToken = new BasicIdToken(
        {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
    basicIdToken.addOptionalClaims(
        {'hello': 'hello', 'aud': 'audience', 'nbf': clockTimestamp + 2});
    basicIdToken.setNoneAlgorithm(true);
    basicIdToken.toJWT('123', {expiresIn: 10}).then(function(token) {
      basicIdToken
          .fromJWT(
              token, '123', {
                'iss': 'issuer',
                'sub': 'subject',
                'aud': 'audience',
                'maxAge': '1d',
                'clockTolerance': 10,
                'jti': 'jti'
              },
              {'clockTimestamp': clockTimestamp})
          .then(function(result) {
            expect(result.exp).to.be.closeTo(clockTimestamp + 10, 0.2);
          });
    });
  });

});