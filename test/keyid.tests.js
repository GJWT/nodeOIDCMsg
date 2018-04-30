var expect = require('chai').expect;

var BasicIdToken = require('../src/oicMsg/tokenProfiles/basicIdToken');

var clockTimestamp = 1000000000;

describe('when signing a token with a known non standard claim', function() {


  var basicIdToken = new BasicIdToken(
      {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
  basicIdToken.addOptionalClaims({
    'hello': 'hello',
    'aud': 'audience',
    'nbf': clockTimestamp + 2,
    'exp': clockTimestamp + 3
  });
  basicIdToken.setNoneAlgorithm(true);

  it('should check known non standard claim', function(done) {
    basicIdToken.toJWT('123', {algorithm: 'HS256', 'keyid': '1234'})
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
                  {'clockTimestamp': clockTimestamp, 'complete': true})
              .then(function(result) {
                expect(result.header.kid).to.equal('1234');
              });
        });
    done();
  });
});