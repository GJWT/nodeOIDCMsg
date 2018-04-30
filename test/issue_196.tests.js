var expect = require('chai').expect;
var atob = require('atob');
var BasicIdToken = require('../src/oicMsg/tokenProfiles/basicIdToken');
var clockTimestamp = 1000000000;

describe('issue 196', function() {
  function b64_to_utf8(str) {
    return decodeURIComponent(escape(atob(str)));
  }

  it('should use issuer provided in payload.iss', function(done) {

    var basicIdToken = new BasicIdToken(
        {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
    basicIdToken.addOptionalClaims({
      'hello': 'hello',
      'aud': 'audience',
      'nbf': clockTimestamp + 2,
      'exp': clockTimestamp + 3
    });
    basicIdToken.setNoneAlgorithm(true);
    basicIdToken.toJWT('123', {algorithm: 'HS256', 'keyid': '1234'})
        .then(function(token) {
          var decoded_issuer = JSON.parse(b64_to_utf8(token.split('.')[1])).iss;
          expect(decoded_issuer).to.equal('issuer');
        });
    done();
  });
});