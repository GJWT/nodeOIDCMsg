var assert = require('chai').assert;
var BasicIdToken = require('../src/oicMsg/tokenProfiles/basicIdToken');

describe('buffer payload', function() {

  var clockTimestamp = 1000000000;

  var basicIdToken = new BasicIdToken(
      {'iss': 'issuer', 'sub': 'subject', 'iat': clockTimestamp, 'jti': 'jti'});
  var payload = new Buffer('TkJyotZe8NFpgdfnmgINqg==', 'base64');

  basicIdToken.addOptionalClaims({
    'payload': payload,
    'aud': 'audience',
    'nbf': clockTimestamp + 2,
    'exp': clockTimestamp + 3
  });
  basicIdToken.setNoneAlgorithm(true);

  it('should work', function() {
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
                  {'clockTimestamp': clockTimestamp})
              .then(function(result) {
                assert.isNotNull(result.payload);
              });
        });
  });
});