var expect = require('chai').expect;
var jwt = require('./..');
var atob = require('atob');
var BasicIdToken = require('../src/models/tokenProfiles/basicIdToken');
var clockTimestamp = 1000000000;

describe('issue 196', function () {
  function b64_to_utf8 (str) {
    return decodeURIComponent(escape(atob( str )));
  }

  it('should use issuer provided in payload.iss', function () {

    var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
    basicIdToken.addNonStandardClaims({"hello": "hello", "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
    basicIdToken.setNoneAlgorithm(true);
    var token = basicIdToken.toJWT('123', {algorithm : 'HS256', "keyid": "1234"});
    var decoded_issuer = JSON.parse(b64_to_utf8(token.split('.')[1])).iss;
    expect(decoded_issuer).to.equal('issuer');
  });
});