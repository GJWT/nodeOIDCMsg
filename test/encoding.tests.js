var jwt = require('../index');
var expect = require('chai').expect;
var atob = require('atob');

var BasicIdToken = require('../node_modules/src/models/tokenProfiles/basicIdToken');

describe('encoding', function() {
    var clockTimestamp = 1000000000;
    
  function b64_to_utf8 (str) {
    return decodeURIComponent(escape(atob( str )));
  }

  it('should properly encode the token (utf8)', function () {
    var expected = 'José';

    var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
    basicIdToken.addNonStandardClaims({"name" : expected, "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
    basicIdToken.setNoneAlgorithm(true);
    var signedJWT = basicIdToken.toJWT('shhhh');

    var decoded_name = JSON.parse(b64_to_utf8(signedJWT.split('.')[1])).name;
    expect(decoded_name).to.equal(expected);
  });

  
  it('should properly encode the token (binary)', function () {
    var expected = 'José';

    var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
    basicIdToken.addNonStandardClaims({"name" : expected, "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3}, { encoding: 'binary' });
    basicIdToken.setNoneAlgorithm(true);
    var signedJWT = basicIdToken.toJWT('shhhh', {encoding: 'binary' });

    var decoded_name = JSON.parse(atob(signedJWT.split('.')[1])).name;
    expect(decoded_name).to.equal(expected);
  });

  it('should return the same result when decoding', function () {
    var username = '測試';

    var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
    basicIdToken.addNonStandardClaims({"username" : username, "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
    basicIdToken.setNoneAlgorithm(true);
    var signedJWT = basicIdToken.toJWT('shhhh');

    var payload = basicIdToken.fromJWT(signedJWT, 'shhhh', {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"}, {'clockTimestamp' : clockTimestamp});
    expect(payload.username).to.equal(username);
    
  });

});