var jwt = require("../.");
var assert = require('chai').assert;
var BasicIdToken = require('../src/models/tokenProfiles/basicIdToken');

describe('buffer payload', function () {

    var clockTimestamp = 1000000000;
    
    var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
    var payload = new Buffer('TkJyotZe8NFpgdfnmgINqg==', 'base64');
    
    basicIdToken.addOptionalClaims({"payload": payload, "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
    basicIdToken.setNoneAlgorithm(true);
    var signedJWT = basicIdToken.toJWT('123', {algorithm : 'HS256', "keyid": "1234"});

  it('should work', function () {
    var result = basicIdToken.fromJWT(signedJWT, '123', {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"},{'clockTimestamp' : clockTimestamp});        
    assert.isNotNull(result.payload);
  });
});