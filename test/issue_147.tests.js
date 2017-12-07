var jwt = require('../index');
var expect = require('chai').expect;
var BasicIdToken = require('../node_modules/src/models/tokenProfiles/basicIdToken');
var clockTimestamp = 1000000000;

describe('issue 147 - signing with a sealed payload', function() {

  it('should put the expiration claim', function () {
    /*var token = jwt.sign(Object.seal({foo: 123}), '123', { expiresIn: 10 });
    var result = jwt.verify(token, '123');
    expect(result.exp).to.be.closeTo(Math.floor(Date.now() / 1000) + 10, 0.2);*/

    var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
    basicIdToken.addNonStandardClaims({"hello": "hello", "aud" : "audience", "nbf" : clockTimestamp + 2});
    basicIdToken.setNoneAlgorithm(true);
    var token = basicIdToken.toJWT('123', { expiresIn: 10});

    var result = basicIdToken.fromJWT(token, "123", {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"},{'clockTimestamp' : clockTimestamp});        
    expect(result.exp).to.be.closeTo(clockTimestamp + 10, 0.2);
    
  });

});