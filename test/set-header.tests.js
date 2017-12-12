var jwt = require('../index');
var expect = require('chai').expect;
var BasicIdToken = require('../src/models/tokenProfiles/basicIdToken');


describe('set header', function() {

  it('should add the header', function () {

    var clockTimestamp = 1000000000;
    
    var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
    basicIdToken.addNonStandardClaims({"aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
    basicIdToken.setNoneAlgorithm(true);
    var signedJWT = basicIdToken.toJWT("123", {header: { foo: 'bar' }});    

    var decoded = basicIdToken.fromJWT(signedJWT, "123", {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"},{'clockTimestamp' : clockTimestamp, complete: true});        
  
    expect(decoded.header.foo).to.equal('bar');
    
});

  it('should allow overriding header', function () {
  
    var clockTimestamp = 1000000000;
    
    var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
    basicIdToken.addNonStandardClaims({"aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
    basicIdToken.setNoneAlgorithm(true);
    var signedJWT = basicIdToken.toJWT("123", {header: { alg: 'HS512' }});    

    var decoded = basicIdToken.fromJWT(signedJWT, "123", {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"},{'clockTimestamp' : clockTimestamp, complete: true});        
    expect(decoded.header.alg).to.equal('HS512');
});

});