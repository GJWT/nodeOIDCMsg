var jwt = require('../index');
var expect = require('chai').expect;

var BasicIdToken = require('../src/models/tokenProfiles/basicIdToken');

var clockTimestamp = 1000000000;

describe('when signing a token with a known non standard claim', function () {
    

var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
basicIdToken.addOptionalClaims({"hello": "hello", "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
basicIdToken.setNoneAlgorithm(true);
var signedJWT = basicIdToken.toJWT('123', {algorithm : 'HS256', "keyid": "1234"});

    it('should check known non standard claim', function (done) {
    
        var result = basicIdToken.fromJWT(signedJWT, '123', {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"},{'clockTimestamp' : clockTimestamp, "complete": true});        
        expect(result.header.kid).to.equal('1234');
        done();
    });
});
