var fs = require('fs');
var jwt = require('../index');
var JsonWebTokenError = require('../node_modules/src/controllers/messageTypes/jwt/jsonwebtoken/lib/JsonWebTokenError');
var expect = require('chai').expect;

var BasicIdToken = require('../node_modules/src/models/tokenProfiles/basicIdToken');
var assert = require('chai').assert;

var TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M';

describe('verifying without specified secret or public key', function () {
  var clockTimestamp = 1000000000;
  
  var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
  basicIdToken.addNonStandardClaims({"aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
  basicIdToken.setNoneAlgorithm(true);
  var signedJWT = basicIdToken.toJWT('shhhh');
  it('should not verify null', function (done) {
    try{
      var decodedPayload = basicIdToken.fromJWT(signedJWT, null, {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"},{'clockTimestamp' : clockTimestamp});
    }catch(err){
        assert.isNotNull(err);
        done();
    }
  });

  it('should not verify undefined', function (done) {
    try{
      var decodedPayload = basicIdToken.fromJWT(signedJWT,{"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"},{'clockTimestamp' : clockTimestamp});
    }catch(err){
      assert.isNotNull(err);
      done();
    }
    });
});