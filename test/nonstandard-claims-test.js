var jwt = require('../index');
var expect = require('chai').expect;
var path = require('path');
var assert = require('chai').assert;
var BasicIdToken = require('../src/models/tokenProfiles/basicIdToken');

describe('iat', function () {

  it('should work with a exp calculated based on numeric iat', function (done) {
    var dateNow = Math.floor(Date.now() / 1000);
    var iat = dateNow - 30;
    var expiresInVal = 50;
    var basicIdToken = new BasicIdToken('issuer','subject', iat, "jti");
    basicIdToken.addOptionalClaims({"aud" : "audience"});
    var signedJWT = basicIdToken.toJWT('shhhh', {expiresIn: expiresInVal});

    try{
      var verificationClaims = {'iss': 'issuer','sub' : 'subject', 'aud' : 'audience', 'maxAge': '1d', 'jti': 'jti'};
      var decodedPayload = basicIdToken.fromJWT(signedJWT, 'shhhh', verificationClaims, {algorithms: ['HS256']});
    
      expect(decodedPayload.exp).to.be.closeTo(iat + expiresInVal, 0.2);
      
    }catch(err){
      assert.isNotNull(decodedPayload);
      assert.isNull(err);
    }
    done();
  });

  it('should throw if nbf or exp value does not match clock tolerance', function (done) {
    var clockTimestamp = 1000000000;
    
    var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
    basicIdToken.addOptionalClaims({"aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
    basicIdToken.setNoneAlgorithm(true);
    var signedJWT = basicIdToken.toJWT('shhhh');
    try{
      var decodedPayload = basicIdToken.fromJWT(signedJWT, 'shhhh', {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 0.001, "jti": "jti"}, {'clockTimestamp' : clockTimestamp});
    }catch(err){
      assert.isNotNull(err);
    }
    done();
  });

  it('should check if iat does not match the max age value provided', function (done) {
    var clockTimestamp = 1000000000;
    
    var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
    basicIdToken.addOptionalClaims({"aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
    basicIdToken.setNoneAlgorithm(true);
    var signedJWT = basicIdToken.toJWT('shhhh');
    try{
      var decodedPayload = basicIdToken.fromJWT(signedJWT, 'shhhh', {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '6d', 'clockTolerance' : 10, "jti": "jti"}, {'clockTimestamp' : clockTimestamp});
    }catch(err){
      assert.isNotNull(err);
    }
    done();
  });

  it('should throw if clock Tolerance is not provided', function (done) {
    var clockTimestamp = 1000000000;
    
    var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
    basicIdToken.addOptionalClaims({"aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
    basicIdToken.setNoneAlgorithm(true);
    var signedJWT = basicIdToken.toJWT('shhhh');
    try{
      var decodedPayload = basicIdToken.fromJWT(signedJWT, 'shhhh', {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', "jti": "jti"}, {'clockTimestamp' : clockTimestamp});
    }catch(err){
      assert.isNotNull(err);
    }
    done();
  });

  it('should throw if iat does not match the max age value provided', function (done) {
    var clockTimestamp = 1000000000;
    
    var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
    basicIdToken.addOptionalClaims({"aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
    basicIdToken.setNoneAlgorithm(true);
    var signedJWT = basicIdToken.toJWT('shhhh');
    try{
      var decodedPayload = basicIdToken.fromJWT(signedJWT, 'shhhh', {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'clockTolerance' : 10, "jti": "jti"}, {'clockTimestamp' : clockTimestamp});
    }catch(err){
      assert.isNotNull(err);
    }
    done();
  });


});

