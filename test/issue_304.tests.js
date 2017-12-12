var jwt = require('../index');
var expect = require('chai').expect;
var BasicIdToken = require('../src/models/tokenProfiles/basicIdToken');
var assert = require('chai').assert;

describe('issue 304 - verifying values other than strings', function() {
    var clockTimestamp = 1000000000;
    
    var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
    basicIdToken.addNonStandardClaims({"hello": "hello", "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
    basicIdToken.setNoneAlgorithm(true);
    var signedJWT = basicIdToken.toJWT('123', {algorithm : 'HS256', "keyid": "1234"});
  it('should fail with numbers', function (done) {
      try{
        var result = basicIdToken.fromJWT(123, '123', {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"},{'clockTimestamp' : clockTimestamp, "complete": true});        
        
        //var result = basicIdToken.fromJWT(signedJWT, '123', 123, {'clockTimestamp' : clockTimestamp, "complete": true});        
      }catch(err){
        assert.isNotNull(err);
        done();
      }
  });

  
  it('should fail with objects', function (done) {
    try{
        var result = basicIdToken.fromJWT({ foo: 'bar' }, '123', {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"},{'clockTimestamp' : clockTimestamp, "complete": true});        
        
        //var result = basicIdToken.fromJWT(signedJWT, '123', 123, {'clockTimestamp' : clockTimestamp, "complete": true});        
      }catch(err){
        assert.isNotNull(err);
        done();
      }
  });

  it('should fail with arrays', function (done) {
    try{
        var result = basicIdToken.fromJWT(['foo'], '123', {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"},{'clockTimestamp' : clockTimestamp, "complete": true});        
        
        //var result = basicIdToken.fromJWT(signedJWT, '123', 123, {'clockTimestamp' : clockTimestamp, "complete": true});        
      }catch(err){
        assert.isNotNull(err);
        done();
      }

  });

  it('should fail with functions', function (done) {

    try{
        var result = basicIdToken.fromJWT(function() {}, '123', {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"},{'clockTimestamp' : clockTimestamp, "complete": true});        
        
        //var result = basicIdToken.fromJWT(signedJWT, '123', 123, {'clockTimestamp' : clockTimestamp, "complete": true});        
      }catch(err){
        assert.isNotNull(err);
        done();
      }
  });

  it('should fail with booleans', function (done) {
    try{
        var result = basicIdToken.fromJWT(true, '123', {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"},{'clockTimestamp' : clockTimestamp, "complete": true});        
        
        //var result = basicIdToken.fromJWT(signedJWT, '123', 123, {'clockTimestamp' : clockTimestamp, "complete": true});        
      }catch(err){
        assert.isNotNull(err);
        done();
      }
    
  });

});