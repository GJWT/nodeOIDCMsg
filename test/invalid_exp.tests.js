// Copyright (c) 2017 The Authors of 'JWTS for NODE'
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

var jwt = require('../index');
var expect = require('chai').expect;
var assert = require('chai').assert;
var BasicIdToken = require('../node_modules/src/models/tokenProfiles/basicIdToken');

describe('invalid expiration', function() {
    var clockTimestamp = 1000000000;
    
  it('should fail with string', function (done) {
    var broken_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOiIxMjMiLCJmb28iOiJhZGFzIn0.cDa81le-pnwJMcJi3o3PBwB7cTJMiXCkizIhxbXAKRg';
    var clockTimestamp = 1000000000;
    try{
        var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
        basicIdToken.addNonStandardClaims({"aud" : "audience", "exp" : "string"});
        basicIdToken.setNoneAlgorithm(true);
        var signedJWT = basicIdToken.toJWT('shhhh');
        var decodedPayload = basicIdToken.fromJWT(signedJWT, 'shhhh', {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"}, {'clockTimestamp' : clockTimestamp});
    }catch(err){        
      assert.isNotNull(err);
      done();
    }
  });

  it('should fail with 0', function (done) {
    try{
        var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
        basicIdToken.addNonStandardClaims({"aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : 0});
        basicIdToken.setNoneAlgorithm(true);
        var signedJWT = basicIdToken.toJWT('shhhh');
        var decodedPayload = basicIdToken.fromJWT(signedJWT, 'shhhh', {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"}, {'clockTimestamp' : clockTimestamp});
    }catch(err){
      assert.isNotNull(err);
      done();      
    }

  });

  it('should fail with false', function (done) {
    try{
        var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
        basicIdToken.addNonStandardClaims({"aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : false});
        basicIdToken.setNoneAlgorithm(true);
        var signedJWT = basicIdToken.toJWT('shhhh');
        var decodedPayload = basicIdToken.fromJWT(signedJWT, 'shhhh', {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"}, {'clockTimestamp' : clockTimestamp});
    }catch(err){
      assert.isNotNull(err);
      done();      
    }

  });

  it('should fail with true', function (done) {
    try{
        var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
        basicIdToken.addNonStandardClaims({"aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : true});
        basicIdToken.setNoneAlgorithm(true);
        var signedJWT = basicIdToken.toJWT('shhhh');
        var decodedPayload = basicIdToken.fromJWT(signedJWT, 'shhhh', {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"}, {'clockTimestamp' : clockTimestamp});
    }catch(err){
      assert.isNotNull(err);
      done();      
    }        
  });

  it('should fail with object', function (done) {
    try{
        var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
        basicIdToken.addNonStandardClaims({"aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : {}});
        basicIdToken.setNoneAlgorithm(true);
        var signedJWT = basicIdToken.toJWT('shhhh');
        var decodedPayload = basicIdToken.fromJWT(signedJWT, 'shhhh', {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"}, {'clockTimestamp' : clockTimestamp});
    }catch(err){
      assert.isNotNull(err);
      done();      
    }    
    
  });

});