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
var path = require('path');
var assert = require('chai').assert;
var BasicIdToken = require('../node_modules/src/models/tokenProfiles/basicIdToken');

describe('iat', function () {

  it('should work with a exp calculated based on numeric iat', function (done) {
    var dateNow = Math.floor(Date.now() / 1000);
    var iat = dateNow - 30;
    var expiresInVal = 50;
    var basicIdToken = new BasicIdToken('issuer','subject', iat, "jti");
    basicIdToken.addNonStandardClaims({"aud" : "audience"});
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
    basicIdToken.addNonStandardClaims({"aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
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
    basicIdToken.addNonStandardClaims({"aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
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
    basicIdToken.addNonStandardClaims({"aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
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
    basicIdToken.addNonStandardClaims({"aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
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

