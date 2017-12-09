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

var fs = require('fs');
var path = require('path');
var jwt = require('../index');
//var JsonWebTokenError = require('../lib/JsonWebTokenError');
var expect = require('chai').expect;
var JsonWebTokenError = require('../node_modules/src/controllers/messageTypes/jwt/jsonwebtoken/lib/JsonWebTokenError');
var BasicIdToken = require('../node_modules/src/models/tokenProfiles/basicIdToken');

var assert = require('chai').assert;

var pub = fs.readFileSync(path.join(__dirname, 'pub.pem'), 'utf8');
// priv is never used
// var priv = fs.readFileSync(path.join(__dirname, 'priv.pem'));

var TOKEN = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE0MjY1NDY5MTl9.';

describe('when setting a wrong `header.alg`', function () {
  var clockTimestamp = 1000000000;
  
  var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
  basicIdToken.addNonStandardClaims({"aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
  basicIdToken.setNoneAlgorithm(true);
  var signedJWT = basicIdToken.toJWT(pub, {algorithm : 'HS256'});

  /*
  describe('signing with pub key as symmetric', function () {
    it('should not verify', function () {
      expect(function () {
        var decodedPayload = basicIdToken.fromJWT(signedJWT, pub, {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"},{'clockTimestamp' : clockTimestamp});        
        //jwt.verify(TOKEN, pub);
      }).to.throw(JsonWebTokenError, /invalid algorithm/);
    });
  });*/

  describe('signing with pub key as HS256 and whitelisting only RS256', function () {
    it('should not verify', function (done) {

      try{
        var decodedPayload = basicIdToken.fromJWT(signedJWT, pub, {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"},{algorithms: ['RS256'], 'clockTimestamp' : clockTimestamp});         
      }catch(err){
        assert.isNotNull(err);
        done();
      }
    });
  });

  describe('signing with HS256 and checking with HS384', function () {
    it('should not verify', function (done) {
      try{
        var decodedPayload = basicIdToken.fromJWT(signedJWT, pub, {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"},{algorithms: ['HS384'], 'clockTimestamp' : clockTimestamp});
               
      }catch(err){
        assert.isNotNull(err);
        done();
      }
    });
  });


});
