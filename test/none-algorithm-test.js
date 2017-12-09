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
var fs = require('fs');
var path = require('path');
var expect = require('chai').expect;
var assert = require('chai').assert;
var ms = require('ms');
var BasicIdToken = require('../node_modules/src/models/tokenProfiles/basicIdToken');

function loadKey(filename) {
  return fs.readFileSync(path.join(__dirname, filename));
}

describe('Asymmetric Algorithms', function(){
  
      describe('when signing a token with none algorithm', function () {
        var clockTimestamp = 1000000000;
        
        var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
        basicIdToken.setNoneAlgorithm(true);
        var signedJWT = basicIdToken.toJWT('shhhh', {algorithm : 'none'});
        
        
        it('should check if explicitly set', function (done) {
          try{
            var decodedPayload = basicIdToken.fromJWT(signedJWT, 'shhhh',  {"iss" : "issuer", "sub": "subject", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"}, {}, {algorithms: ['none']});
            assert.isNotNull(decodedPayload);            
          }catch(err){
            assert.isNotNull(err);
          }
          done();
        });
      });    
      
      describe('when signing a token with none algorithm', function () {
        it('should throw if none algorithm not set by choice', function (done) {
          try{
            var clockTimestamp = 1000000000;
            
            var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
            var signedJWT = basicIdToken.toJWT('shhhh', {algorithm : 'none'});
          }catch(err){
              assert.isNotNull(err);
          }
          done();
        });
      });  
    
    
  
});
