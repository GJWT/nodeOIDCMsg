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

var algorithms = {
  RS256: {
    pub_key: loadKey('pub.pem'),
    priv_key: loadKey('priv.pem'),
    invalid_pub_key: loadKey('invalid_pub.pem')
  },
  ES256: {
    // openssl ecparam -name secp256r1 -genkey -param_enc explicit -out ecdsa-private.pem
    priv_key: loadKey('ecdsa-private.pem'),
    // openssl ec -in ecdsa-private.pem -pubout -out ecdsa-public.pem
    pub_key: loadKey('ecdsa-public.pem'),
    invalid_pub_key: loadKey('ecdsa-public-invalid.pem')
  }
};

describe('Asymmetric Algorithms', function(){

  Object.keys(algorithms).forEach(function (algorithm) {
    describe(algorithm, function () {
      var clockTimestamp = 1000000000;
      
      var pub = algorithms[algorithm].pub_key;
      var priv = algorithms[algorithm].priv_key;

      describe('when signing a token with wrong type values', function () {
    

        it('should throw error for incorrect type format of audience', function (done) {
            try{
              var basicIdToken2 = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
              basicIdToken2.addNonStandardClaims({"aud" : 1, "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
              basicIdToken2.setNoneAlgorithm(true);
              var signedJWT = basicIdToken2.toJWT('shhhh');
            }catch(err){
              assert.isNotNull(err);
              done();
            }
          });

          it('should throw error for incorrect type format of subject', function (done) {
            try{
              var basicIdToken2 = new BasicIdToken('issuer',1, clockTimestamp, "jti");
              basicIdToken2.addNonStandardClaims({"aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
              basicIdToken2.setNoneAlgorithm(true);
              var signedJWT = basicIdToken2.toJWT('shhhh');
            }catch(err){
              assert.isNotNull(err);
              done();
            }
          });

          it('should throw error for incorrect type format of jti', function (done) {
            try{
              var basicIdToken2 = new BasicIdToken('issuer','subject', clockTimestamp, 1);
              basicIdToken2.addNonStandardClaims({"aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
              basicIdToken2.setNoneAlgorithm(true);
              var signedJWT = basicIdToken2.toJWT('shhhh');
            }catch(err){
              assert.isNotNull(err);
              done();
            }
          });
      });
    });
    });
}); 

