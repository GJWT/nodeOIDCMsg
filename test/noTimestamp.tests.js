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
var fs = require('fs');
var jwt = require('../index');
var JsonWebTokenError = require('../node_modules/src/controllers/messageTypes/jwt/jsonwebtoken/lib/JsonWebTokenError');
var expect = require('chai').expect;
var assert = require('chai').assert;  

var BasicIdToken = require('../node_modules/src/models/tokenProfiles/basicIdToken');
var RefreshToken = require('../node_modules/src/models/tokenProfiles/refreshToken');


describe('noTimestamp', function() {
    
  it('should work with string', function () {

    var clockTimestamp = 1437018582;
    //var token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.0MBPd4Bru9-fK_HY3xmuDAc6N_embknmNuhdb9bKL_U';
    var options = {algorithms: ['HS256']};
    var key = "secret";
    var refreshToken = new RefreshToken('refreshToken','accessToken');
    var token = refreshToken.toJWT(key, {expiresIn: '5m', noTimestamp : true});
    try{
        var result = refreshToken.fromJWT(token, key, {"refresh_token" : "refreshToken", "access_token": "accessToken"}, options);        
    }catch(err){
        assert.equal(err.name, 'JsonWebTokenError');
        assert.equal(err.message, 'iat required when maxAge is specified');
        assert.isUndefined(result);
        done();
    }
  });
});