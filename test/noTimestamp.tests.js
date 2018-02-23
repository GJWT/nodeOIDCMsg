
var jwt = require('../index');
var expect = require('chai').expect;
var fs = require('fs');
var jwt = require('../index');
var JsonWebTokenError = require('../src/oicMsg/lib/JsonWebTokenError');
var expect = require('chai').expect;
var assert = require('chai').assert;

var BasicIdToken = require('../src/oicMsg/tokenProfiles/basicIdToken');
var RefreshToken = require('../src/oicMsg/tokenProfiles/refreshToken');


describe('noTimestamp', function() {

  it('should work with string', function() {

    var clockTimestamp = 1437018582;
    // var token =
    // 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.0MBPd4Bru9-fK_HY3xmuDAc6N_embknmNuhdb9bKL_U';
    var options = {algorithms: ['HS256']};
    var key = 'secret';
    var refreshToken = new RefreshToken('refreshToken', 'accessToken');
    var token = refreshToken.toJWT(key, {expiresIn: '5m', noTimestamp: true});
    try {
      var result = refreshToken.fromJWT(
          token, key,
          {'refreshToken': 'refreshToken', 'accessToken': 'accessToken'},
          options);
    } catch (err) {
      assert.equal(err.name, 'JsonWebTokenError');
      assert.equal(err.message, 'iat required when maxAge is specified');
      assert.isUndefined(result);
      done();
    }
  });
});