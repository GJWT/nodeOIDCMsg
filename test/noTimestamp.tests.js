
var assert = require('chai').assert;
var RefreshToken = require('../src/oicMsg/tokenProfiles/refreshToken');

describe('noTimestamp', function() {
  
  it('should work with string', function(done) {
    var options = {algorithms: ['HS256']};
    var key = 'secret';
    var refreshToken = new RefreshToken(
        {refreshToken: 'refreshToken', accessToken: 'accessToken'});
    refreshToken.toJWT(key, {expiresIn: '5m', noTimestamp: true})
        .then(function(token) {
          refreshToken
              .fromJWT(
                  token, key, {
                    'refreshToken': 'refreshToken',
                    'accessToken': 'accessToken'
                  },
                  options)
              .then(function(result) {
                assert.isUndefined(result);
              })
              .catch(function(err) {
                assert.equal(err.name, 'JsonWebTokenError');
                assert.equal(
                    err.message, 'iat required when maxAge is specified');
              });
        });
    done();
  });
});