var assert = require('chai').assert;
var BasicIdToken = require('../src/oicMsg/tokenProfiles/basicIdToken');
const getClient = require('../src/oicMsg/keystore/keyJar').getClient;
const getKey = require('../src/oicMsg/keystore/keyJar').getKey;
const AuthorizationRequest =
    require('../src/oicMsg/oauth2/requests').AuthorizationRequest;
const jws = require('../src/oicMsg/jose/jws');

describe('test static methods', function() {

  var clockTimestamp = 1000000000;

  it('getKey should work', function() {
    let client =
        getClient('https://sandrino.auth0.com/.well-known/jwks.json', true);
    BasicIdToken
        .toJWT(
            {
              iss: 'https://my.auth.server',
              sub: 'subject',
              iat: clockTimestamp,
              jti: 'jti',
              exp: clockTimestamp + 3600,
              aud: 'myClientId'
            },
            'secret', {algorithm: 'HS256'})
        .then(function(signedJWT) {
          var decoded = jws.decode(signedJWT, {complete: true});
          getKey(decoded, client)
              .then(function(key) {
                assert.isNotNull(key);
              })
              .catch(function(err) {
                assert.isNull(err);
              });
        });
  });

  it('toJWT method should work', function() {
    BasicIdToken
        .toJWT(
            {
              iss: 'https://my.auth.server',
              sub: 'subject',
              iat: clockTimestamp,
              jti: 'jti',
              exp: clockTimestamp + 3600,
              aud: 'myClientId'
            },
            'secret', {algorithm: 'HS256'})
        .then(function(signedJWT) {
          assert.isNotNull(signedJWT);
          assert.deepEqual(
              signedJWT,
              'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL215LmF1dGguc2VydmVyIiwic3ViIjoic3ViamVjdCIsImlhdCI6MTAwMDAwMDAwMCwianRpIjoianRpIiwiYXVkIjoibXlDbGllbnRJZCIsImV4cCI6MTAwMDAwMzYwMH0.mq83UORyHAgsWaCllg0XoNwH8HBCavhR4amEA26u6V8');
        })
        .catch(function(err) {
          assert.isNull(err);
        });
  });

  it('fromJWT should work', function() {
    BasicIdToken
        .toJWT(
            {
              iss: 'https://my.auth.server',
              sub: 'subject',
              iat: clockTimestamp,
              jti: 'jti',
              exp: clockTimestamp + 3600,
              aud: 'myClientId'
            },
            'secret', {algorithm: 'HS256'})
        .then(function(signedJWT) {
          BasicIdToken
              .fromJWT(
                  signedJWT, 'secret', {
                    iss: 'https://my.auth.server',
                    sub: 'subject',
                    aud: 'myClientId',
                    maxAge: '3s',
                    clockTolerance: 10,
                    jti: 'jti'
                  },
                  {algorithm: 'HS256', clockTimestamp: clockTimestamp})
              .then(function(decodedPayload) {
                assert.isNotNull(decodedPayload);
                assert.deepEqual(Object.keys(decodedPayload).length, 6);
              })
              .catch(function(err) {
                assert.isNull(err);
              });
        });
  });

  it('toJSON should work', function() {
    const resp = AuthorizationRequest.toJSON(
        {responseType: ['code', 'token'], clientId: 'foobar'});
    assert.deepEqual(
        resp,
        JSON.stringify({responseType: ['code', 'token'], clientId: 'foobar'}));
    assert.isNotNull(resp);
  });

  it('fromJSON should work', function() {
    const ex = {
      'subject': 'acct:bob@example.com',
      'aliases': ['http://www.example.com/~bob/'],
      'properties': {'http://example.com/ns/role/': 'employee'},
      'dummy': 'foo',
      'links': [{
        'rel': 'http://webfinger.net/rel/avatar',
        'type': 'image/jpeg',
        'href': 'http://www.example.com/~bob/bob.jpg'
      }]
    };
    const resp = AuthorizationRequest.fromJSON(JSON.stringify(ex));
    assert.deepEqual(resp['dummy'], 'foo');
  });
  it('toURLEncoded should work', function() {
    const resp = AuthorizationRequest.toUrlEncoded({'error': 'barsoap'});
    assert.isNotNull(resp);
    assert.deepEqual(resp, 'error=barsoap');
  });
  it('fromURLEncoded should work', function() {
    const urlEncodedStr = 'error=barsoap';
    const resp = AuthorizationRequest.fromUrlEncoded(urlEncodedStr);
    assert.deepEqual(resp, {'error': 'barsoap'});
  });
});