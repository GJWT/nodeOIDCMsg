var BasicIdToken = require('../src/models/tokenProfiles/basicIdToken');
var assert = require('chai').assert;  
var XMLHttpRequest = require("xmlhttprequest").XMLHttpRequest;
var jwtDecoder = require('../src/controllers/messageTypes/jwt/jsonwebtoken/decode');  
var readSync = require('read-file-relative').readSync;

describe('When signing an x509 certificate', function () {
  var priv = readSync('./keys/rolandPriv.pem');
  var pub = readSync("./keys/rolandPub.pem");
  
  var clockTimestamp = 1511783267;  
  var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jwtid");
  basicIdToken.addNonStandardClaims({"foo": 'bar', "aud" : "audience"});
  basicIdToken.setNoneAlgorithm(true);
  var token = basicIdToken.toJWT(priv, {algorithm: 'RS256'});
    
  it('should work with the corresponding pub key 1', function () {
    var verified = jwtDecoder.verifyJwtSign(token, pub, basicIdToken,  {"clockTimestamp" : clockTimestamp, jwtid: 'jwtid', algorithm: 'HS256'}, "base64");
    assert.equal(verified, true);
  });
});

describe('When signing an x509 certificate', function () {
  var priv = readSync("./keys/example_key.pem");
  var pub = readSync("./keys/example_pub_key.pem");

  var clockTimestamp = 1511783267;  
  var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jwtid");
  basicIdToken.addNonStandardClaims({"foo": 'bar', "aud" : "audience"});
  basicIdToken.setNoneAlgorithm(true);
  var token = basicIdToken.toJWT(priv, {algorithm: 'RS256'});
  
  it('should work with the corresponding pub key 2', function () {
    var verified = jwtDecoder.verifyJwtSign(token, pub, basicIdToken,  {"clockTimestamp" : clockTimestamp, jwtid: 'jwtid', algorithm: 'HS256'}, "base64");
    assert.equal(verified, true);
  });
    
  it('should not work with wrong pub key 1', function () {
    var pub = readSync("./keys/rolandPub.pem");      
    var verified = jwtDecoder.verifyJwtSign(token, pub, basicIdToken,  {"clockTimestamp" : clockTimestamp, jwtid: 'jwtid', algorithm: 'HS256'}, "base64");
    assert.equal(verified, false);
  });
});

describe('When signing an x509 certificate', function () {
  var priv = readSync("./keys/example_key.pem");
  var pub = readSync("./keys/example_pub_key.pem");
  
  var clockTimestamp = 1511783267;  
  var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jwtid");
  basicIdToken.addNonStandardClaims({"foo": 'bar', "aud" : "audience"});
  basicIdToken.setNoneAlgorithm(true);
  var token = basicIdToken.toJWT(priv, {algorithm: 'RS256'});
  var jwk = {"keys": [{"kty": "RSA", "use": "sig", "kid": "b3FoRUN1bVA0bzZhWV8xbnQwdDdad3F6Q2JINm82R1BtWklkeHdzQng3WQ", "e": "AQAB", "n": "pKs6I50cidbG6rm5zovMZLezyh5mqWmZq3XG8HbU9mExb9Nj3p6sJCf-TjR76CxxP8kHyazPQzQJiHEBbhDjmD_mlK4Zvy3nJ4i4ozYAVpA0qNLfx7WUJXZTJ8ppKqRAsxRidX-sSLqf_EeLeCggwvDwl0tFntBoWB4OjZsI5YwBdd9EUfaSchLz8Xo1kiI2nfB7piVgJBQVuzHuITALlcAAPJ0W3tkhbsDxtR-HC5ylGgIVClRMl6CRbTu_mtLhN2fHk1tMr5pVhjZPVeHDVXYEZD5mUyUKRfGIA5UrUlpt0KwVZk9aiqwAzT04XwuEC0zs7wVNOvHK82-Iyy6izw", "x5c": ["MIIDLjCCAhagAwIBAgIUKriYUd+HQFoyzOwz9yARCyG3G4AwDQYJKoZIhvcNAQELBQAwRDELMAkGA1UEBhMCU0UxDTALBgNVBAcMBFVtZWExEjAQBgNVBAoMCUNhdGFsb2dpeDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTE3MTIyMDIyNDAyMVoXDTE3MTIzMDIyNDAyMVowRDELMAkGA1UEBhMCU0UxDTALBgNVBAcMBFVtZWExEjAQBgNVBAoMCUNhdGFsb2dpeDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApKs6I50cidbG6rm5zovMZLezyh5mqWmZq3XG8HbU9mExb9Nj3p6sJCf+TjR76CxxP8kHyazPQzQJiHEBbhDjmD/mlK4Zvy3nJ4i4ozYAVpA0qNLfx7WUJXZTJ8ppKqRAsxRidX+sSLqf/EeLeCggwvDwl0tFntBoWB4OjZsI5YwBdd9EUfaSchLz8Xo1kiI2nfB7piVgJBQVuzHuITALlcAAPJ0W3tkhbsDxtR+HC5ylGgIVClRMl6CRbTu/mtLhN2fHk1tMr5pVhjZPVeHDVXYEZD5mUyUKRfGIA5UrUlpt0KwVZk9aiqwAzT04XwuEC0zs7wVNOvHK82+Iyy6izwIDAQABoxgwFjAUBgNVHREEDTALgglsb2NhbGhvc3QwDQYJKoZIhvcNAQELBQADggEBAGM5Lcsn9IwuudYxSDDV2FHVMAgkxVZWSLrQmlIMexY1Cis8CdKw7Oh8Y7L3D5/OncIqdvdl32xPLh9qFGahLflTr7ovBBsjuYsestqg4w9DGOk6xMJIz8H8aXHHzAfmeYHwnYNLJnaYGgT3lfZRuFZTiWN5ZE8wfPliYsyyCqjvLBMEcTlk+oXiw/WZ12HaP9KMym207R7SDGcT/5TJeZe51+n/jW42wolLWppGpT7cCuCzui/IgvvQ9P9Hc41jrDlIzg9J5cXSYDjzhNHI7UdkMgX38kJIEMxFG26FUY03/wVFF8RZ/w+OaBGOHZ7e+qhuOb+U/b5SIxoFSlnxGsY="]}]};
    
  it('should work with a JWK input', function () {
    var verified = jwtDecoder.verifyJwtSignature(token, pub, basicIdToken,  {"clockTimestamp" : clockTimestamp, jwtid: 'jwtid', algorithm: 'HS256'}, JSON.stringify(jwk), "base64");
    assert.equal(verified, true);
  });
});