OpenID Connect (and other oauth2) Messages
==========================================

## Background

The OpenID Connect and OAuth2 standards both define multiple messages - requests that are sent from clients to servers and responses from servers to clients.  For each of these messages a number of parameters (claims) are listed, some of them required and some optional. Each parameter are also assigned a data type.
 
## Objective : 
This is a lower level layer module that implements serialization and deserialization of the
protocol messages in OAuth2 and OpenID Connect, including validation both ways.

### Message types
The serialization and deserialization formats supported are:
* JSON
* URLEncoded
* Json Web Token (JWT) signed and/or encrypted’

## JWT
A token profile is a security token that enables identity and security information to be shared across security domains. The token profiles folder contains the different types of JWT messages including the Basic ID Token. A token profile contains the required, optional, and verification claims specific to the token. 

### Supported JWT types 
BasicIdToken
Required claims : iss, sub, iat, jti, exp
Optional claims : nbf, auth_time, nonce, azr, amr, azp
ExtendedIdToken
Required claims : name, email, picture, iss, sub, iat
Optional claims : aud, exp, nbf
GoogleAccessToken
Required claims : iss, sub, iat
Optional claims : aud, exp
FacebookIdToken
Required claims : user_id, app_id, issued_at
Optional claims : expired_at
GoogleIdToken
Required claims : name, email, picture, iss, sub, iat
Optional claims : exp, aud
ImplicitAccessToken
Required claims : iss, sub, iat
Optional claims : aud
RefreshToken
Required claims : refresh_token, access_token
RiscToken
Required claims : jti, iss, sub, iat
Optional claims : aud, nbf, exp
ScopedAccessToken
Required claims : iss, sub, iat, scope
Optional claims : aud, exp

 
## JWT Serialization  
The toJWT method can be passed in required and optional claims claims, the key, and other options that might be necessary. This method checks for missing claims, validates the required claims, and signs and serializes a JWT type, ex- BasicIdToken. Throws error if missing a required claim or claims are not in expected format.

```
/**
 * @param {!Object<string, Object>} payload Required and optional claims
 * @param {!Object} key  Secret or private key used to sign the JWT (OP)
 * @param {?Object<string, Object>} options Other inputs or additional information that might be needed and are not part of the payload 
 * @returns Promise<string> A signed jwt
 */
 <type>.toJWT(payload, key, options);
```

Options such as follows can be passed in as the fourth parameter to token profile’s fromJWT method. Any duplicate options such as issuer cannot be passed in both in the payload and the options. The values provided in the options are not mandatory.
* algorithm (default: HS256)
* expiresIn: expressed in seconds or a string describing a time span zeit/ms. Eg: 60, '2 days', '10h', '7d'
* notBefore: expressed in seconds or a string describing a time span zeit/ms. Eg: 60, '2 days', '10h', '7d'
* audience
* issuer
* jwtid
* subject
* noTimestamp
* header
* Keyid
 
Each token has a NoneAlgorithm boolean value which is set to False by default unless set explicitly. If the none algorithm property is not set, the following error will be thrown when algorithm ‘none’ is used : 'Cannot use none algorithm unless explicitly set'. 
The none algorithm type can be set by passing in {algorithm: ‘none’} in the options parameter.

Usage Example:

```
const signedJwt = GoogleAccessToken.toJWT({iss: ‘https://my.auth.server’, sub: subject, iat: clockTimestamp, exp: clockTimestamp + 3600, aud:’myClientId’}, privateKey, {algorithm : ‘RS256’}); 
```

## JWT Deserialization
A JWT type can be deserialized by calling the token profile’s fromJWT method which extends the Message class.     
The fromJWT method for example can be passed in verification claims, the key, and other options that might be necessary. This method checks for required verification claims, decodes, and verifies the JWT, ex. BasicIdToken. 

```
/**
 * @param {string}   jwt  The JWT gotten from OpenID Provider (OP) 
 * @param {Object} key key used to deserialize the JWT
 * @param {Object<string, Object>} verificationClaims  Include the claims that you want to validate on top of the type's specified claims and the ones validated by the options below.
 * @param {Object<string, Object>} options Other inputs or additional information that might be needed and are not part of the payload 
 * @throws Error if missing a required claim
 * @throws Error if claims not in the expected format
 * @returns Promise<Object> The token claims
 */
 <type>.fromJWT(jwt, key, verificationClaims, options); 
```

Options parameter can include the following : 
* clockTolerance: Clock tolerance signifies the number of seconds to tolerate when checking the nbf and exp claims, to deal with small clock differences among different servers
* algorithms: List of strings with the names of the allowed algorithms. For instance, ["HS256", "HS384"].
* audience: if you want to check audience (aud), provide a value here. The audience can be checked against a string, a regular expression or a list of strings and/or regular expressions. Eg: "urn:foo", /urn:f[o]{2}/, [/urn:f[o]{2}/, "urn:bar"]
* issuer (optional): string or array of strings of valid values for the iss field.
* ignoreExpiration: if true do not validate the expiration of the token.
* ignoreNotBefore...
* maxAge: the maximum allowed age for tokens to still be valid. It is expressed in seconds or a string describing a time span zeit/ms. Eg: 1000, "2 days", "10h", "7d".
* clockTimestamp: the time in seconds that should be used as the current time for all necessary comparisons. This allows the user to provide any date and time and not just the current. In the backend, it fetches the clockTimestamp from the system if it is not provided.

Returns:
Promise of claims. E.g.
```
{
  iss: 'https://server.example.com',
  sub: '24400320',
  aud: 's6BhdRkqt3',
  nonce: 'n-0S6_WzA2Mj',
  exp: 1311281970,
  iat: 1311280970,
  auth_time: 1311280969,
  acr: 'urn:mace:incommon:iap:silver'
}
```

Example usage: 

```
/**
 * @param {Object<string, Object>} jwt Contains the jwt header and payload
 * @param {string}   idToken  The JWT gotten from OpenID Provider (OP)
 * @throws Error if issuer is not https://my.auth.server
 */ 
var keyJar = new KeyJar();
keyJar.getKey({header, payload}, client).then (function (key) {
     // Function gives full payload after validation, but in this case, we are
     // only interested in sub since we only trust one iss.
      BasicIdToken.fromJWT(
          idToken, key, {iss : 'https://my.auth.server', sub: 'subject', aud : 'myClientId', maxAge: '3s', clockTolerance : 10, jti: 'jti'}, {algorithm: 'RS256', clockTimestamp: clockTimestamp}).then(function(decodedPayload) {
               return decodedPayload;
             }).catch(function(err) {
               assert.isNull(err);
             });
}).catch(function (err) {console.log(err)});
```

Example usage 2 using the library: 

```
const jwksClient = require('jwks-rsa');

const client = jwksClient({
  strictSsl: true, // Default value
  jwksUri: 'https://sandrino.auth0.com/.well-known/jwks.json'
});

const kid = 'RkI5MjI5OUY5ODc1N0Q4QzM0OUYzNkVGMTJDOUEzQkFCOTU3NjE2Rg';
client.getSigningKey(kid, (err, key) => {
  const signingKey = key.publicKey || key.rsaPublicKey;
  BasicIdToken.fromJWT(
          idToken, signingKey, {iss : 'https://my.auth.server', sub: 'subject', aud : 'myClientId', maxAge: '3s', clockTolerance : 10, jti: 'jti'}, {algorithm: 'RS256', clockTimestamp: clockTimestamp}).then(function(decodedPayload) {
               return decodedPayload;
             }).catch(function(err) {
               assert.isNull(err);
             });
});
```

Known optional claims have to be verified by using the following parameters.For each of the following known non-required claims (audience, iat, exp, nbf) the respective verification claims are required.
Audience : aud
If you want to check audience, provide the verification claim, aud, in the fromJWT method. The audience can be checked against a string.
* Iat : maxAge
The maxAge is the maximum allowed age for tokens to still be valid. It is expressed in seconds or a string describing a time span zeit/ms. Eg: 1000, '2 days', '10h', '7d'
* exp/ nbf : clockTolerance
* Clock tolerance signifies the number of seconds to tolerate when checking the nbf and exp claims, to deal with small clock differences among different servers

Other Message Types
Similarly, the following methods can be used to serialize and deserialize other message types.
* toJSON
* fromJSON
* toUrlEncoded
* fromUrlEncoded
* JSON Serialization

## JSON Serialization

Serialize a JSON type by using the following function : 

```
/**
 * @param {Object<string, string>} payload Object that needs to be converted to JSON
 * @return Stringified JSON Obj

 */
 <type>.toJSON(payload);

Usage examples : 
const resp = Message.toJSON({'foo': 'bar'})
 
const resp = AuthorizationRequest.toJSON({responseType:[‘code’, ‘token’], clientId: ‘foobar’})
Const expectedResp = {‘responseType’: [‘code’, ‘token’], ‘clientId’: ‘foobar’}
assert.deepEqual(resp, expectedResp);
```

## JSON Deserialization

Deserialize a JSON type by using the following function : 

```
/**
 * @param {JSON} jsonObj JSON Object that needs to be deserialized
 * @return The deserialized JSON Obj

 */
 <type>.fromJSON(jsonObj);
 ```


FromJSON Ex: 
Deserializes a JSON Object 

```
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
const resp = JRD.fromJSON(JSON.stringify(ex));
assert.deepEqual(resp['dummy'], 'foo');
```
 
## URL Type
Included URLEncoded types:

OAuth2 Requests
* [TokenRequest](http://openid.net/specs/openid-connect-core-1_0.html#TokenRequest)
* AccessTokenRequest 
* AuthorizationRequest
* ROPCAccessTokenRequest
* CCAccessTokenRequest
* RefreshAccessTokenRequest
* ResourceRequest
 
OAuth2 Responses
* ErrorResponse 
* AuthorizationErrorResponse
* TokenErrorResponse
* AuthorizationResponse
* AccessTokenResponse
* ASConfigurationResponse
* NoneResponse

OIC Requests
* RefreshAccessTokenRequest 
* AuthorizationRequest
* AccessTokenRequest
* UserInfoRequest
* RegistrationRequest
* RefreshSessionRequest
* CheckSessionRequest
* CheckIDRequest
* EndSessionRequest
* ClaimsRequest
* OpenIdRequest
* DiscoveryRequest
 
OIC Responses
* TokenErrorResponse
* AuthorizationErrorResponse
* AuthorizationResponse
* ClientRegistrationError
* RegistrationResponse
* MessageWithIdToken

* RefreshSessionResponse

* EndSessionResponse

* ProviderConfigurationResponse

* UserInfoErrorResponse


## URL Serialization
 Serializes a claim to a url encoded string by using the following function : 
const oidcMsg = require('oidc-msg');

```
/**
 * @param {Object<string, string>} payload Object that needs to be url encoded
 * @return Serialized URL encoded type

 */
<type>.toURLEncoded(payload);
```

ToURLEncoded ex 
```
const resp = ErrorResponse.toUrlEncoded({'error': 'barsoap'})
```

## Url Deserialization
Deserialize a URL type by using the following function : 
const oidcMsg = require('oidc-msg');

```
/**
 * @param {string} urlEncoded URL Encoded string that needs to be deserialized
 * @return The deserialized JSON Obj
 */
 <type>.fromURLEncoded(urlEncoded);
 ```
From URLEncoded ex:
```
const reqArgs = {
     'redirect_uri': 'https://example.com/cli/authz_cb',
     'code': 'access_code'
   };
service.endpoint = 'https://example.com/authorize';
const params = {cliInfo: cliInfo, requestArgs: reqArgs, clientAuthnMethod: 'client_secret_basic', options: {state: 'state'}};
const info = service.requestInfo(params);
assert.deepEqual(Object.keys(info).length, 5);
assert.deepEqual(info['cis'], {
     'client_id': 'client_id',
     'code': 'access_code',
     'grant_type': 'authorization_code',
     'redirect_uri': 'https://example.com/cli/authz_cb'
});
const resp = AccessTokenRequest.fromUrlEncoded(service.getUrlInfo(info['body']));
assert.deepEqual(resp, info['cis']);
assert.isNotNull(Object.keys(info['hArgs']['headers'].Authorization))
 ```
## Errors & Codes
Possible thrown errors during verification. 
'TokenExpiredError' - Thrown error if the token is expired.
Json Web Token Errors
'jwt malformed'
'jwt signature is required'
'invalid signature'
'jwt audience invalid. expected: [OPTIONS AUDIENCE]'
'jwt issuer invalid. expected: [OPTIONS ISSUER]'
'jwt id invalid. expected: [OPTIONS JWT ID]'
'jwt subject invalid. expected: [OPTIONS SUBJECT]'
Algorithms supported
Array of supported algorithms. The following algorithms are currently supported.

alg Parameter Value | Digital Signature or MAC Algorithm
----------------|----------------------------
HS256 | HMAC using SHA-256 hash algorithm
HS384 | HMAC using SHA-384 hash algorithm
HS512 | HMAC using SHA-512 hash algorithm
RS256 | RSASSA using SHA-256 hash algorithm
RS384 | RSASSA using SHA-384 hash algorithm
RS512 | RSASSA using SHA-512 hash algorithm
ES256 | ECDSA using P-256 curve and SHA-256 hash algorithm
ES384 | ECDSA using P-384 curve and SHA-384 hash algorithm
ES512 | ECDSA using P-521 curve and SHA-512 hash algorithm
none | No digital signature or MAC value included

____________________________________________________________________________
