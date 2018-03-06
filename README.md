OpenID Connect (and other oauth2) Messages
==========================================

[![Build Status](https://secure.travis-ci.org/GJWT/nodeOIDCMsg?branch=master)](http://travis-ci.org/GJWT/nodeOIDCMsg)

This is a module that implements serialization and deserialization of the
protocol messages in OAuth2 and OpenID Connect, including validation both ways.


Example usage
-------------

```javascript
const oidcmsg = require('oidc-msg');

/**
 * @param {function} getKey ({header, payload}) => Promise<publicKey>
 * @param {string}   idToken  The JWT gotten from OpenID Provider (OP)
 *
 * @throws Error if idToken is not valid.
 * @throws Error if issuer is not https://my.auth.server
 */
const concludeLogin = (getKey) => (session, idToken) {
  // Function gives full payload after validation, but in this case, we are
  // only interested in sub since we only trust one iss.
  const {sub} = await oidcmsg.BasicIdToken.fromJWT(
      idToken, getKey,
      {aud: 'myClientId', iss: 'https://my.auth.server'},
      {algorithm: 'RS256'}
  );

  session.setLoggedIn(sub);
}
```


## Message types

The serialization and deserialization formats supported are:

* JSON
* URLEncoded
* Json Web Token (JWT) signed and/or encrypted.


## How to serialize and deserialize using a message type

This depends on the serialization format.  All deserialization will validate
that all required claims are present, and that all specified claims conform to
the correct format.

### JWT

Included JWT types:

* [BasicIdToken](http://openid.net/specs/openid-connect-core-1_0.html#IDToken) - OpenID Connect ID Token
  * Required: iss, sub, iat, jti, exp
  * Optional: nbf, auth_time, nonce, azr, amr, azp
* ExtendedIdToken (?)
  * Required: name, email, picture, iss, sub, iat
  * Optional: aud, exp, nbf
* AccessToken
  * Required:
* GoogleIdToken
  * Required: name, email, picture, iss, sub, iat
  * Optional: aud, exp
* FacebookIdToken
  * Required: user_id, app_id, issued_at
  * Optional: expired_at
* AccessToken
  * Required: iss, sub, iat
  * Optional: aud, exp
* ScopedAccessToken
  * Required: iss, sub, iat, scope
  * Optional: aud, exp
* ImplicitAccessToken
  * Required: iss, sub, iat
  * Optional: aud
* RefreshToken:
  * Required: refresh_token, access_token
* SecurityEvent (risc):
  * Required: jti, iss, sub, iat
  * Optional: aud, nbf, exp


#### `oidcmsg.<type>.fromJWT(jwt, getKey, validation, options)`

Validates and deserialized a JWT, e.g. `BasicIdToken`.

* `jwt` - The token string.

* `getKey` - A function `({header,payload}) => Promise<key>` where `key` is a string
  or buffer containing either the secret for HMAC algorithms, or the PEM
  encoded public key for RSA and ECDSA.

* `validation` - Include the claims that you want to validate on top of the
  type's specified claims and the ones validated by the options below..

* `options`
  * `clockTolerance` - Clock tolerance signifies the number of seconds to
    tolerate when checking the nbf and exp claims, to deal with small clock
    differences among different servers
  * `algorithms`: List of strings with the names of the allowed algorithms. For instance, ["HS256", "HS384"].
  * `audience`: if you want to check audience (aud), provide a value here. The audience can be checked against a string, a regular expression or a list of strings and/or regular expressions. Eg: "urn:foo", /urn:f[o]{2}/, [/urn:f[o]{2}/, "urn:bar"]
  * `issuer`: string or array of strings of valid values for the iss field.
  * `ignoreExpiration`: if true do not validate the expiration of the token.
  * `ignoreNotBefore`...
  * `maxAge`: the maximum allowed age for tokens to still be valid. It is
    expressed in seconds or a string describing a time span zeit/ms. Eg: 1000,
    "2 days", "10h", "7d".
  * `clockTimestamp`: the time in seconds that should be used as the current time
    for all necessary comparisons. This allows the user to provide any date and
    time and not just the current. In the backend, it fetches the
    clockTimestamp from the system if it is not provided.

Returns:

Promise of payload.  E.g.

```javascript
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

#### `oidcmsg.<type>.toJWT(payload, key, options)`

* `payload` - an object literal of all claims.

* `key` is a string, buffer, or object containing either the secret for HMAC
  algorithms or the PEM encoded private key for RSA and ECDSA. In case of a
  private key with passphrase an object `{ key, passphrase }` can be used
  (based on
  [crypto documentation](https://nodejs.org/api/crypto.html#crypto_sign_sign_private_key_output_format)),
  in this case be sure you pass the `algorithm` option.

* `options`: Options are other inputs or additional information that might be
  needed and are not part of the payload, for ex : 'algorithm'. Other options
  such as follows can be passed in as the fourth parameter to token profile’s
  fromJWT method. Any duplicate options such as issuer cannot be passed in both
  in the payload and the options. The values provided in the options are not
  mandatory.
  * `algorithm` (default: `HS256`)
  * `expiresIn`: expressed in seconds or a string describing a time span
    [zeit/ms](https://github.com/zeit/ms). Eg: `60`, `"2 days"`, `"10h"`,
    `"7d"`
  * `notBefore`: expressed in seconds or a string describing a time span
    [zeit/ms](https://github.com/zeit/ms). Eg: `60`, `"2 days"`, `"10h"`,
    `"7d"`
  * `audience`
  * `issuer`
  * `jwtid`
  * `subject`
  * `noTimestamp`
  * `header`
  * `keyid`


### JSON

Included JSON types:

* JRD (?)

#### `oidcmsg.<type>.fromJSON(json, validation, options)`

#### `oidcmsg.<type>.toJSON(payload, options)`



### URLEncoded

Included URLEncoded types:

* [TokenRequest](http://openid.net/specs/openid-connect-core-1_0.html#TokenRequest)
* AccessTokenResponse


#### `oidcmsg.<type>.fromURLEncoded(urlencoded, validation, options)`

#### `oidcmsg.<type>.toURLEncoded(payload, options)`


## Errors & Codes

Possible thrown errors during verification.
Error is the first argument of the verification callback.

### TokenExpiredError

Thrown error if the token is expired.

Error object:

* name: 'TokenExpiredError'
* message: 'jwt expired'
* expiredAt: [ExpDate]


### JsonWebTokenError
Error object:

* name: 'JsonWebTokenError'
* message:
  * 'jwt malformed'
  * 'jwt signature is required'
  * 'invalid signature'
  * 'jwt audience invalid. expected: [OPTIONS AUDIENCE]'
  * 'jwt issuer invalid. expected: [OPTIONS ISSUER]'
  * 'jwt id invalid. expected: [OPTIONS JWT ID]'
  * 'jwt subject invalid. expected: [OPTIONS SUBJECT]'


## Algorithms supported

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
