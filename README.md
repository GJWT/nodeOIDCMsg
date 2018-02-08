This is not an officially supported Google Product.

# JWTs for Node

This is a module that implements the protocol messages in OAuth2 and OpenID Connect.

## What is the message class?

Message is the top layer class that handles common functionality among the different serialization and deserialization types, such as claim verification.

When sending request, it must be possible to serialize the information to a format that can be transmitted over-the-wire. Likewise, when receiving responses it must be possible to de-serialize these into an internal representation. Because of this a number of methods have been added to the token profile to support serialization to and deserialization from a number of representations that are used in the OAuth2 and OIDC protocol exchange. 

Each serialization type extends the Message class, which handles the common functionality among the different types.


## Message types 

The serialization and deserialization formats supported are:
  * JSON
  * urlencoded
  * Json Web Token (JWT) signed and/or encrypted.
  
  
## How to serialize and deserialize other types using a token profile

To serialize and deserialize a JWT type :

When a token profile’s **toJWT** method is called, it calls the JWT classes sign method which extends the message class and serializes the JWT type.

When a token profile’s **fromJWT** method is called, it calls the JWT classes decode method which extends the message class and deserializes the JWT type.

The Message class' sign and verify methods handle the common task among all the three types, such as verifying claims.

Similarily, the following following token profile methods can be used to serialize and deserialize other types. 

* **toJSON**

* **fromJSON**

* **toUrlEncoded**

* **fromUrlEncoded**
  

## How to create a token profile and add required claims 

A token profile is a security token that enables identity and security information to be shared across security domains. The token profiles folder contains the different types of token profile classes including the Basic ID Token class. A token profile contains the token properties, required, optional and verification claims. Each token profile can be instantiated with its required claims. 

If any of the required claims are not specified such as the iss while creating a token profile, it will throw the following error for example : “You are missing a required parameter : iss”. 

```
var clockTimestamp = 1000000000;
var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");

```


## Supported token profile types

### BasicIdToken

* Required claims : *iss, sub, iat, jti*

* Optional claims : *aud, exp, nbf*

### ExtendedIdToken

* Required claims : *name, email, picture, iss, sub, iat*

* Optional claims : *aud, exp, nbf*

### AccessToken

* Required claims : *iss, sub, iat*

* Optional claims : *aud, exp*

### FacebookIdToken

* Required claims : *user_id, app_id, issued_at*

* Optional claims : *expired_at*

### GoogleIdToken

* Required claims : *name, email, picture, iss, sub, iat*

* Optional claims : *exp, aud*

### ImplicitAccessToken

* Required claims : *iss, sub, iat*

* Optional claims : *aud*

### RefreshToken

* Required claims : *refresh_token, access_token*

### RiscToken

* Required claims : *jti, iss, sub, iat*

* Optional claims : *aud, nbf, exp*

### ScopedAccessToken

* Required claims : *iss, sub, iat, scope* 

* Optional claims : *aud, exp* 



## How to add optional claims

Optional claims can be added separately by creating a new basic id token and then calling the method ‘addOptional
Claims’.

```
basicIdToken.addOptionalClaims({"aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
```


## How to access required & optional claims

To access the required claims that were previously added to a token, it can be done as follows : 

```
var requiredClaims = basicIdToken.getRequiredClaims();  
       
var optionalClaims = basicIdToken.getOptionalClaims(); 
```


## Support for jti & kid
Header includes claims such as kid and can be used to select the key wihtin a JWKS needed to verify the signature. Can also be passed in an optional claim for each token. Kid can be used to select the key within a JWKS needed to verify the signature.



## How to set none algorithm type 

Each token has a NoneAlgorithm boolean value which is set to False by default unless set explicitly. 

```
basicIdToken.setNoneAlgorithm(true);
```

If the none algorithm property above is not set, the following error will be thrown when algorithm ‘none’ is used : 'Cannot use none algorithm unless explicitly set'


## How to serialize a JWT type using a token profile

To sign a JWT with the Basic ID Token, call the token’s toJWT method with the secret and any additional options that need to be passed like “algorithm”. A secretOrPublicKey is a string or buffer containing either the secret for HMAC algorithms, or the PEM encoded public key for RSA and ECDSA

```
var signedJWT = basicIdToken.toJWT(secretOrPrivateKey);
```

## Other options for serialization
Options are other inputs or additional information that might be needed and are not part of the payload, for ex : 'algorithm'. Other options such as follows can be passed in as the fourth parameter to token profile’s fromJWT method. Any duplicate options such as issuer cannot be passed in both in the payload and the options. The values provided in the options are not mandatory.

  * algorithm (default: HS256)
  * expiresIn: expressed in seconds or a string describing a time span zeit/ms. Eg: 60, "2 days", "10h", "7d"
  * notBefore: expressed in seconds or a string describing a time span zeit/ms. Eg: 60, "2 days", "10h", "7d"
  * audience
  * issuer
  * jwtid
  * subject
  * noTimestamp
  * header
  * keyid
  
 ```
 var signedJWT = basicIdToken.toJWT(secretOrPrivateKey, {algorithm : 'HS256'});
```

If payload is not a buffer or a string, it will be coerced into a string using JSON.stringify.
There are no default values for expiresIn, notBefore, audience, subject, issuer. These claims can also be provided in the payload directly with exp, nbf, aud, sub and iss respectively, but you can't include in both places.
Remember that exp, nbf and iat are NumericDate, see related Token Expiration (exp claim)
The header can be customized via the options.header object.
Generated jwts will include an iat (issued at) claim by default unless noTimestamp is specified. If iat is inserted in the payload, it will be used instead of the real timestamp for calculating other things like exp given a timespan in options.expiresIn.



## How to deserialize & verify required or optional claims

A token profile’s fromJWT method can be used to decode a JWT. While the JWT is decoded, the backend also verifies the payload to check if it matches the expected claims.  Claims to be verified can be passed in as key value pairs as the third parameter of the fromJwt method. Expected required claim values are required while deserializing.

```
var decodedPayload = basicIdToken.fromJWT(signedJWT, secretOrPublicKey, {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"},{'clockTimestamp' : clockTimestamp});
```

Known optional claims have to be verified by using the following parameters.For each of the following known non-required claims (audience, iat, exp, nbf) the respective verification claims are required.

* **Audience : aud**

If you want to check audience, provide the verification claim, aud, in the fromJWT method. The audience can be checked against a string.

* **Iat : maxAge**

The maxAge is the maximum allowed age for tokens to still be valid. It is expressed in seconds or a string describing a time span zeit/ms. Eg: 1000, "2 days", "10h", "7d"

* **exp/ nbf : clockTolerance**

Clock tolerance signifies the number of seconds to tolerate when checking the nbf and exp claims, to deal with small clock differences among different servers


## Other options for deserialization 

Options are other inputs or additional information that might be needed and are not part of the payload, for ex : 'algorithm'. Other options such as follows can be passed as in as the fourth parameter to token profile’s fromJWT method.Any duplicate options such as issuer cannot be passed in both in the payload and the options. The values provided in the options are not mandatory and can be used to verify a claim value.


### Options
* algorithms: List of strings with the names of the allowed algorithms. For instance, ["HS256", "HS384"].
* audience: if you want to check audience (aud), provide a value here. The audience can be checked against a string, a regular expression or a list of strings and/or regular expressions. Eg: "urn:foo", /urn:f[o]{2}/, [/urn:f[o]{2}/, "urn:bar"]
* issuer (optional): string or array of strings of valid values for the iss field.
* ignoreExpiration: if true do not validate the expiration of the token.
* ignoreNotBefore...
* subject: if you want to check subject (sub), provide a value here
* clockTolerance: number of seconds to tolerate when checking the nbf and exp claims, to deal with small clock differences among different servers
* maxAge: the maximum allowed age for tokens to still be valid. It is expressed in seconds or a string describing a time span zeit/ms. Eg: 1000, "2 days", "10h", "7d".
* clockTimestamp: the time in seconds that should be used as the current time for all necessary comparisons. This allows the user to provide any date and time and not just the current. In the backend, it fetches the clockTimestamp from the system if it is not provided : 
```var clockTimestamp = otherOptions.clockTimestamp || Math.floor(Date.now() / 1000);```

For example, you can use the options algorithm and clockTimestamp as follows :
```
var decodedPayload = basicIdToken.fromJWT(signedJWT, secretOrPublicKey, {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"},{algorithm: 'HS256', 'clockTimestamp' : clockTimestamp});
```

## Callbacks
Callbacks can be provided as one of the parameters for a token profile's toJwt and fromJwt method. 

For example, here are the Basic Json Web token profiles method signatures:

```
BasicIdToken.prototype.toJWT = function(secretOrPrivateKey, options, callback)

```

```
BasicIdToken.prototype.fromJWT = function(signedJWT, secretOrPublicKey, claimsToVerify, options, callback)
```

(Asynchronous) If a callback is supplied, function acts asynchronously. The callback is called with the decoded payload if the signature is valid and optional expiration, audience, or issuer are valid. If not, it will be called with the error.

(Synchronous) If a callback is not supplied, function acts synchronously. Returns the payload decoded if the signature is valid and optional expiration, audience, or issuer are valid. If not, it will throw the error.



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


## Refreshing JWTs

First of all, we recommend to think carefully if auto-refreshing a JWT will not introduce any vulnerability in your system.

We are not comfortable including this as part of the library, however, you can take a look to [this example](https://gist.github.com/ziluvatar/a3feb505c4c0ec37059054537b38fc48) to show how this could be accomplished.
Apart from that example there are [an issue](https://github.com/auth0/node-jsonwebtoken/issues/122) and [a pull request](https://github.com/auth0/node-jsonwebtoken/pull/172) to get more knowledge about this topic.

## Project directory

Navigate to the main directory:

```
cd LOCAL-GIT-REPO-PATH/OIDCMsg-NodeJS/node_modules/src

```

## Running tests

``` 
cd LOCAL-GIT-REPO-PATH/OIDCMsg-NodeJS/
```

```
npm test
```

# TODO

* X.509 certificate chain is not checked



