'use strict';

var KeyError = require('./lib/KeyError');
var KeyIOError = require('./lib/KeyIOError');
var MessageException = require('./lib/MessageException');

var keyJar = KeyJar.prototype;

function KeyJar(issuerKeys, verifySSL, removeAfter) {};

keyjar.issuerKeys = {};
keyjar.verifySSL = false;
keyjar.removeAfter = 0;

keyjar.repr = function() {
  throw new Error('Unsupported Operation Exception');
};

/**
 * Add a set of keys by url. This method will create a
 * :py:class:`oicmsg.oauth2.keybundle.KeyBundle` instance with the
 * url as source specification.
 * :param issuer: Who issued the keys
 * :param url: Where can the key/-s be found
 * : param kwargs: extra parameters for instantiating KeyBundle
 * :return: A :py:class:`oicmsg.oauth2.keybundle.KeyBundle` instance
 */
keyjar.add = function(issuer, url, kwargs) {
  try {
    throw new Error('Unsupported Operation Exception');
  } catch (e) {
    if (e instanceof KeyError) {
      // Statements to handle error
    } else {
      // statements to handle error
    }
  };
};

keyJar.addSymmetric = function(issuer, key, args) {
  throw new Error('Unsupported Operation Exception');
};

keyJar.addKb = function(issuer, kb) {
  try {
    throw new Error('Unsupported Operation Exception');
  } catch (e) {
    if (e instanceof KeyError) {
      // Statements to handle error
    } else {
      // statements to handle error
    }
  };
};

keyJar.setItem = function(issuer, val) {
  throw new Error('Unsupported Operation Exception');
};

keyJar.items =
    function() {
  throw new Error('Unsupported Operation Exception');
}

/**
 * :param keyUser: A key useful for this usage (enc, dec, sig, ver)
 * :param keyType: Type of key (rsa, ec, symmetric, ..)
 * :param issuer: Who is responsible for the keys, "" == me
 * :param kid: A Key Identifier
 * :return: A possibly empty list of keys 
 * */

keyJar.get = function(keyUser, keyType, issuer, kid, args) {
  
  try {
    throw new Error('Unsupported Operation Exception');
  } catch (e) {
    if (e instanceof KeyError) {
      // Statements to handle error
    } else if (e instanceof AssertionError) {
      // Statements to handle error
    } else {
      // statements to handle error
    }
  };
};

keyJar.getSigningKey = function(keyType, owner, kid, args) {
  throw new Error('Unsupported Operation Exception');
};

keyJar.getVerifyKey = function(keyType, owner, kid, args) {
  throw new Error('Unsupported Operation Exception');
};

keyJar.getEncryptKey = function(keyType, owner, kid, args) {
  throw new Error('Unsupported Operation Exception');
};

keyJar.getDecryptKey = function(keyType, owner, kid, args) {
  throw new Error('Unsupported Operation Exception');
};

keyJar.getKeyByKid = function(kid, owner) {
  throw new Error('Unsupported Operation Exception');
};

keyJar.xKeys = function(variable, part) {
  throw new Error('Unsupported Operation Exception');
};

/**
 * Keys for me and someone else.
 * :param part: The other part
 * :return: dictionary of keys
 */
keyJar.verifyKeys = function(part) {
  throw new Error('Unsupported Operation Exception');
}

/**
 * Keys for me and someone else.
 * :param part: The other part
 * :return: dictionary of keys
 */
keyJar.decryptKeys = function(part) {
  throw new Error('Unsupported Operation Exception');
};

keyJar.getItem = function(issuer) {
  try {
    throw new Error('Unsupported Operation Exception');
  } catch (e) {
    if (e instanceof KeyError) {
      // Statements to handle error
    } else {
      // statements to handle error
    }
  };
};

keyJar.removeKey = function(issuer, keyType, key) {
  try {
    throw new Error('Unsupported Operation Exception');
  } catch (e) {
    if (e instanceof KeyError) {
      // Statements to handle error
    } else {
      // statements to handle error
    }
  };
};

keyJar.update = function(kj) {
  try {
    throw new Error('Unsupported Operation Exception');
  } catch (e) {
    if (e instanceof KeyError) {
      // Statements to handle error
    } else {
      // statements to handle error
    }
  };
};

keyJar.matchOwner = function(url) {
  try {
    throw new Error('Unsupported Operation Exception');
  } catch (e) {
    if (e instanceof KeyIOError) {
      // Statements to handle error
    } else {
      // statements to handle error
    }
  };
};

keyJar.toString = function() {
  throw new Error('Unsupported Operation Exception');
};

keyJar.getKeys = function() {
  throw new Error('Unsupported Operation Exception');
};

/**
 * Fetch keys from another server
 * :param pcr: The provider information
 * :param issuer: The provider URL
 * :param replace: If all previously gathered keys from this provider should be replace.
 * :return: Dictionary with usage as key and keys as values
 */
keyJar.loadKeys = function(pcr, issuer, replace) {
  try {
    throw new Error('Unsupported Operation Exception');
  } catch (e) {
    if (e instanceof KeyError) {
      // Statements to handle error
    } else if (e instanceof MessageException) {
      // Statements to handle error
    } else {
      // statements to handle error
    }
  };
};

/**
 * Find a key bundle
 * :param source: A url
 * :param issuer: The issuer of keys
 */
keyJar.find = function(source, issuer) {
  try {
    throw new Error('Unsupported Operation Exception');
  } catch (e) {
    if (e instanceof KeyError) {
      // Statements to handle error
    } else {
      // statements to handle error
    }
  };
};

keyJar.dumpIssuerKeys = function(issuer) {
  try {
    throw new Error('Unsupported Operation Exception');
  } catch (e) {
    if (e instanceof KeyError) {
      // Statements to handle error
    } else {
      // statements to handle error
    }
  };
};

keyJar.exportJwks = function(isPrivate, issuer) {
  throw new Error('Unsupported Operation Exception');
};

/**
 * :param jwks: Dictionary representation of a JWKS
 * :param issuer: Who 'owns' the JWKS
 */
keyJar.importJwks = function(jwks, issuer) {
  try {
    throw new Error('Unsupported Operation Exception');
  } catch (e) {
    if (e instanceof KeyError) {
      // Statements to handle error
    } else if (e instanceof InvalidValue) {
      // Statements to handle error
    } else {
      // statements to handle error
    }
  };
};

keyJar.addKeyJar = function(keyJar) {
  try {
    throw new Error('Unsupported Operation Exception');
  } catch (e) {
    if (e instanceof KeyError) {
      // Statements to handle error
    } else {
      // statements to handle error
    }
  };
};

keyJar.dump = function() {
  throw new Error('Unsupported Operation Exception');
};

keyJar.restore = function(info) {
  throw new Error('Unsupported Operation Exception');
};

keyJar.copy = function() {
  throw new Error('Unsupported Operation Exception');
};

keyJar.keysByAlgAndUsage = function(issuer, alg, usage) {
  throw new Error('Unsupported Operation Exception');
};

keyJar.getIssuerKeys = function(issuer) {
  throw new Error('Unsupported Operation Exception');
};

keyJar.equals = function(other) {
  throw new Error('Unsupported Operation Exception');
};

/**
 * Goes through the complete list of issuers and for each of them removes outdated keys.
 * Outdated keys are keys that has been marked as inactive at a time that is longer ago 
 * then some set number of seconds. The number of seconds a carried in the remove_after 
 * parameter.
 * :param when: To facilitate testing
 */
keyJar.removeOutdated = function(when) {
  throw new Error('Unsupported Operation Exception');
};

keyJar.addKey = function(issuer, key, keyType, kid, noKidIssuer) {
  throw new Error('Unsupported Operation Exception');
};

/**
 * Get keys from a keyjar. These keys should be usable to verify a signed JWT.
 * :param keyjar: A KeyJar instance
 * :param key: List of keys to start with
 * :param jso: The payload of the JWT, expected to be a dictionary.
 * :param header: The header of the JWT
 * :param jwt: A jwkest.jwt.JWT instance
 * :param kwargs: Other key word arguments
 * :return: list of usable keys
 */
keyJar.getJwtVerifyKeys = function(key, jso, header, jwt, kwargs) {
  throw new Error('Unsupported Operation Exception');
};

module.exports = keyJar;
