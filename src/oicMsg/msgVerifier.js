const timespan = require('./lib/timespan');
const xtend = require('xtend');
const JSError = require('./lib/JSError');

/**
 * @fileoverview Handles the common verification functionality for all message
 * protocols
 */

/**
 * MessageVerifier
 * @class
 * @constructor
 */
class MessageVerifier {
  constructor() {}

  /**
   * Check message signature and other option values
   *
   * @param jwtString The signed Jwt string
   * @param secretOrPublicKey A string or buffer containing either the secret
   for HMAC algorithms, or the PEM encoded public key for RSA and ECDSA
   * @param options Other inputs that are not part of the payload, for ex :
   'algorithm'
   * @throws JsonWebToken error if options does not match expected claims
   * @memberof MessageVerifier.prototype
   */
  verifyOptions(jwtString, secretOrPublicKey, options) {
    if ((typeof options === 'function' || !options)) {
      options = {};
    }
    // clone this object since we are going to mutate it.
    options = xtend(options);
    return new Promise((resolve, reject) => {
      if (options.clockTimestamp &&
          typeof options.clockTimestamp !== 'number') {
        reject(
            new JSError('clockTimestamp must be a number'),
            'JSONWebTokenError');
      }

      if (!jwtString) {
        reject(new JSError('jwt must be provided', 'JSONWebTokenError'));
      }

      if (typeof jwtString !== 'string') {
        reject(new JSError('jwt must be a string', 'JSONWebTokenError'));
      }

      const parts = jwtString.split('.');

      if (parts.length !== 3) {
        reject(new JSError('jwt malformed', 'JSONWebTokenError'));
      }

      const hasSignature = parts[2].trim() !== '';


      if (!hasSignature && secretOrPublicKey) {
        reject(new JSError('jwt signature is required', 'JSONWebTokenError'));
      }

      if (hasSignature && !secretOrPublicKey) {
        reject(new JSError(
            'secret or public key must be provided', 'JSONWebTokenError'));
      }

      if (options && !hasSignature && !options.algorithms) {
        options.algorithms = ['none'];
      }

      if (options && !options.algorithms) {
        options.algorithms =
            ~secretOrPublicKey.toString().indexOf('BEGIN CERTIFICATE') ||
                ~secretOrPublicKey.toString().indexOf('BEGIN PUBLIC KEY') ?
            ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'] :
            ~secretOrPublicKey.toString().indexOf('BEGIN RSA PUBLIC KEY') ?
            ['RS256', 'RS384', 'RS512'] :
            ['HS256', 'HS384', 'HS512'];
      }
      resolve(null);
    });
  }

  /**
   * Verify if payload options matches the expected claim values
   * @param payload Could be an object literal, buffer or string, containing
   claims. Please note that exp is only set if the payload is an object literal.
   * @param tokenProfile Contains the token properties, required, optional and
   verification claims
   * @throws JsonWebToken error if options does not match expected claims
   * @memberof MessageVerifier.prototype
   */
  verifyPayload(decoded, tokenProfile, otherOptions) {
    const options = tokenProfile.getVerificationClaims();
    let payload;
    if (otherOptions.complete) {
      payload = decoded.payload;
    } else {
      payload = decoded;
    }

    if (!otherOptions) {
      otherOptions = {};
    }
    const clockTimestamp =
        otherOptions.clockTimestamp || Math.floor(Date.now() / 1000);

    return new Promise((resolve, reject) => {
      if (typeof payload.nbf !== 'undefined' && !otherOptions.ignoreNotBefore) {
        if (typeof payload.nbf !== 'number') {
          reject(new JSError('invalid nbf value', 'JSONWebTokenError'));
        }
        if (payload.nbf > clockTimestamp + (options.clockTolerance || 0)) {
          reject(new JSError(
              'jwt not active', 'NotBeforeError',
              new Date(payload.nbf * 1000)));
        }
      }

      if (typeof payload.exp !== 'undefined' &&
          !otherOptions.ignoreExpiration) {
        if (typeof payload.exp !== 'number') {
          reject(new JSError('invalid exp value', 'JSONWebTokenError'));
        }
        if (clockTimestamp >= payload.exp + (options.clockTolerance || 0)) {
          reject(new JSError(
              'jwt expired', 'JSONWebTokenError',
              new Date(payload.exp * 1000)));
        }
      }

      Object.keys(tokenProfile.claimsForVerification).forEach(key => {
        const claim = tokenProfile.claimsForVerification[key];
        if (options[key] && key !== 'maxAge' && key !== 'clockTolerance' &&
            key !== 'aud') {
          if (payload[claim] !== options[key]) {
            reject(new JSError(
                `jwt option invalid. expected: ${options[key]}`,
                'JSONWebTokenError'));
          }
        }
      });

      if (options.aud) {
        const audiences =
            Array.isArray(options.audience) ? options.aud : [options.aud];
        const target = Array.isArray(payload.aud) ? payload.aud : [payload.aud];

        const match = target.some(
            targetAudience => audiences.some(
                audience => audience instanceof RegExp ?
                    audience.test(targetAudience) :
                    audience === targetAudience));

        if (!match)
          reject(new JSError(
              `jwt audience invalid. expected: ${audiences.join(' or ')}`,
              'JSONWebTokenError'));
      }

      /*
      if (otherOptions.issuer) {
        const invalid_issuer =
            (typeof otherOptions.issuer === 'string' && payload.iss !==
      otherOptions.issuer) || (Array.isArray(otherOptions.issuer) &&
      otherOptions.issuer.indexOf(payload.iss) === -1);

        if (invalid_issuer) {
          return done(new JsonWebTokenError('jwt issuer invalid. expected: ' +
      otherOptions.issuer));
        }
      }

      if (otherOptions.subject) {
        if (payload.sub !== otherOptions.subject) {
          return done(new JsonWebTokenError('jwt subject invalid. expected: ' +
      otherOptions.subject));
        }
      }*/
      if (otherOptions.jwtid) {
        if (payload.jti !== otherOptions.jwtid) {
          reject(new JSError(
              `jwt jwtid invalid. expected: ${otherOptions.jwtid}`,
              'JSONWebTokenError'));
        }
      }

      if (options.maxAge) {
        if (typeof payload.iat !== 'number') {
          reject(new JSError(
              'iat required when maxAge is specified', 'JSONWebTokenError'));
        }

        const maxAgeTimestamp = timespan(options.maxAge, payload.iat);
        if (typeof maxAgeTimestamp === 'undefined') {
          reject(new JSError(
              '"maxAge" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60',
              'JSONWebTokenError'));
        }
        if (clockTimestamp >= maxAgeTimestamp + (options.clockTolerance || 0)) {
          reject(new JSError(
              'maxAge exceeded', 'TokenExpiredError',
              new Date(maxAgeTimestamp * 1000)));
        }
      }
      resolve(decoded);
    });
  }
}

module.exports = MessageVerifier;