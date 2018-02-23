const Message = require('../message');
const AccessToken = require('../tokenProfiles/accessToken');
const SINGLE_REQUIRED_STRING = require('./init').SINGLE_REQUIRED_STRING
const SINGLE_OPTIONAL_STRING = require('./init').SINGLE_OPTIONAL_STRING
const REQUIRED_LIST_OF_SP_SEP_STRINGS =
    require('./init').REQUIRED_LIST_OF_SP_SEP_STRINGS;
const OPTIONAL_LIST_OF_SP_SEP_STRINGS =
    require('./init').OPTIONAL_LIST_OF_SP_SEP_STRINGS;
const REQUIRED_LIST_OF_STRINGS = require('./init').REQUIRED_LIST_OF_STRINGS;
const OPTIONAL_LIST_OF_STRINGS = require('./init').OPTIONAL_LIST_OF_STRINGS;
const SINGLE_OPTIONAL_INT = require('./init').SINGLE_OPTIONAL_INT;

/**
 * @fileoverview Contains all the OIC request classes
 */

/**
 * ErrorResponse
 * @class
 * @constructor
 * @extends Message
 * The basic error response
 */
class ErrorResponse extends Message {
  constructor() {
    super();
    this.cParam = {
      'error': SINGLE_REQUIRED_STRING,
      'error_description': SINGLE_OPTIONAL_STRING,
      'error_uri': SINGLE_OPTIONAL_STRING,
    };
  }
};

/**
 * AuthorizationErrorResponse
 * @class
 * @constructor
 * @extends Message
 * Authorization error response
 */
class AuthorizationErrorResponse extends Message {
  constructor() {
    super();
    this.cParam = ErrorResponse.c_param.copy()
    cParam.update({'state': SINGLE_OPTIONAL_STRING});
    this.cAllowedValues =
        ErrorResponse.c_allowed_values.copy()
    cAllowedValues.update({
      'error': [
        'invalid_request', 'unauthorized_client', 'access_denied',
        'unsupported_response_type', 'invalid_scope', 'server_error',
        'temporarily_unavailable'
      ]
    });
  }
};

/**
 * TokenErrorResponse
 * @class
 * @constructor
 * @extends Message
 * Error response from the token endpoint
 */
class TokenErrorResponse extends Message {
  constructor() {
    this.cAllowedValues = {
      'error': [
        'invalid_request', 'invalid_client', 'invalid_grant',
        'unauthorized_client', 'unsupported_grant_type', 'invalid_scope'
      ]
    };
  }
};

/**
 * AuthorizationResponse
 * @class
 * @constructor
 * @extends Message
 *  An authorization response.
 *  If *client_id* is returned in the response it will be checked against
 *  a client_id value provided when calling the verify method.
 *  The same with *iss* (issuer).
 */
class AuthorizationResponse extends Message {
  constructor(code, state, accessToken, tokenType, idToken) {
    super();
    this.cParam = {
      'code': SINGLE_REQUIRED_STRING,
      'state': SINGLE_OPTIONAL_STRING,
      'iss': SINGLE_OPTIONAL_STRING,
      'client_id': SINGLE_OPTIONAL_STRING
    };

    const dict = {};
    if (code) {
      dict['code'] = code;
      this.code = code;
    }
    if (state) {
      dict['state'] = state;
      this.state = state;
    }
    if (accessToken) {
      dict['access_token'] = accessToken;
    }
    if (tokenType) {
      dict['token_type'] = tokenType;
    }
    if (idToken) {
      dict['id_token'] = idToken;
    }
    return dict;
  }

  verify(kwargs) {
    // Token.call(AuthorizationResponse).verify(kwargs);
    if (this.client_id) {
      try {
        if (this.clientId !== kwargs['clientId']) {
          console.log('client id mismatch');
        }
      } catch (err) {
        console.log('No client_id to verify against');
        return;
      }
    }
    if (this.iss) {
      try {
        if (this.iss !== kwargs['iss']) {
          console.log('Issuer mismatch');
        }
      } catch (err) {
        console.log('No issuer set in the Client config');
        return;
      }
    }
    return true;
  };
}

/**
 * AccessTokenResponse
 * @class
 * @constructor
 * @extends Message
 */
class AccessTokenResponse extends Message {
  constructor(args) {
    super();
    this.cParam = {
      'access_token': SINGLE_REQUIRED_STRING,
      'token_type': SINGLE_REQUIRED_STRING,
      'expires_in': SINGLE_OPTIONAL_INT,
      'refresh_token': SINGLE_OPTIONAL_STRING,
      'scope': OPTIONAL_LIST_OF_SP_SEP_STRINGS,
      'state': SINGLE_OPTIONAL_STRING
    };
    return args;
  }
}

/**
 * ASConfigurationResponse
 * @class
 * @constructor
 * @extends Message
 */
class ASConfigurationResponse extends Message {
  constructor() {
    super();
    this.cParam = {
      'issuer': SINGLE_REQUIRED_STRING,
      'authorization_endpoint': SINGLE_OPTIONAL_STRING,
      'token_endpoint': SINGLE_OPTIONAL_STRING,
      'jwks_uri': SINGLE_OPTIONAL_STRING,
      'registration_endpoint': SINGLE_OPTIONAL_STRING,
      'scopes_supported': OPTIONAL_LIST_OF_STRINGS,
      'response_types_supported': REQUIRED_LIST_OF_STRINGS,
      'response_modes_supported': OPTIONAL_LIST_OF_STRINGS,
      'grant_types_supported': REQUIRED_LIST_OF_STRINGS,
      'token_endpoint_auth_methods_supported': OPTIONAL_LIST_OF_STRINGS,
      'token_endpoint_auth_signing_alg_values_supported':
          OPTIONAL_LIST_OF_STRINGS,
      'service_documentation': SINGLE_OPTIONAL_STRING,
      'ui_locales_supported': OPTIONAL_LIST_OF_STRINGS,
      'op_policy_uri': SINGLE_OPTIONAL_STRING,
      'op_tos_uri': SINGLE_OPTIONAL_STRING,
      'revocation_endpoint': SINGLE_OPTIONAL_STRING,
      'introspection_endpoint': SINGLE_OPTIONAL_STRING,
    };
    this.cDefault = {'version': '3.0'};
  }
};

/**
 * NoneResponse
 * @class
 * @constructor
 * @extends Message
 */
class NoneResponse extends Message {
  constructor() {
    super();
    this.cParam = { 'state': SINGLE_OPTIONAL_STRING }
  }
};

module.exports.ErrorResponse = ErrorResponse;
module.exports.AuthorizationErrorResponse = AuthorizationErrorResponse;
module.exports.TokenErrorResponse = TokenErrorResponse;
module.exports.AuthorizationResponse = AuthorizationResponse;
module.exports.AccessTokenResponse = AccessTokenResponse;
module.exports.NoneResponse = NoneResponse;
module.exports.ASConfigurationResponse = ASConfigurationResponse;