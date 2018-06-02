const OAuth2 = require('../OAuth2/init.js');
const OAuth2TokenErrorResponse =
    require('../OAuth2/responses').TokenErrorResponse;
const OAuth2RefreshAccessTokenRequest =
    require('../OAuth2/requests').RefreshAccessTokenRequest;
const OAuth2AccessTokenResponse =
    require('../OAuth2/responses').AccessTokenResponse;
const OAuth2AuthorizationResponse =
    require('../OAuth2/responses').AuthorizationResponse;
const OAuth2AuthorizationErrorResponse =
    require('../OAuth2/responses').AuthorizationErrorResponse;
const OAuth2AuthorizationRequest =
    require('../OAuth2/requests').AuthorizationRequest;
const OAuth2AccessTokenRequest =
    require('../OAuth2/requests').AccessTokenRequest;
const OAuth2ErrorResponse = require('../OAuth2/responses').ErrorResponse;
const SINGLE_OPTIONAL_STRING = require('../OAuth2/init').SINGLE_OPTIONAL_STRING;
const SINGLE_OPTIONAL_IDTOKEN = require('../OAuth2/init').SINGLE_OPTIONAL_IDTOKEN;
const Message = require('../message');

/**
 * @fileoverview Contains all the OIC response classes
 */

/**
 * TokenErrorResponse
 * @class
 * @constructor
 * @extends OAuth2TokenErrorResponse
 */
class TokenErrorResponse extends OAuth2TokenErrorResponse {
  constructor() {
    super();
  }
}

/**
 * AccessTokenResponse
 * @class
 * @constructor
 * @extends OAuth2AccessTokenResponse
 */
class AccessTokenResponse extends OAuth2AccessTokenResponse {
  constructor(claims) {
    super(claims);
    if (claims){
      this.claims = claims;
    }else{
      this.claims = {};
    }
    this.cParam =
        Object.assign(this.cParam, {'id_token': SINGLE_OPTIONAL_STRING});
    return this;
  }

  verify(params) {
    if (!params){
      params = this.claims;
    }
    // super();
    if (Object.keys(this.claims).indexOf('id_token')) {
      let args = {};
      const argsArray = ['key', 'keyjar', 'algs', 'sender'];
      for (var i = 0; i < argsArray.length; i++) {
        let arg = argsArray[i];
        if (params[arg]) {
          args[arg] = params[arg];
        }
      }

      if (this.claims['id_token']){
        const idt = new Message().fromJWT(this.claims['id_token'], 'shhh', {}, {algorithm: 'HS256'});
        /*if (!idt.verify(params)){
          return false;
        }*/
        this.claims['verified_id_token'] = idt;
      }
    }
    return true;
  }
}


/**
 * AuthorizationResponse
 * @class
 * @constructor
 * @extends OAuth2AuthorizationResponse
 */
class AuthorizationResponse extends OAuth2AuthorizationResponse {
  constructor(claims) {
    super(claims);
    if (claims){
      this.claims = claims;
    }else{
      this.claims = {};
    }
    this.cParam = OAuth2AuthorizationResponse.cParam;
    //this.cParam = Object.assign(OAuth2AccessTokenResponse.cParam, this.cParam);
    this.cParam = Object.assign({
      'code': SINGLE_OPTIONAL_STRING,
      'nonce': SINGLE_OPTIONAL_STRING,
      'access_token': SINGLE_OPTIONAL_STRING,
      'token_type': SINGLE_OPTIONAL_STRING,
      'id_token': SINGLE_OPTIONAL_IDTOKEN
    }, this.cParam);
    return this;
  }

  verify(params) {}
}

/**
 * AuthorizationErrorResponse
 * @class
 * @constructor
 * @extends OAuth2AuthorizationErrorResponse
 */
class AuthorizationErrorResponse extends OAuth2AuthorizationErrorResponse {
  constructor() {
    super();
    this.cAllowedValues = responses.AuthorizationErrorResponse.cAllowedValues;
    this.cAllowedValues['error'].extend([
      'interaction_required', 'login_required', 'session_selection_required',
      'consent_required', 'invalid_request_uri', 'invalid_request_object',
      'registration_not_supported', 'request_not_supported',
      'request_uri_not_supported'
    ]);
  }
}

/**
 * RegistrationResponse
 * @class
 * @constructor
 * @extends Message
 */
class RegistrationResponse extends Message {
  /** Response to client_register registration requests */
  constructor() {
    super();
    this.cParam = {
      'client_id': SINGLE_REQUIRED_STRING,
      'client_secret': SINGLE_OPTIONAL_STRING,
      'registration_access_token': SINGLE_OPTIONAL_STRING,
      'registration_client_uri': SINGLE_OPTIONAL_STRING,
      'client_id_issued_at': SINGLE_OPTIONAL_INT,
      'client_secret_expires_at': SINGLE_OPTIONAL_INT,
    }
  }

  verify() {}
}

/**
 * ClientRegistrationErrorResponse
 * @class
 * @constructor
 * @extends OAuth2ErrorResponse
 */
class ClientRegistrationErrorResponse extends OAuth2ErrorResponse {
  constructor() {
    super();
    this.cAllowedValues = {
      'error': [
        'invalid_redirect_uri', 'invalid_client_metadata',
        'invalid_configuration_parameter'
      ]
    };
  }
}

/**
 * MessageWithIdToken
 * @class
 * @constructor
 * @extends Message
 */
class MessageWithIdToken extends Message {
  constructor() {
    super();
    this.cParam = {'id_token': SINGLE_REQUIRED_IDTOKEN};
  }

  verify() {}
}

/**
 * RefreshSessionResponse
 * @class
 * @constructor
 * @extends MessageWithIdToken
 */
class RefreshSessionResponse extends MessageWithIdToken {
  constructor() {
    super();
    this.cParam = MessageWithIdToken.cParam;
    this.cParam.update({'state': SINGLE_REQUIRED_STRING});
  }
}

/**
 * EndSessionResponse
 * @class
 * @constructor
 * @extends Message
 */
class EndSessionResponse extends Message {
  constructor() {
    super();
    this.cParam = {'state': SINGLE_OPTIONAL_STRING};
  }
}

/**
 * ProviderConfigurationResponse
 * @class
 * @constructor
 * @extends Message
 */
class ProviderConfigurationResponse extends Message {
  constructor(claims) {
    super(claims);
    if (claims){
      this.claims = claims;
    }else{
      this.claims = {};
    }
    this.cParam = {
      'issuer': SINGLE_REQUIRED_STRING,
      'authorization_endpoint': SINGLE_REQUIRED_STRING,
      'token_endpoint': SINGLE_OPTIONAL_STRING,
      'userinfo_endpoint': SINGLE_OPTIONAL_STRING,
      'jwks_uri': SINGLE_REQUIRED_STRING,
      'registration_endpoint': SINGLE_OPTIONAL_STRING,
      'scopes_supported': OPTIONAL_LIST_OF_STRINGS,
      'response_types_supported': REQUIRED_LIST_OF_STRINGS,
      'response_modes_supported': OPTIONAL_LIST_OF_STRINGS,
      'grant_types_supported': OPTIONAL_LIST_OF_STRINGS,
      'acr_values_supported': OPTIONAL_LIST_OF_STRINGS,
      'subject_types_supported': REQUIRED_LIST_OF_STRINGS,
      'id_token_signing_alg_values_supported': REQUIRED_LIST_OF_STRINGS,
      'id_token_encryption_alg_values_supported': OPTIONAL_LIST_OF_STRINGS,
      'id_token_encryption_enc_values_supported': OPTIONAL_LIST_OF_STRINGS,
      'userinfo_signing_alg_values_supported': OPTIONAL_LIST_OF_STRINGS,
      'userinfo_encryption_alg_values_supported': OPTIONAL_LIST_OF_STRINGS,
      'userinfo_encryption_enc_values_supported': OPTIONAL_LIST_OF_STRINGS,
      'request_object_signing_alg_values_supported': OPTIONAL_LIST_OF_STRINGS,
      'request_object_encryption_alg_values_supported':
          OPTIONAL_LIST_OF_STRINGS,
      'request_object_encryption_enc_values_supported':
          OPTIONAL_LIST_OF_STRINGS,
      'token_endpoint_auth_methods_supported': OPTIONAL_LIST_OF_STRINGS,
      'token_endpoint_auth_signing_alg_values_supported':
          OPTIONAL_LIST_OF_STRINGS,
      'display_values_supported': OPTIONAL_LIST_OF_STRINGS,
      'claim_types_supported': OPTIONAL_LIST_OF_STRINGS,
      'claims_supported': OPTIONAL_LIST_OF_STRINGS,
      'service_documentation': SINGLE_OPTIONAL_STRING,
      'claims_locales_supported': OPTIONAL_LIST_OF_STRINGS,
      'ui_locales_supported': OPTIONAL_LIST_OF_STRINGS,
      'claims_parameter_supported': SINGLE_OPTIONAL_BOOLEAN,
      'request_parameter_supported': SINGLE_OPTIONAL_BOOLEAN,
      'request_uri_parameter_supported': SINGLE_OPTIONAL_BOOLEAN,
      'require_request_uri_registration': SINGLE_OPTIONAL_BOOLEAN,
      'op_policy_uri': SINGLE_OPTIONAL_STRING,
      'op_tos_uri': SINGLE_OPTIONAL_STRING,
      'check_session_iframe': SINGLE_OPTIONAL_STRING,
      'end_session_endpoint': SINGLE_OPTIONAL_STRING,
      'jwk_encryption_url': SINGLE_OPTIONAL_STRING,
      'x509_url': SINGLE_REQUIRED_STRING,
      'x509_encryption_url': SINGLE_OPTIONAL_STRING,
    };
    this.cDefault = {
      'version': '3.0',
      'token_endpoint_auth_methods_supported': ['client_secret_basic'],
      'claims_parameter_supported': False,
      'request_parameter_supported': False,
      'request_uri_parameter_supported': True,
      'require_request_uri_registration': True,
      'grant_types_supported': ['authorization_code', 'implicit']
    };
    return this;
  }

  verify(params) {}
}

/**
 * UserInfoErrorResponse
 * @class
 * @constructor
 * @extends OAuth2ErrorResponse
 */
class UserInfoErrorResponse extends OAuth2ErrorResponse {
  constructor() {
    super();
    this.cAllowedValues = {
      'error': [
        'invalid_schema', 'invalid_request', 'invalid_token',
        'insufficient_scope'
      ]
    };
  }
}

module.exports.AuthorizationResponse = AuthorizationResponse;
module.exports.AccessTokenResponse = AccessTokenResponse;
module.exports.ProviderConfigurationResponse = ProviderConfigurationResponse;
module.exports.RegistrationResponse = RegistrationResponse;