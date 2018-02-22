const OAuth2 = require('../OAuth2/init.js');
const OAuth2TokenErrorResponse = require('../OAuth2/responses').TokenErrorResponse;
const OAuth2RefreshAccessTokenRequest = require('../OAuth2/requests').RefreshAccessTokenRequest;
const OAuth2AccessTokenResponse = require('../OAuth2/responses').AccessTokenResponse;
const OAuth2AuthorizationResponse = require('../OAuth2/responses').AuthorizationResponse;
const OAuth2AuthorizationErrorResponse = require('../OAuth2/responses').AuthorizationErrorResponse;
const OAuth2AuthorizationRequest = require('../OAuth2/requests').AuthorizationRequest;
const OAuth2AccessTokenRequest = require('../OAuth2/requests').AccessTokenRequest;
const OAuth2ErrorResponse = require('../OAuth2/responses').ErrorResponse;
const SINGLE_OPTIONAL_STRING = require('../OAuth2/init').SINGLE_OPTIONAL_STRING;
const Message = require('../src/models/tokenProfiles/message');
const MessageWithIdToken = require('./init').MessageWithIdToken;

/**
 * @fileoverview Contains all the OIC request classes
 */

/**
 * RefreshAccessTokenRequest
 * @class
 * @constructor
 * @extends OAuth2RefreshAccessTokenRequest
 */
class RefreshAccessTokenRequest extends OAuth2RefreshAccessTokenRequest{
    constructor(){
        super();
    }
}

/**
 * UserInfoRequest
 * @class
 * @constructor
 * @extends Message
 */
class UserInfoRequest extends Message{
    constructor(){
        super();
        this.cParam = {
            access_token: SINGLE_OPTIONAL_STRING,
        }
    }
}

/**
 * AuthorizationRequest
 * @class
 * @constructor
 * @extends OAuth2AuthorizationRequest
 */
class AuthorizationRequest extends OAuth2AuthorizationRequest{
    constructor(){
        super();
        this.cParam = requests.AuthorizationRequest.cParam;
        this.cParam.update({
            "scope": REQUIRED_LIST_OF_SP_SEP_STRINGS,
            "redirect_uri": SINGLE_REQUIRED_STRING,
            "nonce": SINGLE_OPTIONAL_STRING,
            "display": SINGLE_OPTIONAL_STRING,
            "prompt": OPTIONAL_LIST_OF_STRINGS,
            "max_age": SINGLE_OPTIONAL_INT,
            "ui_locales": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
            "claims_locales": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
            "id_token_hint": SINGLE_OPTIONAL_STRING,
            "login_hint": SINGLE_OPTIONAL_STRING,
            "acr_values": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
            "claims": SINGLE_OPTIONAL_CLAIMSREQ,
            "registration": SINGLE_OPTIONAL_JSON,
            "request": SINGLE_OPTIONAL_STRING,
            "request_uri": SINGLE_OPTIONAL_STRING,
            "session_state": SINGLE_OPTIONAL_STRING,
            "response_mode": SINGLE_OPTIONAL_STRING,
        });
        this.cAllowedValues = requests.AuthorizationRequest.cAllowedValues;
        this.cAllowedValues.update({
            "display": ["page", "popup", "touch", "wap"],
            "prompt": ["none", "login", "consent", "select_account"]
        });
    }

    verify(){
    }
}

/**
 * AccessTokenRequest
 * @class
 * @constructor
 * @extends OAuth2AccessTokenRequest
 */
class AccessTokenRequest extends OAuth2AccessTokenRequest{
    constructor(){
        super();
        this.cParam = requests.AccessTokenRequest.cParam;
        this.cParam.update({"client_assertion_type": SINGLE_OPTIONAL_STRING,
        "client_assertion": SINGLE_OPTIONAL_STRING});
        this.cDefault = {"grant_type": "authorization_code"};
        this.cAllowedValues = {'clientAssertionType': ["urn:ietf:params:oauth:client-assertion-type:jwt-bearer"]};
    }
}

/**
 * RegistrationRequest
 * @class
 * @constructor
 * @extends Message
 */
class RegistrationRequest extends Message{
    constructor(){
        super();
        this.cParam ={"redirect_uris": REQUIRED_LIST_OF_STRINGS,
            "response_types": OPTIONAL_LIST_OF_STRINGS,
            "grant_types": OPTIONAL_LIST_OF_STRINGS,
            "application_type": SINGLE_OPTIONAL_STRING,
            "contacts": OPTIONAL_LIST_OF_STRINGS,
            "client_name": SINGLE_OPTIONAL_STRING,
            "logo_uri": SINGLE_OPTIONAL_STRING,
            "client_uri": SINGLE_OPTIONAL_STRING,
            "policy_uri": SINGLE_OPTIONAL_STRING,
            "tos_uri": SINGLE_OPTIONAL_STRING,
            "jwks": SINGLE_OPTIONAL_STRING,
            "jwks_uri": SINGLE_OPTIONAL_STRING,
            "sector_identifier_uri": SINGLE_OPTIONAL_STRING,
            "subject_type": SINGLE_OPTIONAL_STRING,
            "id_token_signed_response_alg": SINGLE_OPTIONAL_STRING,
            "id_token_encrypted_response_alg": SINGLE_OPTIONAL_STRING,
            "id_token_encrypted_response_enc": SINGLE_OPTIONAL_STRING,
            "userinfo_signed_response_alg": SINGLE_OPTIONAL_STRING,
            "userinfo_encrypted_response_alg": SINGLE_OPTIONAL_STRING,
            "userinfo_encrypted_response_enc": SINGLE_OPTIONAL_STRING,
            "request_object_signing_alg": SINGLE_OPTIONAL_STRING,
            "request_object_encryption_alg": SINGLE_OPTIONAL_STRING,
            "request_object_encryption_enc": SINGLE_OPTIONAL_STRING,
            "token_endpoint_auth_method": SINGLE_OPTIONAL_STRING,
            "token_endpoint_auth_signing_alg": SINGLE_OPTIONAL_STRING,
            "default_max_age": SINGLE_OPTIONAL_INT,
            "require_auth_time": OPTIONAL_LOGICAL,
            "default_acr_values": OPTIONAL_LIST_OF_STRINGS,
            "initiate_login_uri": SINGLE_OPTIONAL_STRING,
            "request_uris": OPTIONAL_LIST_OF_STRINGS,
            "client_id": SINGLE_OPTIONAL_STRING,
            "client_secret": SINGLE_OPTIONAL_STRING,
            "access_token": SINGLE_OPTIONAL_STRING,
            "post_logout_redirect_uris": OPTIONAL_LIST_OF_STRINGS
        };
        this.cDefault = {"application_type": "web", "response_types": ["code"]};
        this.cAllowedValues = {"application_type": ["native", "web"],
        "subject_type": ["public", "pairwise"]};
    }

    verify(kwargs){
    }
}

/**
 * RefreshSessionRequest
 * @class
 * @constructor
 * @extends MessageWithIdToken
 */
class RefreshSessionRequest extends MessageWithIdToken{
    constructor(){
        super();
        this.cParam = super.cParam;
        this.cParam.update({"redirect_url": SINGLE_REQUIRED_STRING,
        "state": SINGLE_REQUIRED_STRING});
    }
}

/**
 * CheckSessionRequest
 * @class
 * @constructor
 * @extends MessageWithIdToken
 */
class CheckSessionRequest extends MessageWithIdToken{
}

/**
 * CheckIdRequest
 * @class
 * @constructor
 * @extends Message
 */
class CheckIdRequest extends Message{
    constructor(){
        super();
        this.cParam = {"access_token": SINGLE_REQUIRED_STRING};
    }
}

/**
 * EndSessionRequest
 * @class
 * @constructor
 * @extends Message
 */
class EndSessionRequest extends Message{
    constructor(){
        super();
        this.cParam = {
            "id_token_hint": SINGLE_OPTIONAL_IDTOKEN,
            "post_logout_redirect_uri": SINGLE_OPTIONAL_STRING,
            "state": SINGLE_OPTIONAL_STRING
        };
    }
    verify(){
    }
}

/**
 * ClaimsRequest
 * @class
 * @constructor
 * @extends Message
 */
class ClaimsRequest extends Message{
    constructor(){
        super();
        this.cParam = {
            "userinfo": OPTIONAL_MULTIPLE_Claims,
            "id_token": OPTIONAL_MULTIPLE_Claims
        };
    }
}

/**
 * OpenIdRequest
 * @class
 * @constructor
 * @extends OAuth2AuthorizationRequest
 */
class OpenIdRequest extends OAuth2AuthorizationRequest{
}

/**
 * DiscoveryRequest
 * @class
 * @constructor
 * @extends Message
 */
class DiscoveryRequest extends Message{
    constructor(){
        this.cParam = {"resource": SINGLE_REQUIRED_STRING,
        "rel": SINGLE_REQUIRED_STRING};
    }
}