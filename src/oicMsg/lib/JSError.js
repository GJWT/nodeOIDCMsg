
var Type = {
  JsonWebTokenError: 'JsonWebTokenError',
  TokenExpiredError: 'TokenExpiredError',
  NotBeforeError: 'NotBeforeError',
};

const JSError = function(message, type, error) {

  Error.call(this, message);
  if (Error.captureStackTrace) {
    Error.captureStackTrace(this, this.constructor);
  }
  switch (type) {
    case Type.JsonWebTokenError:
      this.name = Type.JsonWebTokenError;
      break;
    case Type.TokenExpiredError:
      this.name = Type.TokenExpiredError;
      break;
    default:
      this.name = 'Unknown Error';
      break;
  }
  this.message = message;
  if (error) this.inner = error;
};

JSError.prototype = Object.create(JSError.prototype);
JSError.prototype.constructor = JSError;
module.exports = JSError;