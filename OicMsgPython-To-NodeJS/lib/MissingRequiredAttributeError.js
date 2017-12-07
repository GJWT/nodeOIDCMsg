  var MissingRequiredAttributeError = function (message, error) {
    Error.call(this, message);
    if(Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
    this.name = 'MissingRequiredAttributeError';
    this.message = message;
    if (error) this.inner = error;
  };
  
  MissingRequiredAttributeError.prototype = Object.create(Error.prototype);
  MissingRequiredAttributeError.prototype.constructor = MissingRequiredAttributeError;
  
  module.exports = MissingRequiredAttributeError