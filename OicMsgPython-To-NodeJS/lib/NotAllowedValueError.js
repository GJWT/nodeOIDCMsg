  var NotAllowedValueError = function (message, error) {
    Error.call(this, message);
    if(Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
    this.name = 'NotAllowedValueError';
    this.message = message;
    if (error) this.inner = error;
  };
  
  NotAllowedValueError.prototype = Object.create(Error.prototype);
  NotAllowedValueError.prototype.constructor = NotAllowedValueError;
  
  module.exports = NotAllowedValueError