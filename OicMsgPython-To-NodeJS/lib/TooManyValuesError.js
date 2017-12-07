  var TooManyValuesError = function (message, error) {
    Error.call(this, message);
    if(Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
    this.name = 'TooManyValuesError';
    this.message = message;
    if (error) this.inner = error;
  };
  
  TooManyValuesError.prototype = Object.create(Error.prototype);
  TooManyValuesError.prototype.constructor = TooManyValuesError;
  
  module.exports = TooManyValuesError;