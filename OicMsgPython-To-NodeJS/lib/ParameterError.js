  var ParameterError = function (message, error) {
    Error.call(this, message);
    if(Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
    this.name = 'ParameterError';
    this.message = message;
    if (error) this.inner = error;
  };
  
  ParameterError.prototype = Object.create(Error.prototype);
  ParameterError.prototype.constructor = ParameterError;
  
  module.exports = ParameterError