  var InvalidAlgorithmException = function (message, error) {
    Error.call(this, message);
    if(Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
    this.name = 'InvalidAlgorithmException';
    this.message = message;
    if (error) this.inner = error;
  };
  
  InvalidAlgorithmException.prototype = Object.create(Error.prototype);
  InvalidAlgorithmException.prototype.constructor = InvalidAlgorithmException;
  
  module.exports = InvalidAlgorithmException;