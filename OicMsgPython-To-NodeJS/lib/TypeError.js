  var TypeError = function (message, error) {
    Error.call(this, message);
    if(Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
    this.name = 'TypeError';
    this.message = message;
    if (error) this.inner = error;
  };
  
  TypeError.prototype = Object.create(Error.prototype);
  TypeError.prototype.constructor = TypeError;
  
  module.exports = TypeError;