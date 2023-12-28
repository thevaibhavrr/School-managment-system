const ErrorHandler = require("./errorHandel");

module.exports = function checkPostBody(requiredFields, req) {
  for (const field of requiredFields) {
    if (!Object.prototype.hasOwnProperty.call(req.body, field)) {
      throw new ErrorHandler(`Missing field: ${field}.`, 400);
    }
  }
};
