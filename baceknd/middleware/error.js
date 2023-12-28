const ErrorHander = require("../utils/errorHandel");

const errorHandel = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.message = err.message || "Internal Server Error";

  //  sending status data

  res.status(err.statusCode).json({
    success: false,
    message: err.message,
  });
};

module.exports = errorHandel;
