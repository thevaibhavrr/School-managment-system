const mongoose = require("mongoose");
const SchoolClass = new mongoose.Schema({
  className: {
    type: String,
    required: [true, "please Enter className"],
    unique: [true , "this class is already exist"],
  },
});

module.exports = mongoose.model("Class",SchoolClass) 


