const mongoose = require("mongoose");

const Notification = new mongoose.Schema({
  title: {
    type: String,
  },
  description: {
    type: String,
  },
  status: {
    type: String, 
    default: "active",
  },
  date: {
    type: Date, 
    default: Date.now(),
  },
  CreateByuser: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "users",
  },
  schoolId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "schools",
  },
  for: {
    type: String,
  },
});

module.exports = mongoose.model("notification", Notification);
