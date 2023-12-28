const mongoose = require("mongoose");
const section = new mongoose.Schema({
  schoolId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Schools",
  },
  classId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Class",
    required: [true, "please enter classId"],
  },
  sectioname: {
    type: String,
    required: [true, "please enter sectioname name"],
  },
});

module.exports = mongoose.model("section", section);
