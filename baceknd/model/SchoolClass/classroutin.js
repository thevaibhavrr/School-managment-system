const mongoose = require("mongoose");
const classroutine = new mongoose.Schema({
  subject: {
    type: String,
    required: [true, "please Enter subject name"],
  },
  schoolId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Schools",
  },
  classId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Class",
    required: [true, "please enter classId"],
  },
  day: {
    type: String,
    required: [true, "please Enter day "],
  },
  starttime: {
    type: String,
    required: [true, "please class strting time "],
  },
  endtime: {
    type: String,
    required: [true, "please class end time "],
  },
});

module.exports = mongoose.model("classroutine", classroutine);
