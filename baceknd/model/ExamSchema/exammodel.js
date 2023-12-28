const mongoose = require("mongoose");

const ExamSchema = new mongoose.Schema({
  subject: {
    type: String,
    required: [true, "please enter subject nane"],
  },
  date: {
    type: Date,
    required: [true, "please enter Date"],
  },
  duration: {
    type: Number,
    required: [true, "please enter exam time"],
  },
  examtype: {
    type: String,
    enum:["Quarterly","Half Yearly","Yearly"],
    required: [true, "please enter exam type"],
  },
  totalMarks: {
    type: Number,
    required: [true, "please enter Toal marks"],
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Users",
    required: [true, "please enter created by id"],
  },
  schoolId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Schools",
    required: [true, "please enter School  id"],
  },
  classId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Class",
    required: [true, "please enter class  id"],
  },
  status: {
    type: String,
    enum: ["upcoming", "history"],
    default: "upcoming",
  },
  
});

const Exam = mongoose.model("Exam", ExamSchema);

module.exports = Exam;
