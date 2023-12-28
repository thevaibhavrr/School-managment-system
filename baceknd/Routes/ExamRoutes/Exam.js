const express = require("express");
const router = express.Router();
const ExamController = require("../../controller/Examcontroller/exam");
const auth = require("../../middleware/Auth");

// Routes for exams

//create an exam
router.post(
  "/addexam",
  auth.isAuthenticateUser,
  auth.authorizeRole("admin", "teacher"),
  ExamController.createExam
);

//get all exams
router.get(
  "/allexams",
  auth.isAuthenticateUser,
  auth.authorizeRole("admin", "teacher"),
  ExamController.getAllExams
);

//get all exams by class ID
router.get(
  "/allexams/:classId",
  auth.isAuthenticateUser,
  ExamController.getAllExamsByClass
);

//get exam details by exam ID
router.get(
  "/examdetails/:examId",
  auth.isAuthenticateUser,
  ExamController.getExamById
);

//update an exam by exam ID
router.put(
  "/examupdate/:examId",
  auth.isAuthenticateUser,
  ExamController.updateExamById
);

//delete an exam by exam ID
router.delete(
  "/examdelete/:examId",
  auth.isAuthenticateUser,
  ExamController.deleteExamById
);

//get my exams (for students)
router.get("/myexam", auth.isAuthenticateUser, ExamController.MyExams);

//get my school exams (for admin and teacher)
router.get(
  "/myschoolexam",
  auth.isAuthenticateUser,
  auth.authorizeRole("admin", "teacher"),
  ExamController.MySchoolExams
);

module.exports = router;
