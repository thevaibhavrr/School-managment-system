const TryCatch = require("../../middleware/TryCatch"); // TryCatch middleware
const School = require("../../model/SuperAdmin/School"); // School model
const User = require("../../model/User/User"); // User model
const Fee = require("../../model/admin/Fee"); // Fee model
const SchoolExam = require("../../model/ExamSchema/exammodel");
const Userclass = require("../../model/SchoolClass/Schoolclass");

// Admin Panel for superadmin
const SuperAdminPanel = TryCatch(async (req, res) => {
  const TotalUser = await User.countDocuments();
  const totalTeacher = await User.countDocuments({
    role: "teacher",
  });
  const totalStudent = await User.countDocuments({
    role: "student",
  });
  const totalAdmin = await User.countDocuments({
    role: "admin",
  });
  const TotalSchool = await School.countDocuments();
  res.json({
    totalUser: TotalUser,
    totalTeachers: totalTeacher,
    totalStudents: totalStudent,
    totalAdmin: totalAdmin,
    totalSchool: TotalSchool,
  });
});

// admin panel for admin
const AdminPanel = TryCatch(async (req, res) => {
  const schoolId = req.user.schoolId;
  const userId = req.user.id;

  // self details
  const AboutMe = await User.findById(userId);
  const username = AboutMe.name;

  // for exam
  const searchQuery = {
    schoolId,
  };
  const exams = await SchoolExam.find(searchQuery);

  // for fees
  const Feesdata = await Fee.find(searchQuery);

  var totalschoolFees = 0;
  await Feesdata.map((e) => {
    totalschoolFees = totalschoolFees + e.fees;
  });

  // total painding fees
   const roleFilter = ["student"];
     const searchQuery2 = {
       role: { $in: roleFilter },
       schoolId,
     };
    const AllStudent = await User.find(searchQuery2);
    var totalpaindingfees = 0;
    await AllStudent.map((e)=>{
       totalpaindingfees = totalpaindingfees + e.totalreminingfee;
    })
// total paid fees
var totalpaidfee = 0;
await AllStudent.map((e) => {
  totalpaidfee = totalpaidfee + e.totalpaidfee;
});

  // total classed in school
  const totalClass = Feesdata.length;

  // for school
  const schooldetails = await School.findById(schoolId);
  const schoolName = schooldetails.schoolname;

  // oother users details
  const TotalUser = await User.countDocuments({ schoolId });
  const totalTeacher = await User.countDocuments({
    role: "teacher",
    schoolId,
  }); 
  const totalStudent = await User.countDocuments({
    role: "student",
    schoolId,
  });
  const totalAdmin = await User.countDocuments({
    role: "admin",
    schoolId,
  });

  res.json({
    username,
    schoolName,
    totalUser: TotalUser,
    totalTeachers: totalTeacher,
    totalStudents: totalStudent,
    totalAdmin: totalAdmin,
    Totalclasses: totalClass,
    totalschoolFees,
    totalpaidfee,
    totalpaindingfees,
    Fees: Feesdata,
    Schoolexams: exams,
  });
});

// admin panel forteacher
const TeacherPanel = TryCatch(async (req, res) => {
  const schoolId = req.user.schoolId;
  const userId = req.user.id;

  // self details
  const AboutMe = await User.findById(userId);
  const username = AboutMe.name;

  // for exam
  const searchQuery = {
    schoolId,
  };
  const exams = await SchoolExam.find(searchQuery);

  // for fees
  const Feesdata = await Fee.find(searchQuery);
  const totalClass = Feesdata.length;

  // for school
  const schooldetails = await School.findById(schoolId);
  const schoolName = schooldetails.schoolname;

  // users details
  const totalTeacher = await User.countDocuments({
    role: "teacher",
    schoolId,
  });
  const totalStudent = await User.countDocuments({
    role: "student",
    schoolId,
  });

  res.json({
    username,
    schoolName,
    totalTeachers: totalTeacher,
    totalStudents: totalStudent,
    Totalclasses: totalClass,
    Fees: Feesdata,
    Schoolexams: exams,
  });
});

// admin panel for student
const StudentPanel = TryCatch(async (req, res) => {
  const schoolId = req.user.schoolId;
  const userId = req.user.id;
  const classid = await req.user.classId;

  // class details
  const classfind = await Userclass.findOne(classid);

  // for exam
  const searchQuery = {
    schoolId,
    classId: classid,
  };
  const exams = await SchoolExam.find(searchQuery);

  // self details
  const AboutMe = await User.findById(userId);
  const username = AboutMe.name;

  // for fees
  const classFees = await Fee.findOne({ schoolId, classId: classid });
  const totalFess = classFees.fees;
  const instalment1 = AboutMe.feesinstall1;
  const instalment2 = AboutMe.feesinstall2;
  const instalment3 = AboutMe.feesinstall3;
  const totalpaidfee = instalment1 + instalment2 + instalment3;

  const remingfees = totalFess - totalpaidfee;

  // for school
  const schooldetails = await School.findById(schoolId);
  const schoolName = schooldetails.schoolname;

  res.json({
    username,
    classs: classfind.className,
    schoolName,
    instalment1,
    instalment2,
    instalment3,
    totalpaidfee,
    allfess: totalFess,
    pandingFee: remingfees,
    Schoolexams: exams,
  });
});

// exporting data
module.exports = {
  SuperAdminPanel,
  AdminPanel,
  TeacherPanel,
  StudentPanel,
};
