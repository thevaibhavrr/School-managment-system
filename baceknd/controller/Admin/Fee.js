const Fee = require("../../model/admin/Fee"); // Fee model
const TryCatch = require("../../middleware/TryCatch"); // TryCatch middleware
const ErrorHandler = require("../../utils/errorHandel"); // ErrorHandler utility
const SchoolClass = require("../../model/SchoolClass/Schoolclass"); // SchoolClass model
const School = require("../../model/SuperAdmin/School"); // School model

const User = require("../../model/User/User");

// add fees
const AddFees = TryCatch(async (req, res) => {
  const schoolId = req.user.schoolId;
  const { classId, fees } = req.body;
  // class find
  const className = await SchoolClass.findById(classId);
  const Feeclass = await className.className;

  // find class
  const findClass = await SchoolClass.findOne({ _id: classId });
  // Check if class already exists for the school
  const existingClass = await Fee.findOne({ schoolId, classId });
  if (existingClass) {
    return res.status(400).json({
      success: false,
      message: `Class ${findClass.className} already exists for the school please update class fee`,
    });
  }

  // Create a new class entry
  const SchoolFeeByClass = await Fee.create({
    classId,
    fees,
    schoolId,
    classname: Feeclass,
  });

  res.status(200).json({
    success: true,
    message: `School class - ${findClass.className} fees have been added`,
    SchoolFeeByClass,
  });
});

// see all fees
const SeeAllFee = TryCatch(async (req, res) => {
  if (req.user.role == "superadmin") {
    const schoolFees = await Fee.find();
    res.json({ success: true, schoolFees });
  }
  // admin
  else if (req.user.role === "admin" || req.user.role === "teacher") {
    const schoolId = req.user.schoolId;
    const searchQuery = {
      schoolId,
    };
    const schoolcheck = await School.findById(schoolId);
    const data = await Fee.find(searchQuery)
    // total fees of school
    var total = 0;
    await data.map((e) => {
      total = total + e.fees;
    });
    // toal paid fees

    const totalClass = data.length;
    res.status(200).json({
      School: schoolcheck.schoolname,
      totalfee: total,
      TotalClass: totalClass,
      data,
    });
  }
});

// GetFeesByfeesId
const GetFeesByClassName = TryCatch(async (req, res) => {
  const { id } = req.params;

  const existingFees = await Fee.findById(id);

  if (!existingFees) {
    return res.status(404).json({
      success: false,
      message: "Fees not found.",
    });
  }

  const feesData = existingFees.fees;
  res.status(200).json({
    success: true,
    message: "School fees fetched successfully.",
    fees: feesData,
    Schoolclass: existingFees.classname,
  });
});

// update fees
const UpdateFees = TryCatch(async (req, res) => {
  const { id } = req.params;

  const existingClass = await Fee.findById(id);

  // If the class doesn't exist, return an error
  if (!existingClass) {
    return res.status(404).json({
      success: false,
      message: "Class not found",
    });
  }

  // Update data
  const updatedFee = await Fee.findByIdAndUpdate(
    id,
    { $set: req.body },
    { new: true }
  );
  res.status(200).json({
    success: true,
    message: "Fees updated successfully",
    updatedClass: updatedFee,
  });
});

// my school Fees
const MySchoolFees = TryCatch(async (req, res) => {
  const schoolId = req.user.schoolId;
  const searchQuery = {
    schoolId,
  };
  const existingClass = await Fee.findOne(searchQuery).populate({
    path: "schoolId",
    select: ["schoolname"],
  });

  const allData = {
    existingClass,
  };

  res.status(200).json({
    allData,
  });
});

// my fees for student
const MyFees = TryCatch(async (req, res) => {
  const schoolId = req.user.schoolId;
  const classId = req.user.classId;
  const userId = req.user.id
  const searchQuery = {
    schoolId,
    classId,
  };
  const user = await User.findById(userId)
  const TotalFees = user.totalFeeofStudent;
  const totalreminingfee = user.totalreminingfee;
  const install1 = user.feesinstall1;
  const install2 = user.feesinstall2;
  const install3 = user.feesinstall3;
  const totalpaidfee = user.totalpaidfee;



  const allData = {
    // user,
    TotalFees,
    totalpaidfee,
    install1,
    install2,
    install3,
    totalreminingfee,
    // install1,
    // install2,
    // install3,
    // remainingFees,
    // totalPaidFee,
  };

  res.status(200).json({
    allData,
  });
});

// delete fees

const DelteFess = TryCatch(async (req, res, next) => {
  const { id } = req.params;

  const fees = await Fee.findByIdAndRemove(id);

  if (!fees) {
    return res.status(404).json({ error: "Fees not found." });
  }

  res.json({ message: "Fees deleted successfully." });
});

module.exports = {
  AddFees,
  SeeAllFee,
  UpdateFees,
  GetFeesByClassName,
  MyFees,
  MySchoolFees,
  DelteFess,
};
