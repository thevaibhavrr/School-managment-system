// Import required modules
const SchoolClass = require("../../model/SchoolClass/Schoolclass");
const TryCatch = require("../../middleware/TryCatch");
const ErrorHandler = require("../../utils/errorHandel");

// Create a class
const AddClass = TryCatch(async (req, res, next) => {
  const classname = await SchoolClass.create(req.body);
  res
    .status(200)
    .json({
      success: true,
      classname,
      message: "School class created successfully",
    });
});

// Find class by ID
const ClassDetails = TryCatch(async (req, res, next) => {
  const { classId } = req.params;
  if (!classId) {
    return new ErrorHandler("Please provide classId", 400);
  }
  const classdetails = await SchoolClass.findById(classId);
  if (!classdetails) {
    return new ErrorHandler("No School available with this ID", 400);
  }
  res.status(200).json({ success: true, classdetails });
});

// Get all classes
const AllClass = TryCatch(async (req, res, next) => {
  const query = req.query;
  const allClasses = await SchoolClass.find(query);
  const totalClasses = allClasses.length;
  res.status(200).json({ success: true, allClasses, totalClasses });
});

// Delete class by ID
const DeleteClass = TryCatch(async (req, res, next) => {
  const { classId } = req.params;

  if (!classId) {
    return res.status(400).json({
      success: false,
      message: "Please provide classId",
    });
  }
  const deletedClass = await SchoolClass.findByIdAndRemove(classId);

  if (!deletedClass) {
    return res.status(404).json({
      success: false,
      message: "Class not found",
    });
  }

  res.status(200).json({
    success: true,
    message: "Class deleted successfully",
    deletedClass,
  });
});



// Export the modules
module.exports = {
  AddClass,
  AllClass,
  ClassDetails,
  DeleteClass,
};
