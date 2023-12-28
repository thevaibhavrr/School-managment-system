const TryCatch = require("../../middleware/TryCatch");
const ClassRoutine = require("../../model/SchoolClass/classroutin");

// Controller for creating a new class routine
const createClassRoutine = TryCatch(async (req, res) => {
  const { subject, classId, day, starttime, endtime } = req.body;
  const schoolId = req.user.schoolId;

  const newClassRoutine = await ClassRoutine.create({
    subject,
    schoolId,
    classId,
    day,
    starttime,
    endtime,
  });

  res.status(201).json(newClassRoutine);
});
// all classes routine
const getClassRoutinesBySchool = async (req, res) => {
  try {
    const { schoolId } = req.user.schoolId;
    const classRoutines = await ClassRoutine.find(schoolId)
      .populate("classId", "className")
      .exec();

    res.status(200).json(classRoutines);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// routine by class
const getClassRoutinesBySclassId = TryCatch(async (req, res) => {
  const { classId } = req.params;
  const schoolId = req.user.schoolId; // Corrected assignment

  const searchQuery = {
    classId,
    schoolId,
  };

  const classRoutines = await ClassRoutine.find(searchQuery);
  res.status(200).json(classRoutines);
});

// update routine
const updateClassRoutine1 = TryCatch(async (req, res) => {
  const { id } = req.params;
  const updatedClassRoutine = await ClassRoutine.findByIdAndUpdate(id, {
    $set: req.body,
  });
  res.status(200).json(updatedClassRoutine);
});
// Update routine
const updateClassRoutine = TryCatch(async (req, res) => {
  const { id } = req.params;

  const updatedClassRoutine = await ClassRoutine.findByIdAndUpdate(
    id,
    { $set: req.body },
    { new: true }
  );

  if (!updatedClassRoutine) {
    return res.status(404).json({ error: "Class routine not found" });
  }

  res.status(200).json(updatedClassRoutine);
});

// Controller for deleting a class routine
const deleteClassRoutine = TryCatch(async (req, res) => {
  const { id } = req.params;
  const updatedClassRoutine = await ClassRoutine.findByIdAndDelete(id);

  if (!updatedClassRoutine) {
    return res.status(404).json({ error: "Class routine not found" });
  }
  res.status(200).json({ message: "Class routine deleted successfully" });
});
// my routine
const MySchoolRoutine = TryCatch(async (req, res) => {
  const schoolId = req.user.schoolId;
   const classId = req.user.classId;
  const searchQuery = {
    schoolId,
    classId,
  };
  const myRoutine = await ClassRoutine.findOne(searchQuery).populate({
    path: "schoolId",
    select: ["schoolname"],
  });



  res.status(200).json({
    myRoutine,
  });
});

module.exports = {
  createClassRoutine,
  getClassRoutinesBySclassId,
  updateClassRoutine,
  deleteClassRoutine,
  getClassRoutinesBySchool,
  MySchoolRoutine,
};
