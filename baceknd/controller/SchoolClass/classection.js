const TryCatch = require("../../middleware/TryCatch");
const Section = require("../../model/SchoolClass/classection");

const createSection = TryCatch(async (req, res) => {
  const { classId, sectioname } = req.body;
  const schoolId = req.user.schoolId; // Assuming schoolId is obtained from the logged-in user

  const section = await Section.create({
    schoolId,
    classId,
    sectioname,
  });

  res.status(201).json({
    success: true,
    section, 
  });
});

// Get All Sections
const getSections = TryCatch(async (req, res) => {
  const schoolId = req.user.schoolId;

  const sections = await Section.find({ schoolId }).populate({
    path: "classId",
    select: ["className"],
  });
 
  res.status(200).json({
    success: true,
    sections,
  });
});

// Get Sections by Class ID
const getSectionsByClassId = TryCatch(async (req, res) => {
  const classId = req.params.id;
  const schoolId = req.user.schoolId; // Assuming schoolId is obtained from the logged-in user

  const sections = await Section.find({ classId, schoolId }).populate({
    path: "classId",
    select: ["className"],
  });
  const totalSection = sections.length;
  res.status(200).json({
    success: true,
    totalSection,
    sections,
  });
});

// Get Section by ID
const getSectionById = TryCatch(async (req, res) => {
  const sectionId = req.params.id;

  const section = await Section.findById(sectionId).populate({
    path: "classId",
    select: ["className"],
  });

  if (!section) {
    return res.status(404).json({
      success: false,
      error: "Section not found",
    });
  }

  res.status(200).json({
    success: true,
    section,
  });
});

// Update Section
const updateSection = TryCatch(async (req, res) => {
  const sectionId = req.params.id;
  const { sectioname } = req.body;

  const section = await Section.findById(sectionId);

  if (!section) {
    return res.status(404).json({
      success: false,
      error: "Section not found",
    });
  }

  section.sectioname = sectioname;

  const updatedSection = await section.save();

  res.status(200).json({
    success: true,
    section: updatedSection,
  });
});

// Delete Section
const deleteSection = TryCatch(async (req, res) => {
  const sectionId = req.params.id;

  const section = await Section.findByIdAndRemove(sectionId);

  if (!section) {
    return res.status(404).json({
      success: false,
      error: "Section not found",
    });
  }

  res.status(200).json({
    success: true,
    section,
    message: "Section deleted successfully",
  });
});

module.exports = {
  createSection,
  getSections,
  getSectionById,
  updateSection,
  deleteSection,
  getSectionsByClassId,
};
