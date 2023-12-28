const express = require("express");
const router = express.Router();
const SchoolClass = require("../../controller/SchoolClass/schoollClass");

// add a new class
router.post("/addclass", SchoolClass.AddClass);

// get all classes
router.get("/allclass", SchoolClass.AllClass);

// get class details by class ID
router.get("/classdetails/:classId", SchoolClass.ClassDetails);

// delete a class by class ID
router.delete("/classdelete/:classId", SchoolClass.DeleteClass);

module.exports = router;
