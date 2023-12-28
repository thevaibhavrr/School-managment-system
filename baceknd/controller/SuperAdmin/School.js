// Import required modules
const TryCatch = require("../../middleware/TryCatch");
const School = require("../../model/SuperAdmin/School");
const ErrorHandler = require("../../utils/errorHandel");
const User = require("../../model/User/User");
const checkPostBody = require("../../utils/QueryCheck");
const SchoolClass = require("../../model/SchoolClass/Schoolclass");
const Fee = require("../../model/admin/Fee");
const SchoolExame = require("../../model/ExamSchema/exammodel");
const cloudinary = require("cloudinary");
const getDataUri = require("../../utils/dataUri");
const nodemailer = require("nodemailer");
// Create school
const AddSchool2 = TryCatch(async (req, res) => {
  // Extract data from request body
  const {
    ownername,
    ownerimage,
    owneremail,
    ownerphonenumber,
    principalname,
    principalimage,
    principalemail,
    principalphonenumber,
    contectpersonname,
    contectpersonimage,
    contectpersonemail,
    contectpersonphonenumber,
    schoolname,
    schoollogo,
    schoolimage,
    schoolemail,
    city,
    address,
    schoolId,
    entrollmentYear,
    schooltype,
    bordtype,
    schoollevel,
    schoolwebsite,
    libraryavailability,
    sportfacility,
    transportservice,
    totalstudent,
    totalteacher,
  } = req.body;

  // Create a new school
  const newSchool = await School.create({
    ownername: ownername || "Ankur",
    ownerimage: ownerimage || [],
    owneremail: owneremail || "ankur@example.com",
    ownerphonenumber: ownerphonenumber || 1234567890,
    principalname: principalname || "jaya mittal",
    principalimage: principalimage || [],
    principalemail: principalemail || "ja@example.com",
    principalphonenumber: principalphonenumber || 9876543210,
    contectpersonname: contectpersonname || "vaibha",
    contectpersonimage: contectpersonimage || [],
    contectpersonemail: contectpersonemail || "vai@example.com",
    contectpersonphonenumber: contectpersonphonenumber || 8765432109,
    schoolname: schoolname || "ABC School",
    schoollogo: schoollogo || [],
    schoolimage: schoolimage || [],
    schoolemail: schoolemail || "abc@example.com",
    city: city || "City",
    address: address || "Address",
    entrollmentYear: entrollmentYear || 2022,
    schooltype: schooltype || "Public",
    bordtype: bordtype || "State",
    schoollevel: schoollevel || "Primary",
    schoolwebsite: schoolwebsite || "www.abcschool.com",
    libraryavailability: libraryavailability || true,
    sportfacility: sportfacility || true,
    transportservice: transportservice || true,
    totalstudent: totalstudent || 1000,
    totalteacher: totalteacher || 50,
  });

  res.json({ message: "School added successfully", school: newSchool });
});

// Add school and admin at the same time
const AddSchool = TryCatch(async (req, res, next) => {
  // Check required fields in the request body
  await checkPostBody(
    ["schoolname", "name", "email", "password", "schooladdress", "city"],
    req
  );
  if (req.file) {
    // file upload
    const file = req.file;
    const fileUri = getDataUri(file);
    // using cloudnary
    const mycloud = await cloudinary.v2.uploader.upload(fileUri.content);

    // Extract data from request body
    const {
      schoolname,
      email,
      name,
      password,
      schooladdress,
      city,
      mobilenumber,
    } = req.body;

    // Create a new school
    var school = await School.create({
      schoolname,
      schooladdress,
      city,
      schoolimage: {
        public_id: mycloud.public_id,
        url: mycloud.secure_url,
      },
    });
  }else{
    // file upload
    // using cloudnary

    // Extract data from request body
    const { schoolname, email, name, password, address, city, mobilenumber } =
      req.body;

    // Create a new school
    var school = await School.create({
      schoolname,
      address,
      city,
      schoolimage: {
        public_id: "aoasncmxslmrzek6uz0t",
        url: "https://res.cloudinary.com/dgtrp5bxo/image/upload/v1689076550/axiom9mkswfz1m2fuzx5.jpg",
      },
    }); 
  }
  

  const Admin = await User.create({
    ...req.body,
    role: "admin",
    schoolId: school._id,
  });

  // send email
  let testAccount = await nodemailer.createTestAccount();

  const transporter = nodemailer.createTransport({
    service: "gmail",
    port: 587,
    secure: false,
    auth: {
      user: "vaibhav.aurasoft@gmail.com",
      pass: "avjulakvbjgyfdmg",
    },
  });

  const info = await transporter.sendMail({
    from: '"vaibhav rathore" <isai.thompson93@ethereal.email>', // sender address
    to: `${Admin.email}`, // list of receivers
    subject: `Welcome to Aurasoft school management system `,
    text: "created account", // plain text body
    html: `<p>Dear School Administrator,</p>
    <p>We are delighted to welcome ${school.schoolname} to our Aurasoft school management system. .</p>
    <p>Here are your school credentials:</p>
    <ul>
      <li>Email: ${Admin.email}</li>
      <li>Password: ${req.body.password}</li>
    </ul>
    <p>We appreciate your trust in choosing our service. We are committed to providing you with the best possible support and assistance. If you have any questions or feedback, please do not hesitate to contact us at any time.</p>
 
    <p>Thank you for joining us, and we hope you enjoy using our school management system.</p>
    <p>Sincerely,</p>
    <p>Aurasoft School Management System Team</p>
    <img src="https://res.cloudinary.com/dgtrp5bxo/image/upload/v1689076432/aurasoftblack_lsevrd.png"/>
    `, // html body
  });

  res.json({ message: "Account created successfully", school, Admin });
});

// Get all schools with counts
const AllSchool = TryCatch(async (req, res, next) => {
  const query = req.query;
  const SchoolList = (await School.find(query)).reverse();

  const schoolsWithCounts = await Promise.all(
    SchoolList.map(async (school) => {
      // Total teacher count
      const totalTeacher = await User.countDocuments({
        schoolId: school._id,
        role: "teacher",
      });

      // Total student count
      const totalStudent = await User.countDocuments({
        schoolId: school._id,
        role: "student",
      });

      // Total admin count
      const totalAdmin = await User.countDocuments({
        schoolId: school._id,
        role: "admin",
      });

      // Total user count
      const totalUser = await User.countDocuments({
        schoolId: school._id,
      });

      return {
        ...school.toObject(),
        totalStudent,
        totalTeacher,
        totalAdmin,
        totalUser,
      };
    })
  );

  const totalSchool = schoolsWithCounts.length;
  const finalData = schoolsWithCounts.reverse();
  const totalUser = await User.countDocuments();
  const totalStudent = await User.countDocuments({ role: "student" });
  const totalTeacher = await User.countDocuments({ role: "teacher" });
  const totalAdmin = await User.countDocuments({ role: "admin" });
  const totalSuperAdmin = await User.find({
    role: "superAdmin",
  }).countDocuments();

  res.status(200).json({
    totalSchool,
    totalUser,
    totalSuperAdmin,
    totalAdmin,
    totalTeacher,
    totalStudent,
    SchoolList: finalData,
  });
});

// Get school details by ID
const SchoolDetails = TryCatch(async (req, res, next) => {
  const { schoolId } = req.params;
  if (!schoolId) {
    return new ErrorHandler("Please provide SchoolId", 400);
  }

  const schooldetails = await School.findById(schoolId);
  if (!schooldetails) {
    return new ErrorHandler("No School Available with this id", 400);
  }

  // Find exams for the school
  const exams = await SchoolExame.find({ schoolId });

  // Find total fees for the school
  const fees = await Fee.find({ schoolId });

  // Find total classes for the school
  const totalClass = await Fee.countDocuments({ schoolId });

  // Find total users for the school
  const totalTeacher = await User.countDocuments({
    schoolId: schooldetails._id,
    role: "teacher",
  });

  const totalStudent = await User.countDocuments({
    schoolId: schooldetails._id,
    role: "student",
  });

  const totalAdmin = await User.countDocuments({
    schoolId: schooldetails._id,
    role: "admin",
  });

  const totalUser = await User.countDocuments({
    schoolId: schooldetails._id,
  });

  const schoolWithCounts = {
    ...schooldetails.toObject(),
    totalStudent,
    totalTeacher,
    totalAdmin,
    totalUser,
    totalclass: totalClass,
    classes: fees,
    exams,
  };

  res.json({
    success: "School details fetched successfully",
    School: schoolWithCounts,
  });
});

// my school

// Get school details by ID
const MySchoolDetails = TryCatch(async (req, res, next) => {
  const schoolId = req.user.schoolId;

  const schooldetails = await School.findById(schoolId);

  // Find exams for the school
  const exams = await SchoolExame.find({ schoolId });

  // Find total fees for the school
  const fees = await Fee.find({ schoolId });

  // Find total classes for the school
  const totalClass = await Fee.countDocuments({ schoolId });

  // Find total users for the school
  const totalTeacher = await User.countDocuments({
    schoolId: schooldetails._id,
    role: "teacher",
  });

  const totalStudent = await User.countDocuments({
    schoolId: schooldetails._id,
    role: "student",
  });

  const totalAdmin = await User.countDocuments({
    schoolId: schooldetails._id,
    role: "admin",
  });

  const totalUser = await User.countDocuments({
    schoolId: schooldetails._id,
  });

  const schoolWithCounts = {
    ...schooldetails.toObject(),
    totalStudent,
    totalTeacher,
    totalAdmin,
    totalUser,
    totalclass: totalClass,
    classes: fees,
    exams,
  };

  res.json({
    success: "School details fetched successfully",
    School: schoolWithCounts,
  });
});

// Update school details
const UpdateSchoolDetails = TryCatch(async (req, res) => {
  const { schoolId } = req.params;
  if (!schoolId) {
    return new ErrorHandler("Please provide SchoolId", 400);
  }
  const school = await School.findById(schoolId);
  if (!school) {
    return new ErrorHandler("No School Available with this id", 400);
  }
    if (req.file) {
      // file upload
      const file = req.file;
      const fileUri = getDataUri(file);
      // using cloudnary
      const mycloud = await cloudinary.v2.uploader.upload(fileUri.content);

      // Create user
      var user = await User.create({
        ...req.body,
        schoolimage: {
          public_id: mycloud.public_id,
          url: mycloud.secure_url,
        },
      });
      // Update data
      var updatedSchool = await School.findByIdAndUpdate(
        schoolId,
        { $set: req.body },
        { new: true }
      );
    }else{
      
      // Update data
      const updatedSchool = await School.findByIdAndUpdate(
        schoolId,
        { $set: req.body },
        { new: true }
      );
    }

  res.json({
    success: "School details updated successfully",
    school: updatedSchool,
  });
});

// Delete school
const DeleteSchool = TryCatch(async (req, res, next) => {
  const { schoolId } = req.params;
  if (!schoolId) {
    return res.json({ error: "Please provide SchoolId" });
  }
  const school = await School.findByIdAndDelete(schoolId);
  if (!school) {
    return res.json({ error: "No School Available with this id" });
  }

  await User.deleteMany({ schoolId });
    // await User.findByIdAndDelete({ schoolId });


  res.json({ success: "School details deleted successfully", school });
});

module.exports = {
  AddSchool,
  AllSchool,
  SchoolDetails,
  UpdateSchoolDetails,
  DeleteSchool,
  MySchoolDetails,
};
