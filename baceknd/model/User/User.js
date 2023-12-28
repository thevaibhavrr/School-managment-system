const mongoose = require("mongoose");
const validator = require("validator");
const jwt = require("jsonwebtoken");
const bcryptJS = require("bcrypt");
const Users = new mongoose.Schema({
  // everyone
  // Common fields
  name: {
    type: String,
    required: [true, "Please enter a name"],
  },
  email: {
    type: String,
    required: [true, "Please Email Id"],
    unique: true,
    validate: [validator.isEmail, "Please enter a valid email"],
  },
  password: {
    type: String,
    select: false,
  },
  role: {
    type: String,
    default: "student",
  },
  schoolId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "schools",
    // required: true
  },
  classId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "classes",
  },
  sectionId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "section",
  },
  profilepic: {
    type: String,
  },
  subject: {
    type: String,
  },
  paidFees: {
    type: Number,
  },
  feesinstall1: {
    type: Number,
    default: 0,
  },
  feesinstall2: {
    type: Number,
    default: 0,
  },
  feesinstall3: {
    type: Number,
    default: 0,
  },
  // testing
  userimage: {
    public_id: {
      type: String,
    },
    url: {
      type: String,
    },
  },
  image: {
    data: {
      type: String,
      // required: true,
    },
    contentType: {
      type: String,
      // required: true,
    },
  },
  classId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "class",
  },
  section: {
    type: String,
  },

  address: {
    type: String,
  },
  mobilenumber: {
    type: Number,
    maxLength: [12, "Number can not exceed 12 digits"],
    minLength: [10, "Number must be at least 10 digits"],
    // required: [true, "please enter mobile number"],
  },
  totalpaidfee: {
    type: Number,
    default: 0,
  },
  totalFeeofStudent: {
    type: Number,
    default: 0,
  },
  totalreminingfee: {
    type: Number,
    default: 0,
  },

  educationalBackground: {
    type: String,
  },
  businessRegistration: {
    type: String,
  },
  financialInformation: {
    type: String,
  },

  CreateByuser: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  age: {
    type: Number,
  },
  gender: {
    type: String,
  },
  previousSchools: {
    type: String,
  },
  // nationality: {
  //   type: String,
  //   default: "indian",
  // },

  // studentID: {
  //   type: String,
  //   unique: true,
  // },
  section: {
    type: Number,
  },
  mothername: {
    name: String,
  },
  fathername: {
    name: String,
  },
  medical: {
    deses: String,
  },
  // enrollmentDate: {
  //   type: Date,
  //   default: Date.now,
  // },
  // subjects: [
  //   {
  //     name: String,
  //   },
  // ],
  dateOfBirth: {
    type: Date,
  },
  lastclassmarks: {
    class: Number,
    type: String,
  },
  qualification: {
    type: String,
  },
  degrees: {
    type: String,
  },
  experience: {
    type: Number,
  },
  // joiningDate: {
  //   type: Date,
  //   default: Date.now,
  // },
  nativeLanguage: {
    type: String,
  },
  otherLanguages: {
    type: String,
  },
  institutions: {
    type: String,
  },
  certification: {
    type: String,
  },
  positions: {
    type: String,
  },
  skills: {
    type: String,
  },
  resume: {
    type: String,
  },
});

// password hashing
Users.pre("save", async function (next) {
  if (!this.isModified("password")) {
    next();
  }
  this.password = await bcryptJS.hash(this.password, 10);
});

//  JWT token
Users.methods.getJWTToken = function () {
  return jwt.sign({ id: this._id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRE,
  });
};

// compare password
Users.methods.comparePassword = async function (enterpassword) {
  return await bcryptJS.compare(enterpassword, this.password);
};

module.exports = mongoose.model("Users", Users);
