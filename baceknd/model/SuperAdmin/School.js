// sir s bat krna ki vikas ko SMS ka frontend dede ky

const mongoose = require("mongoose");
const validator = require("validator");

const RegisterSchool = new mongoose.Schema({
  // owner
  ownername: {
    type: String,
  },
  ownerimage: [
    {
      public_id: {
        type: String,
        // required: true,
      },
      url: {
        type: String,
        // required: true,
      },
    },
  ],
  // principal
  principalname: {
    type: String,
  },
 
  principalemail: {
    type: String,
    // required: [true, "Please enter Principal email id"],
  },
  principalphonenumber: {
    type: Number,
    minLength: 9,
    maxLength: 12,
  },

  // school contect team
  contectpersonname: {
    type: String,
  },
  contectpersonimage: [
    {
      public_id: {
        type: String,
        // required: true,
      },
      url: {
        type: String,
        // required: true,
      },
    },
  ],
  contectpersonemail: {
    type: String,
    // validate: [validator.isEmail, "Please enter a valid contect person email"],
  },
  contectpersonphonenumber: {
    type: Number,
    minLength: 9,
    maxLength: 12,
  },

  // School Details
  schoolname: {
    type: String,
    // required: [true, "Please enter School Name"],
  },
  schoollogo: [
    {
      public_id: {
        type: String,
      },
      url: {
        type: String,
      },
    },
  ],
  schoolimage: [
    {
      public_id: {
        type: String,
        // required: true,
      },
      url: {
        type: String, 
        // required: true,
      },
    },
  ],
  schoolemail: {
    type: String,
    // validate: [validator.isEmail, "Please enter a school valid email"],
    // required: [true, "Please enter contectperson email id"],
  },
  city: {
    type: String,
    // required: [true, "Please enter City Name"],
  },
  schooladdress: {
    type: String,
    // required: [true, "Please enter Address"],
  },
  schoolId: {
    type: Number,
    // required: [true, "Please enter School Id"],
  },
  entrollmentYear: {
    type: Number,
    // required: [true, "Please enter School Entrollment Year"],
  },
  schooltype: {
    type: String,
    // required: [true, "Please enter School Type"],
  },
  bordtype: {
    type: String,
    // required: [true, "Please enter bord Type"],
  },

  schoolwebsite: {
    type: String,
  },

  // School Facilities
  libraryavailability: {
    type: Boolean,
  },
  sportfacility: {
    type: Boolean,
  },
  transportservice: {
    type: Boolean,
  },

  // qunantity
  totalstudent: {
    type: Number,
  },
  totalteacher: {
    type: Number,
  },
});



module.exports =  mongoose.model("Schools",RegisterSchool)