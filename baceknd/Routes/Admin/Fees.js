const express = require("express");
const router = express.Router();
const auth = require("../../middleware/Auth");
const Data = require("../../controller/Admin/Fee");

// add fees
router.post(
  "/addfee",
  auth.isAuthenticateUser,
  auth.authorizeRole("admin"),
  Data.AddFees
);

// get all fees
router.get(
  "/allfees",
  auth.isAuthenticateUser,
  Data.SeeAllFee
);

// get fees by class ID
router.get(
  "/feesbyclassid/:id",
  auth.isAuthenticateUser,
  Data.GetFeesByClassName 
);

// delete fees by class ID
router.delete(
  "/deletefess/:id",
  auth.isAuthenticateUser,
  Data.DelteFess
);

// update fees
router.put(
  "/updatefee/:id",
  auth.isAuthenticateUser,
  auth.authorizeRole("admin"),
  Data.UpdateFees
);

// get my fees (for students) 
router.get(
  "/myfees",
  auth.isAuthenticateUser,
  Data.MyFees
);

// get my school fees (for admin and teacher)
router.get(
  "/myschoolfees",
  auth.isAuthenticateUser,
  auth.authorizeRole("admin", "teacher"),
  Data.MySchoolFees
);

module.exports = router;
