// // This class provides API features for query manipulation

// class ApiFeatures {
//   constructor(query, queryStr) {
//     this.query = query; // Query to be executed
//     this.queryStr = queryStr; // Query parameters
//   }

//   // search() {
//   //   const { schoolname, role, name } = this.queryStr;

//   //   if (schoolname || role || name) {
//   //     const searchQuery = {};

//   //     if (schoolname) {
//   //       searchQuery.schoolname = {
//   //         $regex: schoolname,
//   //         $options: "i",
//   //       };
//   //     }

//   //     if (role) {
//   //       searchQuery.role = {
//   //         $regex: role,
//   //         $options: "i",
//   //       };
//   //     }

//   //     if (name) {
//   //       searchQuery.name = {
//   //         $regex: name,
//   //         $options: "i",
//   //       };
//   //     }

//   //     this.query = this.query.find(searchQuery);
//   //   }

//   //   return this;
//   // }

//   pagination(resultPerPage) {
//     const currentPage = parseInt(this.queryStr.page, 10) || 1;
//     const skip = resultPerPage * (currentPage - 1);

//     this.query = this.query.limit(resultPerPage).skip(skip);

//     return this;
//   }
// }

// module.exports = ApiFeatures;

class ApiFeatures {
  constructor(query, queryStr) {
    (this.query = query), (this.queryStr = queryStr);
  }

  //   search
  search() {
    const name = this.queryStr.name
      ? {
          name: {
            $regex: this.queryStr.name,
            $options: "i",
          },
        }
      : {};
    console.log(name);
    this.query = this.query.find({ ...name });
    return this;
  }
}
module.exports = ApiFeatures;
