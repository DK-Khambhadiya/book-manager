const jwt = require("express-jwt");
const secret = process.env.JWT_SECRET;

const authenticate = jwt({
    secret: secret,
    credentialsRequired: false,
});
// console.log("authenticate:: ", authenticate)

module.exports = authenticate;