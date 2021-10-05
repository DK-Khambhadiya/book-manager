const UserModel = require("../models/UserModel");
const AdminUserModel = require("../models/AdminUserModel");
const CompanyModel = require("../models/CompanyModel");
const { body, validationResult } = require("express-validator");
const { sanitizeBody } = require("express-validator");
//helper file to prepare responses.
const apiResponse = require("../helpers/apiResponse");
const utility = require("../helpers/utility");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mailer = require("../helpers/mailer");
const { constants } = require("../helpers/constants");

/**
 * User registration.
 *
 * @param {string}      firstName
 * @param {string}      lastName
 * @param {string}      email
 * @param {string}      password
 *
 * @returns {Object}
 */
exports.register = [
	// Validate fields.
	body("firstName")
		.isLength({ min: 1 })
		.trim()
		.withMessage("First name must be specified.")
		.isAlphanumeric()
		.withMessage("First name has non-alphanumeric characters."),
	body("lastName")
		.isLength({ min: 1 })
		.trim()
		.withMessage("Last name must be specified.")
		.isAlphanumeric()
		.withMessage("Last name has non-alphanumeric characters."),
	body("email")
		.isLength({ min: 1 })
		.trim()
		.withMessage("Email must be specified.")
		.isEmail()
		.withMessage("Email must be a valid email address.")
		.custom((value) => {
			return UserModel.findOne({ email: value }).then((user) => {
				if (user) {
					return Promise.reject("E-mail already in use");
				}
			});
		}),
	body("password")
		.isLength({ min: 6 })
		.trim()
		.withMessage("Password must be 6 characters or greater."),
	// Sanitize fields.
	sanitizeBody("firstName").escape(),
	sanitizeBody("lastName").escape(),
	sanitizeBody("email").escape(),
	sanitizeBody("password").escape(),
	// Process request after validation and sanitization.
	(req, res) => {
		try {
			// Extract the validation errors from a request.
			const errors = validationResult(req);
			if (!errors.isEmpty()) {
				// Display sanitized values/errors messages.
				return apiResponse.validationErrorWithData(
					res,
					"Validation Error.",
					errors.array(),
				);
			} else {
				//hash input password
				bcrypt.hash(req.body.password, 10, function (err, hash) {
					// generate OTP for confirmation
					let otp = utility.randomNumber(4);
					// Create User object with escaped and trimmed data
					var user = new UserModel({
						firstName: req.body.firstName,
						lastName: req.body.lastName,
						email: req.body.email,
						password: hash,
						confirmOTP: otp,
					});
					// Html email body
					let html =
						"<p>Please Confirm your Account.</p><p>OTP: " +
						otp +
						"</p>";
					// Send confirmation email
					mailer
						.send(
							constants.confirmEmails.from,
							req.body.email,
							"Confirm Account",
							html,
						)
						.then(function () {
							// Save user.
							user.save(function (err) {
								if (err) {
									return apiResponse.ErrorResponse(res, err);
								}
								let userData = {
									_id: user._id,
									firstName: user.firstName,
									lastName: user.lastName,
									email: user.email,
								};
								return apiResponse.successResponseWithData(
									res,
									"Registration Success.",
									userData,
								);
							});
						})
						.catch((err) => {
							console.log(err);
							return apiResponse.ErrorResponse(res, err);
						});
				});
			}
		} catch (err) {
			//throw error in json response with status 500.
			return apiResponse.ErrorResponse(res, err);
		}
	},
];

/**
 * User login.
 *
 * @param {string}      phone
 * @param {string}      email
 * @param {string}      city
 * @param {string}      branch_id
 * @param {string}      company_id
 * @param {string}      profile_pic
 * @param {string}      address_id
 * @param {string}      business_name
 *
 * @returns {Object}
 */
exports.login = [
	body("phone")
		.isLength({ min: 1 })
		.trim()
		.withMessage("Phone number must be specified."),
	body("unique_id")
		.isLength({ min: 1 })
		.trim()
		.withMessage("Company number must be specified."),
	sanitizeBody("phone").escape(),
	(req, res) => {
		try {
			const errors = validationResult(req);
			if (!errors.isEmpty()) {
				return apiResponse.validationErrorWithData(
					res,
					"Validation Error.",
					errors.array(),
				);
			} else {
				UserModel.findOne({ phone: req.body.phone }).then((user) => {
					if (user) {
						//Compare given password with db's hash.
						if (user.status == "active") {
							let userData = {
								_id: user._id,
								company_id: user.company_id
									? user.company_id
									: 0,
								phone: user.phone,
							};
							//Prepare JWT token for authentication
							const jwtPayload = userData;
							const jwtData = {
								expiresIn: process.env.JWT_TIMEOUT_DURATION,
							};
							const secret = process.env.JWT_SECRET;
							//Generated JWT token with Payload and secret.
							userData.token = jwt.sign(jwtPayload, secret);
							return apiResponse.successResponseWithData(
								res,
								"Login Success.",
								userData,
							);
						} else {
							return apiResponse.unauthorizedResponse(
								res,
								"Account is not active. Please contact admin.",
							);
						}
					} else {
						CompanyModel.findOne({ unique_id: req.body.unique_id })
							.then((company) => {
								console.log("company: ", company);
								if (company) {
									var user = new UserModel({
										phone: req.body.phone,
										status: "active",
										company_id: company._id,
									});
									user.save(function (err) {
										if (err) {
											return apiResponse.ErrorResponse(
												res,
												err,
											);
										}
										let userData = {
											_id: user._id,
											phone: user.phone,
											status: user.status,
										};
										const jwtPayload = userData;
										const jwtData = {
											expiresIn:
												process.env
													.JWT_TIMEOUT_DURATION,
										};
										const secret = process.env.JWT_SECRET;
										//Generated JWT token with Payload and secret.
										userData.token = jwt.sign(
											jwtPayload,
											secret,
										);
										return apiResponse.successResponseWithData(
											res,
											"Registration Success.",
											userData,
										);
									});
								} else {
									return apiResponse.ErrorResponse(
										res,
										"Company is not active. Please contact admin.",
									);
								}
							})
							.catch((error) => {
								console.log("error: ", error);
							});
					}
				});
			}
		} catch (err) {
			return apiResponse.ErrorResponse(res, err);
		}
	},
];

/**
 * Verify Confirm otp.
 *
 * @param {string}      email
 * @param {string}      otp
 *
 * @returns {Object}
 */
exports.verifyConfirm = [
	body("email")
		.isLength({ min: 1 })
		.trim()
		.withMessage("Email must be specified.")
		.isEmail()
		.withMessage("Email must be a valid email address."),
	body("otp")
		.isLength({ min: 1 })
		.trim()
		.withMessage("OTP must be specified."),
	sanitizeBody("email").escape(),
	sanitizeBody("otp").escape(),
	(req, res) => {
		try {
			const errors = validationResult(req);
			if (!errors.isEmpty()) {
				return apiResponse.validationErrorWithData(
					res,
					"Validation Error.",
					errors.array(),
				);
			} else {
				var query = { email: req.body.email };
				UserModel.findOne(query).then((user) => {
					if (user) {
						//Check already confirm or not.
						if (!user.isConfirmed) {
							//Check account confirmation.
							if (user.confirmOTP == req.body.otp) {
								//Update user as confirmed
								UserModel.findOneAndUpdate(query, {
									isConfirmed: 1,
									confirmOTP: null,
								}).catch((err) => {
									return apiResponse.ErrorResponse(res, err);
								});
								return apiResponse.successResponse(
									res,
									"Account confirmed success.",
								);
							} else {
								return apiResponse.unauthorizedResponse(
									res,
									"Otp does not match",
								);
							}
						} else {
							return apiResponse.unauthorizedResponse(
								res,
								"Account already confirmed.",
							);
						}
					} else {
						return apiResponse.unauthorizedResponse(
							res,
							"Specified email not found.",
						);
					}
				});
			}
		} catch (err) {
			return apiResponse.ErrorResponse(res, err);
		}
	},
];

/**
 * Resend Confirm otp.
 *
 * @param {string}      email
 *
 * @returns {Object}
 */
exports.resendConfirmOtp = [
	body("email")
		.isLength({ min: 1 })
		.trim()
		.withMessage("Email must be specified.")
		.isEmail()
		.withMessage("Email must be a valid email address."),
	sanitizeBody("email").escape(),
	(req, res) => {
		try {
			const errors = validationResult(req);
			if (!errors.isEmpty()) {
				return apiResponse.validationErrorWithData(
					res,
					"Validation Error.",
					errors.array(),
				);
			} else {
				var query = { email: req.body.email };
				UserModel.findOne(query).then((user) => {
					if (user) {
						//Check already confirm or not.
						if (!user.isConfirmed) {
							// Generate otp
							let otp = utility.randomNumber(4);
							// Html email body
							let html =
								"<p>Please Confirm your Account.</p><p>OTP: " +
								otp +
								"</p>";
							// Send confirmation email
							mailer
								.send(
									constants.confirmEmails.from,
									req.body.email,
									"Confirm Account",
									html,
								)
								.then(function () {
									user.isConfirmed = 0;
									user.confirmOTP = otp;
									// Save user.
									user.save(function (err) {
										if (err) {
											return apiResponse.ErrorResponse(
												res,
												err,
											);
										}
										return apiResponse.successResponse(
											res,
											"Confirm otp sent.",
										);
									});
								});
						} else {
							return apiResponse.unauthorizedResponse(
								res,
								"Account already confirmed.",
							);
						}
					} else {
						return apiResponse.unauthorizedResponse(
							res,
							"Specified email not found.",
						);
					}
				});
			}
		} catch (err) {
			return apiResponse.ErrorResponse(res, err);
		}
	},
];
