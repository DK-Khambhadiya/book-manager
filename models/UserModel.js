var mongoose = require("mongoose");

var Schema = mongoose.Schema;

var UserSchema = new mongoose.Schema({
	phone: { type: String, required: true },
	city: { type: String, required: false },
	email: { type: String, required: false },
	firebase_token: { type: String, required: false },
	branch_id: { type: Schema.ObjectId, required: false },
	company_id: { type: Schema.ObjectId, required: false },
	address_id: { type: Schema.ObjectId, required: false },
	profile_pic: { type: String, required: false, default: 0 },
	business_name: { type: String, required: false },
	full_name: { type: String, required: false },
	status: { type: String, required: false, default: 1 }
}, { timestamps: true, collection:'users' });

module.exports = mongoose.model("User", UserSchema);