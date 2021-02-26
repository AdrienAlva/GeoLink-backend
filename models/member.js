var mongoose = require('mongoose');

// module.exports allows us to pass this to other files when it is called
module.exports = mongoose.model('Member', {
	surname : {type : String, default: '' },
	name : {type : String, default: ''},
	lat : {type : Number, default: ''},
	lng : {type : Number, default: ''},
	thematics : {type : Array, default: ['','','','','']},
	status : {type : String, default: ''},
	contract : {type : String, default: ''},
	environment : {type : String, default: ''},
	former : {type : Boolean, default: false},
	email : {type : String, default: ''},
	emailToDisplay : {type : String, default: ''},
	site : {type : String, default: ''},
	password : {type : String, default: ''},
	about : {type : String, default: ''},
	avatar : {type : String, default: 'avatar-default.jpg'},
	isAdmin: {type : Boolean, default: false},
	isVerified : {type : Boolean, default: false},
	isRejected : {type : Boolean, default: false},
	hasSubmitedProfile : {type : Boolean, default: false},
	isOrganization: {type : Boolean, default: false},
	resetPasswordToken: {type: String, default: ''},
	resetPasswordExpires: {type: Number}
});

