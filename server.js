// modules =================================================
const express = require('express');
const request = require('request');
const cors = require('cors');
const mongoose = require('mongoose');
const multer  = require('multer'); // to parse form-data
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const expressJWT = require('express-jwt');
const helpers = require('./controllers/helpers');
const randomPassword = require ('generate-password');
const bcrypt = require('bcrypt');
const mailjet = require ('node-mailjet').connect('', '');// REQUIRED FOR PROD .connect(process.env.MJ_APIKEY_PUBLIC, process.env.MJ_APIKEY_PRIVATE)
const { body, validationResult } = require('express-validator');
const path = require('path');
const fs = require('fs');// "file-system" to manage files in directories
const crypto = require('crypto');

//==========================================================

const app = express();
const port = 80;

/*const upload = multer({ dest: 'uploads/' });*/ // defining upload's folder

app.use(cors());
app.options('*', cors());
app.use(express.json());
app.use(express.static(__dirname + '/dist/GeoLink'));
/*app.use('*', express.static(__dirname + '/dist/GeoLink'));*/
app.use(bodyParser.json({ extended: true }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use('/uploads', express.static('uploads'));

// MULTER SETTINGS 
const storage = multer.diskStorage({
    destination: function(req, file, cb) {
        cb(null, 'uploads/');
    },

    // By default, multer removes file extensions so let's add them back
    filename: function(req, file, cb) {
        cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
    }
});

//SECRET FOR JSON WEB TOKEN
let secret = 'some_secret'; //REQUIRE FOR PROD
const tokenSettings = { secret: secret, algorithms: ['HS256'] };

//ALLOW PATHS WITHOUT TOKEN AUTHENTICATION
/*app.use(expressJWT({ secret: secret, algorithms: ['HS256'] })// Voir quel algo choisir pour JWT
    .unless(
        { path: [
        	
        	'/user-account',
            '/login',
            '/recovery',
            '/reset-password',
            '/admin-login',
            '/register-account',
            '/verified-members',
            {url: /^\/uploads\/([^\/]*)$/} //regex pour autoriser tout les path apres /upload/  
        ]}
));*/

/* MONGO */

const db = require('./config/db'); // REQUIRED FOR PROD

const Member = require('./models/member');

console.log("connecting--",db);

mongoose.connect(db.url, { useNewUrlParser: true, useUnifiedTopology: true} ); //Mongoose connection created

/* FUNCTION */

function isAdmin(req, res, next) {
    // Check if the requesting user is marked as admin in database

    Member.findOne({email: req.user.email}).then(
    	result => {

    		if(result.isAdmin) {
		        next();
    		} else {
    			console.log('no admin');
    			res.json({ message: 'Vous n\'avez pas les privilèges administrateur...' }).status(401);
    		}
    	}
    );//Eo findOne   
}//Eo isAdmin()

/* SENDING DATA FROM DB TO PUBLIC FRONT */

app.get('/api/verified-members', function(req, res) { //route pour requêtes publiques.
	console.log('Requete sur membres vérifiés !');

	res.setHeader('Access-Control-Allow-Origin', 'http://localhost:4200'); // REQUIRED FOR PROD

	Member.find({ 'isVerified': true, 'isRejected': false })
        .select('name surname status lat lng thematics about email emailToDisplay isOrganization site avatar')
        .exec(function(err, members) {
        if (err){
        	console.log(err);
        	res.send(err);
    	}
    	res.json(members); 
	});
});//Eo GET /members

/* END */

app.get('/api/user-account', expressJWT(tokenSettings), function(req, res) { 

	console.log('Requete lors de la connexion');

	Member.find({ email: req.user.email })
        .select('name surname status lat lng thematics about email hasSubmitedProfile site')
        .exec(function(err, members) {
        if (err){
        	console.log(err);
        	res.send(err);
    	}
    	res.json(members); 
	});
});//Eo POST /user-account

app.get('/api/update-profile', expressJWT(tokenSettings),  function(req, res) { 
	console.log('Requete données page /update-profile ');

	Member.find({ email: req.user.email })
        .select('name surname status lat lng thematics about site')
        .exec(function(err, members) {
        if (err){
        	console.log(err);
        	res.send(err);
    	}
    	res.json(members); 
	});
});//Eo POST /update-profile

app.get('/api/members-validation', expressJWT(tokenSettings), isAdmin,   function(req, res) { //route pour requêtes de validation.
	console.log('Requete pour validation membres.');

	Member.find({ 'isVerified': false , 'isRejected': false })
        .select('name surname status lat lng thematics about email isVerified isOrganization site avatar') 
        .exec(function(err, members) {
        if (err){
        	console.log(err);
        	res.send(err);
    	}

    	res.json(members); 
	});
});//Eo GET /verified-members

app.get('/api/members-management', expressJWT(tokenSettings), isAdmin, function(req, res) { //route pour requêtes de validation.
	console.log('Requete sur liste de management.');

	Member.find({})
        .select('name surname status lat lng thematics about email isVerified isRejected isOrganization site avatar') 
        .exec(function(err, members) {
        if (err){
        	console.log(err);
        	res.send(err);
    	}
    	
    	res.json(members); 
	});
});//Eo GET /verified-members

/* ADMIN-LOGIN */

app.post('/api/admin-login',(req, res) => {
	console.log('requête sur POST Admin-Login')
	
	let password = req.body.password; 
		( async () => {
			try{
				let salt = await bcrypt.genSalt(10);
				let passwordToHash = await bcrypt.hash(password, salt);

				console.log(passwordToHash);
			}
			catch(error){
				console.log(error);
			}
	})()//Eo async

	Member.findOne({email: req.body.email}).then(
			result => {
				if(result){
					bcrypt.compare(password, result.password, function(err, response) {
						if (err){
					    	console.log(err);
						} else if (response){
							Member.findOne({email: req.body.email}).then(
						    	result => {
						    		if(result.isAdmin) {
						    			
										var payload = {"email": req.body.email};
					    				let token = jwt.sign(payload, secret, { expiresIn: '1800s'}, {algorithms: ['HS256']})
					    				res.status(200).json({"token": token});
	   					    		} else {
						    			console.log('else de isAdmin');
					    				res.json({ message: 'Vous n\'avez pas les privilèges administrateur.' }).status(401);
						    		}
						    	}
				    		);//Eo findOne 
						} else {
							console.log('Mauvais mot de passe...');
							res.json({ message: 'Le mot de passe renseigné n\'est pas valable...'}).status(401);
						}
					});//Eo bcrypt compare()
				} else {
					console.log('Cet utilisateur n\'existe pas...');
					res.json({ message: 'Cette utilisateur n\'existe pas...'}).status(401);
				}//Eo else
		}//Eo Arrow function
	);  
});//Eo POST /admin-login

app.get('/api/admin-login',(req, res) => {
	if(req.headers.authorization == 'Bearer null'){ // Cas où il n'y a pas de JWT.
		res.json({ value: 'false'});
	} else {

		const token = req.headers.authorization.split(' ')[1];

		const clearToken = jwt.verify(token, secret);
		console.log(req.headers)
		Member.findOne({email: clearToken.email}).then(
			result => {
				if(result.isAdmin){ // Si admin.
					console.log('ADMIN');
					res.json({ value: 'true'});
				} else {
					console.log('PAS ADMIN'); // Si user mais non-admin.
					res.json({ value: 'false'});
				}//Eo else
			}//Eo Arrow function
		);//Eo findOne
	}//Eo else	 
});//Eo GET /admin-login

/* LOGIN */

app.post('/api/login', (req, res) => {
	console.log('requête sur POST Login')
	let password = req.body.password; 
	( async () => {
		try{
			let salt = await bcrypt.genSalt(10);
			let passwordToHash = await bcrypt.hash(password, salt);

			console.log(passwordToHash);
		}

		catch(error){
			console.log(error);
		}
	})()

	Member.findOne({email: req.body.email}).then(
		result => {
			if(result){

				bcrypt.compare(password, result.password, function(err, response) {
					if (err){
				    	console.log(err);
					} else if (response){
						console.log('Connexion');
						var payload = {
	        				"email": req.body.email,
	    				}
	    				let token = jwt.sign(payload, secret, { expiresIn: '1800s'}, {algorithms: ['HS256']});
	    				res.status(200).json({"token": token});
					} else {
						console.log('Mauvais mot de passe...');
						res.json({ message: 'Le mot de passe renseigné n\'est pas valable...'}).status(401);
					}
				});

			} else {
				console.log('Cet utilisateur n\'existe pas...');
				res.json({ message: 'Cette utilisateur n\'existe pas...'}).status(401);
			}//Eo else
		}//Eo Arrow function
	);  
});//Eo POST /login

/* REGISTER ACCOUNT */

app.post('/api/register-account', [body('email').isEmail(), body('password').isLength({min: 8, max: 16})], (req, res) => {

	const errors = validationResult(req);
	if (!errors.isEmpty()) {
		return res.status(400).json({ errorMessage: 'Une erreur' });
	}

	let recaptchaVerify= false;

	request.post(
	    'https://www.google.com/recaptcha/api/siteverify',
	    {
	        form: {
	            secret: '6LdQscUZAAAAAK34YB3j8w3p6h-hTzCiBDJn8VbT',
	            response: req.body.recaptchaReactive
	        }
	    },
	    function (error, response, body) {
	        if (!error && response.statusCode == 200) {
	        	responseBody = body = JSON.parse(body);
	            if (responseBody.success) {	

					console.log('Requete POST sur /register-account')

					Member.findOne({ email: req.body.email}).then((result) => {
						if(result){ // email déja pris
							console.log('Adresse déjà utilisée...');
							res.json({ message: 'L\'adresse renseignée correspond à un membre existant.'}).status(401);
							
						} else { //

							let password = req.body.password;
							let passwordConfirm = req.body.passwordConfirm;

							if(password != passwordConfirm){
								console.log('Mdp et confirmation non-similaire...');
								res.json({ message: 'Le mot de passe et la confirmation du mot de passe ne correspondent pas.'}).status(401);
							} else {

								console.log('Création d\'un token');
								var payload = {
				    				"email": req.body.email,
								}

								let token = jwt.sign(payload, secret, { expiresIn: '3600s'}, {algorithms: ['HS256']})
								res.status(200).json({"token": token});


								( async () => {
									try{
										let salt = await bcrypt.genSalt(10);
										let passwordToHash = await bcrypt.hash(password, salt);

										newMember = Member({
											email: req.body.email,
											password: passwordToHash
										});

										newMember.save();
									}

									catch(error){
										console.log(error);
									}
								})()

							}//Eo else
						}//Eo else
					});//Eo Member.findOne()	
            	} else {
                	res.json({ message: 'Une erreur s\'est produite lors de la confirmation du recaptcha.'}).status(401);
            	}
	        }
	    } 
    );//Eo request POST sur api de vérication recaptcha   
});//Eo POST /register-account

/* ACCOUNT USER ACTIONS */

app.post('/api/register-profile', expressJWT(tokenSettings),  (req, res) => {
	console.log('Requete POST sur /register-profile');
	
	memberToAdd = new Member({
		surname: req.body.surname,
		name: req.body.name,
		status: req.body.status,
		lat: req.body.lat,
		lng: req.body.lng,
		thematics: [req.body.thematic1, req.body.thematic2, req.body.thematic3, req.body.thematic4, req.body.thematic5],
		about: req.body.about,
		site: req.body.site,
		emailToDisplay: req.body.emailToDisplay,
		former: req.body.former
	});

	console.log(memberToAdd)

	if(memberToAdd.surname != ''){Member.updateOne({ email: req.user.email}, 
		{ $set: {surname: memberToAdd.surname}}).then()}

	if(memberToAdd.name != ''){Member.updateOne({ email: req.user.email}, 
		{ $set: {name: memberToAdd.name}}).then()}

	if(memberToAdd.status != ''){Member.updateOne({ email: req.user.email}, 
		{ $set: {status: memberToAdd.status}}).then()}

	if(memberToAdd.lat != null){Member.updateOne({ email: req.user.email}, 
		{ $set: {lat: memberToAdd.lat}}).then()}

	if(memberToAdd.lng != null){Member.updateOne({ email: req.user.email}, 
		{ $set: {lng: memberToAdd.lng}}).then()}

	if(memberToAdd.thematics[0] != ''){Member.updateOne({ email: req.user.email}, 
		{ $set: {'thematics.0': memberToAdd.thematics[0]}}).then()}

	if(memberToAdd.thematics[1] != ''){Member.updateOne({ email: req.user.email}, 
		{ $set: {'thematics.1': memberToAdd.thematics[1]}}).then()}

	if(memberToAdd.thematics[2] != ''){Member.updateOne({ email: req.user.email}, 
		{ $set: {'thematics.2': memberToAdd.thematics[2]}}).then()}

	if(memberToAdd.thematics[3] != ''){Member.updateOne({ email: req.user.email}, 
		{ $set: {'thematics.3': memberToAdd.thematics[3]}}).then()}

	if(memberToAdd.thematics[4] != ''){Member.updateOne({ email: req.user.email}, 
		{ $set: {'thematics.4': memberToAdd.thematics[4]}}).then()}

	if(memberToAdd.about != ''){Member.updateOne({ email: req.user.email}, 
		{ $set: {about: memberToAdd.about}}).then()}

	if(memberToAdd.emailToDisplay == ''){
		Member.updateOne({ email: req.user.email}, 
		{ $set: {emailToDisplay: req.user.email}}).then()
	} else {
		Member.updateOne({ email: req.user.email}, 
		{ $set: {emailToDisplay: memberToAdd.emailToDisplay}}).then()
	}//si pas d'email particulier a afficher on utilise celui de creation du compte.

	if(memberToAdd.site != ''){Member.updateOne({ email: req.user.email}, 
		{ $set: {site: memberToAdd.site}}).then()}

	if(memberToAdd.former == true){
		console.log('true de former');
		Member.updateOne({ email: req.user.email}, { $set: {former: true}}).then();
	} else if (memberToAdd.former == false){
		console.log('false de former');
		Member.updateOne({ email: req.user.email}, { $set: {former: false}}).then();
	}//Eo else if

	Member.updateOne({ email: req.user.email},{ $set: { hasSubmitedProfile: true }}, (e,s)=>{});

	const request = mailjet
						.post("send", {'version': 'v3.1'})
						.request({
						  "Messages":[
						    {
						      "From": {
						        "Email": "adrien.alvarez.vanhard@gmail.com",
						        "Name": "Association GéoLink"
						      },
						      "To": [
						        {
						          "Email": "jamespatageules@gmail.com",
						          "Name": ""
						        }
						      ],
						      "Subject": "Nouvelle demande pour rejoindre l'annuaire GéoLink ! ",
						      "TextPart": "",
						      "HTMLPart": '<h2>Nouvelle demande !</h2><b>L\'utilisateur : ' + req.user.email + ' souhaite rejoindre l\'annuaire GéoLinK.</b><br><a href=\"http://localhost:4200/admin-login\">Se connecter au panneau d\'administration</a>',
						      "CustomID": "Member-asking-to-join"
						    }
						  ]
						});

						request
						  .then((result) => {
						    console.log(result.body)
						  })
						  .catch((err) => {
						    console.log(err.statusCode)
						  });
	res.end();				
});//Eo POST /register-profile

app.post('/api/register-profile-organization', expressJWT(tokenSettings),  (req, res) => {
	console.log('Requete POST sur /register-profile');
	
	memberToAdd = new Member({
		surname: req.body.surname,
		name: req.body.name,
		status: req.body.status,
		lat: req.body.lat,
		lng: req.body.lng,
		thematics: [req.body.thematic1, req.body.thematic2, req.body.thematic3, req.body.thematic4, req.body.thematic5],
		about: req.body.about,
		emailToDisplay: req.body.emailToDisplay,
		site: req.body.site
	});

	if(memberToAdd.surname != ''){Member.updateOne({ email: req.user.email}, 
		{ $set: {surname: memberToAdd.surname}}).then()}

	if(memberToAdd.name != ''){Member.updateOne({ email: req.user.email}, 
		{ $set: {name: memberToAdd.name}}).then()}

	if(memberToAdd.status != ''){Member.updateOne({ email: req.user.email}, 
		{ $set: {status: memberToAdd.status}}).then()}

	if(memberToAdd.lat != null){Member.updateOne({ email: req.user.email}, 
		{ $set: {lat: memberToAdd.lat}}).then()}

	if(memberToAdd.lng != null){Member.updateOne({ email: req.user.email}, 
		{ $set: {lng: memberToAdd.lng}}).then()}

	if(memberToAdd.thematics[0] != ''){Member.updateOne({ email: req.user.email}, 
		{ $set: {'thematics.0': memberToAdd.thematics[0]}}).then()}

	if(memberToAdd.thematics[1] != ''){Member.updateOne({ email: req.user.email}, 
		{ $set: {'thematics.1': memberToAdd.thematics[1]}}).then()}

	if(memberToAdd.thematics[2] != ''){Member.updateOne({ email: req.user.email}, 
		{ $set: {'thematics.2': memberToAdd.thematics[2]}}).then()}

	if(memberToAdd.thematics[3] != ''){Member.updateOne({ email: req.user.email}, 
		{ $set: {'thematics.3': memberToAdd.thematics[3]}}).then()}

	if(memberToAdd.thematics[4] != ''){Member.updateOne({ email: req.user.email}, 
		{ $set: {'thematics.4': memberToAdd.thematics[4]}}).then()}

	if(memberToAdd.about != ''){Member.updateOne({ email: req.user.email}, 
		{ $set: {about: memberToAdd.about}}).then()}

	if(memberToAdd.emailToDisplay == ''){
		Member.updateOne({ email: req.user.email}, 
		{ $set: {emailToDisplay: req.user.email}}).then()
	} else {
		Member.updateOne({ email: req.user.email}, 
		{ $set: {emailToDisplay: memberToAdd.emailToDisplay}}).then()
	}//si pas d'email particulier a afficher on utilise celui de creation du compte.

	if(memberToAdd.site != ''){Member.updateOne({ email: req.user.email}, 
		{ $set: {site: memberToAdd.site}}).then()}

	Member.updateOne({ email: req.user.email},{ $set: { hasSubmitedProfile: true }}, (e,s)=>{});

	Member.updateOne({ email: req.user.email},{ $set: { isOrganization: true }}, (e,s)=>{});

	const request = mailjet
						.post("send", {'version': 'v3.1'})
						.request({
						  "Messages":[
						    {
						      "From": {
						        "Email": "adrien.alvarez.vanhard@gmail.com",
						        "Name": "Association GéoLink"
						      },
						      "To": [
						        {
						          "Email": "jamespatageules@gmail.com",
						          "Name": ""
						        }
						      ],
						      "Subject": "Nouvelle demande pour rejoindre l'annuaire GéoLink ! ",
						      "TextPart": "",
						      "HTMLPart": '<h2>Nouvelle demande !</h2><b>L\'utilisateur : ' + req.user.email + ' souhaite rejoindre l\'annuaire GéoLinK.</b><br><a href=\"http://localhost:4200/admin-login\">Se connecter au panneau d\'administration</a>',
						      "CustomID": "Member-asking-to-join"
						    }
						  ]
						});

						request
						  .then((result) => {
						    console.log(result.body)
						  })
						  .catch((err) => {
						    console.log(err.statusCode)
						  });
	res.end();				
});//Eo POST /register-profile-organization

app.post('/api/update-profile', expressJWT(tokenSettings),  (req, res) => {

	updatedMember = Member({
		name: req.body.name,
		surname: req.body.surname,
		status: req.body.status,
		about: req.body.about,
		lat: req.body.lat,
		lng: req.body.lng,
		thematics: [req.body.thematic1, req.body.thematic2, req.body.thematic3, req.body.thematic4, req.body.thematic5],
		site: req.body.site
	});

	if(updatedMember.surname != ''){Member.updateOne({ email: req.user.email}, 
							{ $set: {surname: updatedMember.surname}}).then()}

	if(updatedMember.name != ''){Member.updateOne({ email: req.user.email}, 
		{ $set: {name: updatedMember.name}}).then()}

	if(updatedMember.status != ''){Member.updateOne({ email: req.user.email}, 
		{ $set: {status: updatedMember.status}}).then()}

	if(updatedMember.lat != null){Member.updateOne({ email: req.user.email}, 
		{ $set: {lat: updatedMember.lat}}).then()}

	if(updatedMember.lng != null){Member.updateOne({ email: req.user.email}, 
		{ $set: {lng: updatedMember.lng}}).then()}

	if(updatedMember.thematics[0] != ''){Member.updateOne({ email: req.user.email}, 
		{ $set: {'thematics.0': updatedMember.thematics[0]}}).then()}

	if(updatedMember.thematics[1] != ''){Member.updateOne({ email: req.user.email}, 
		{ $set: {'thematics.1': updatedMember.thematics[1]}}).then()}

	if(updatedMember.thematics[2] != ''){Member.updateOne({ email: req.user.email}, 
		{ $set: {'thematics.2': updatedMember.thematics[2]}}).then()}

	if(updatedMember.thematics[3] != ''){Member.updateOne({ email: req.user.email}, 
		{ $set: {'thematics.3': updatedMember.thematics[3]}}).then()}

	if(updatedMember.thematics[4] != ''){Member.updateOne({ email: req.user.email}, 
		{ $set: {'thematics.4': updatedMember.thematics[4]}}).then()}

	if(updatedMember.about != ''){Member.updateOne({ email: req.user.email}, 
		{ $set: {about: updatedMember.about}}).then()}	

	if(updatedMember.site != ''){Member.updateOne({ email: req.user.email}, 
		{ $set: {site: updatedMember.site}}).then()}		

	res.json({ message: 'Modifications enregistrées !'});

});//Eo POST /update-profile

app.post('/api/update-password', expressJWT(tokenSettings), [body('password').isLength({min:8, max:16})], (req, res) => {
	console.log('requête sur POST update-password')

	const errors = validationResult(req); //validator
	if (!errors.isEmpty()) {
		return res.status(400).json({ message: errors.array() });
	}

	Member.findOne({email: req.user.email}).then(
		result => {
			if(result){
				bcrypt.compare(req.body.oldPassword, result.password, function(err, response) {
					if (err){
				    	console.log(err);
				    	res.end();
					} else if (response){
						if(req.body.password != req.body.passwordConfirm){
							res.json({ message: 'Le mot de passe et la confirmation du mot de passe ne correspondent pas.'}).status(401);
						} else {
							( async () => {
								try{
									let salt = await bcrypt.genSalt(10);
									let passwordToHash = await bcrypt.hash(req.body.password, salt);

									Member.updateOne({ email: req.user.email}, 
										{ $set: {
											password : passwordToHash,
										}
									}).then()

									res.json({successMessage: 'Mot de passe modifié avec succès !'})
								}//Eo try	

								catch(error){
									console.log(error);
								}//Eo catch
							})()//Eo async
						}//Eo else
					} else {
						console.log('Mauvais mot de passe...');
						res.json({ message: 'Le mot de passe actuel n\'est pas correct'}).status(401);
					}
				});//Eo bcrypt compare

			} else {
				console.log('Cet utilisateur n\'existe pas...');
				res.json({ message: 'Cette utilisateur n\'existe pas...'}).status(401);
			}//Eo else
		}//Eo Arrow function
	);  
});//Eo POST /update-password

/* MEMBER VALIDATION */

app.post('/api/validation', expressJWT(tokenSettings), isAdmin, (req, res) => {

	console.log(req.body);

	verifiedMember = Member({
		name: req.body.name,
		surname: req.body.surname,
		status: req.body.status,
		about: req.body.about,
		lat: req.body.lat,
		lng: req.body.lng,
		thematics: [req.body.thematic1, req.body.thematic2, req.body.thematic3, req.body.thematic4, req.body.thematic5],
		email: req.body.email,
		isOrganization: req.body.isOrganization,
		site: req.body.site
	});

	if(verifiedMember.surname != ''){Member.updateOne({ email: verifiedMember.email}, 
							{ $set: {surname: verifiedMember.surname}}).then()}

	if(verifiedMember.name != ''){Member.updateOne({ email: verifiedMember.email}, 
		{ $set: {name: verifiedMember.name}}).then()}

	if(verifiedMember.status != ''){Member.updateOne({ email: verifiedMember.email}, 
		{ $set: {status: verifiedMember.status}}).then()}

	if(verifiedMember.lat != null){Member.updateOne({ email: verifiedMember.email}, 
		{ $set: {lat: verifiedMember.lat}}).then()}

	if(verifiedMember.lng != null){Member.updateOne({ email: verifiedMember.email}, 
		{ $set: {lng: verifiedMember.lng}}).then()}

	if(verifiedMember.thematics[0] != ''){Member.updateOne({ email: verifiedMember.email}, 
		{ $set: {'thematics.0': verifiedMember.thematics[0]}}).then()}

	if(verifiedMember.thematics[1] != ''){Member.updateOne({ email: verifiedMember.email}, 
		{ $set: {'thematics.1': verifiedMember.thematics[1]}}).then()}

	if(verifiedMember.thematics[2] != ''){Member.updateOne({ email: verifiedMember.email}, 
		{ $set: {'thematics.2': verifiedMember.thematics[2]}}).then()}

	if(verifiedMember.thematics[3] != ''){Member.updateOne({ email: verifiedMember.email}, 
		{ $set: {'thematics.3': verifiedMember.thematics[3]}}).then()}

	if(verifiedMember.thematics[4] != ''){Member.updateOne({ email: verifiedMember.email}, 
		{ $set: {'thematics.4': verifiedMember.thematics[4]}}).then()}

	if(verifiedMember.about != ''){Member.updateOne({ email: verifiedMember.email}, 
		{ $set: {about: verifiedMember.about}}).then()}

	if(verifiedMember.site != ''){Member.updateOne({ email: verifiedMember.email}, 
		{ $set: {site: verifiedMember.site}}).then()}

	if(verifiedMember.isOrganization != null){Member.updateOne({ email: req.body.email},
		{ $set: { isOrganization: verifiedMember.isOrganization }}, (e,s)=>{}).then();}

	Member.updateOne({ email: req.body.email},{ $set: { isVerified: true }}, (e,s)=>{});					

	res.json({ message: 'Fin de la requête de validation'})

});//Eo POST /validation

app.post('/api/refused',  expressJWT(tokenSettings), isAdmin, (req, res) => {

	console.log(req.body);

	Member.updateOne({ email: req.body.email},{ $set: { isRejected: true }}, (e,s)=>{if(e)console.log(e);});

	Member.updateOne({ email: req.body.email},{ $set: { isVerified: true }}, (e,s)=>{if(e)console.log(e);});
										
	res.json({ message: 'Fin de la requête de refus'});

});//Eo POST /refused

/* MEMBER MANAGEMENT*/

app.post('/api/update', expressJWT(tokenSettings), isAdmin, (req, res) => {

	console.log(req.body);

	updatedMember = Member({
		name: req.body.name,
		surname: req.body.surname,
		status: req.body.status,
		about: req.body.about,
		lat: req.body.lat,
		lng: req.body.lng,
		thematics: [req.body.thematic1, req.body.thematic2, req.body.thematic3, req.body.thematic4, req.body.thematic5],
		email: req.body.email,
		isVerified: req.body.isVerified,
		isRejected: req.body.isRejected,
		isOrganization: req.body.isOrganization,
		site: req.body.site
	});

	if(updatedMember.surname != ''){Member.updateOne({ email: updatedMember.email}, 
							{ $set: {surname: updatedMember.surname}}).then()}

	if(updatedMember.name != ''){Member.updateOne({ email: updatedMember.email}, 
		{ $set: {name: updatedMember.name}}).then()}

	if(updatedMember.status != ''){Member.updateOne({ email: updatedMember.email}, 
		{ $set: {status: updatedMember.status}}).then()}

	if(updatedMember.lat != null){Member.updateOne({ email: updatedMember.email}, 
		{ $set: {lat: updatedMember.lat}}).then()}

	if(updatedMember.lng != null){Member.updateOne({ email: updatedMember.email}, 
		{ $set: {lng: updatedMember.lng}}).then()}

	if(updatedMember.thematics[0] != ''){Member.updateOne({ email: updatedMember.email}, 
		{ $set: {'thematics.0': updatedMember.thematics[0]}}).then()}

	if(updatedMember.thematics[1] != ''){Member.updateOne({ email: updatedMember.email}, 
		{ $set: {'thematics.1': updatedMember.thematics[1]}}).then()}

	if(updatedMember.thematics[2] != ''){Member.updateOne({ email: updatedMember.email}, 
		{ $set: {'thematics.2': updatedMember.thematics[2]}}).then()}

	if(updatedMember.thematics[3] != ''){Member.updateOne({ email: updatedMember.email}, 
		{ $set: {'thematics.3': updatedMember.thematics[3]}}).then()}

	if(updatedMember.thematics[4] != ''){Member.updateOne({ email: updatedMember.email}, 
		{ $set: {'thematics.4': updatedMember.thematics[4]}}).then()}

	if(updatedMember.about != ''){Member.updateOne({ email: updatedMember.email}, 
		{ $set: {about: updatedMember.about}}).then()}

	if(updatedMember.site != ''){Member.updateOne({ email: updatedMember.email}, 
		{ $set: {site: updatedMember.site}}).then()}

	if(updatedMember.isOrganization != null){Member.updateOne({ email: req.body.email},
		{ $set: { isOrganization: updatedMember.isOrganization }}, (e,s)=>{}).then();}

	Member.updateOne({ email: updatedMember.email},{ $set: { isVerified: updatedMember.isVerified }}, (e,s)=>{});

	Member.updateOne({ email: updatedMember.email},{ $set: { isRejected: updatedMember.isRejected }}, (e,s)=>{});

	res.json({ message: 'Fin de la requête de modification.'})

});//Eo POST /update

app.post('/api/delete', expressJWT(tokenSettings), isAdmin, (req, res) => {

	Member.deleteOne({ email: req.body.email}, function (err) {
	  if (err) return handleError(err);
	});

    const pathToFile = 'uploads/' + req.body.avatar;
    
    if(pathToFile != 'uploads/avatar-default.jpg') {
		console.log("Removing : " + pathToFile);
		fs.unlink(pathToFile, function(err) {
		  	if (err) {
		    	throw err
		  	} else {
		    	console.log("Successfully deleted the file.")
		  	}
		})
	}//Eo if

	res.json({ message: 'Fin de la requête de suppression'});

});//Eo POST /delete

/* PASSWORD RECOVERY */

app.post('/api/recovery', (req, res) => {

	const errors = validationResult(req);
	if (!errors.isEmpty()) {
		return res.status(400).json({ message: errors.array() });
	}

	let recaptchaVerify= false;

	request.post(
	    'https://www.google.com/recaptcha/api/siteverify',
	    {
	        form: {
	            secret: '', // REQUIRED FOR PROD
	            response: req.body.recaptchaReactive
	        }
	    },
	    function (error, response, body) {
	        if (!error && response.statusCode == 200) {
	        	responseBody = body = JSON.parse(body);
	            if (responseBody.success) {	

					Member.findOne({email: req.body.email}).then(
						result => {
							if(result){
								console.log(result);
								(async () => { 
									try {

										/* Génération du token */

										const token = crypto.randomBytes(20).toString('hex');

										console.log(token);

										Member.updateOne({email: req.body.email},{
											resetPasswordToken: token,
											resetPasswordExpires: Date.now() + 180000
										}).then();

										/* Envoi de l'email*/

										let email = result.email;

										console.log(email);

										
										const request = mailjet
										.post("send", {'version': 'v3.1'})
										.request({
										  "Messages":[
										    {
										      "From": {
										        "Email": "", // REQUIRED FOR PROD
										        "Name": "Asso"
										      },
										      "To": [
										        {
										          "Email": email,
										          "Name": ""
										        }
										      ],
										      "Subject": "Demande de renouvellement du mot de passe de votre compte GéoLink",
										      "TextPart": "",
										      "HTMLPart": "<p>Pour renouveller votre mot de passe rendez-vous sur la page suivante : </p><a href='http://localhost:4200/recovery/" + token + "'>Changer mon mot de passe</a>",
										      "CustomID": "password-recovery"
										    }
										  ]
										});

										request
										  .then((result) => {
										    console.log(result.body)
										  })
										  .catch((err) => {
										    console.log(err.statusCode)
										  });

										  res.json({successMessage: 'Demande de modification de mot de passe envoyée avec succès. Veuillez consulter votre boîte mail.'});

									}//EO try

									catch(error) {
										console.log("Erreur dans update password" + error);
									}
								})()//EO async

							} else {
								res.json({ errorMessage: 'Il n\'y a pas de compte utilisateur associé à cette adresse email.'}).status(401);
							}//Eo else
						}//Eo Arrow function
					);//Eo Member.findOne()
            	} else {
                	res.json({ errorMessage: 'Une erreur s\'est produite lors de la confirmation du recaptcha.'}).status(401);
            	}
	        }
	    } 
    );//Eo request POST sur api de vérication recaptcha 
});//Eo POST /recovery

app.post('/api/reset-password', [body('password').isLength({min:8, max:16})], (req, res) => {

	console.log('Requête sur POST /reset-password');
	console.log(req.body);
	console.log(Date.now());

	const errors = validationResult(req); //validator
	if (!errors.isEmpty()) {
		return res.json({ errorMessage: 'Le mot de passe ne respecte pas le format requis', resetting: true }).status(400);
	}

	Member.findOne({
			resetPasswordToken: req.body.token,
			resetPasswordExpires: {
				$gt: Date.now(), //$gt = 'greater than'
			},
		
	}).then(
		result => {
			if (result) {
				console.log('>>> password resetting');

				if(req.body.password != req.body.passwordConfirm){
					res.json({ errorMessage: 'Le mot de passe et la confirmation du mot de passe ne correspondent pas.', resetting: true}).status(401);
				} else {	

					(async () => { //async obligatoire pour le salt
						try {	
								
							let salt = await bcrypt.genSalt(10);
							let passwordToHash = await bcrypt.hash(req.body.password, salt);

							Member.updateOne({ resetPasswordToken: req.body.token}, 
								{ $set: {
									password : passwordToHash,
								}
							}).then()

							res.json({successMessage: 'Mot de passe modifié avec succès.', resetting: false}).status(200);

						}//EO try

						catch(error) {
						console.log("Erreur dans update password" + error);
						}
					})()//EO async
								
				}//Eo if / else
				
			} else {
				console.log('>>> not allowed to reset password');
				res.json({errorMessage: 'Vous n\'êtes pas autorisé à mener cette action.', resetting: true }).status(401);
			}
		}//Eo arrow function
	);
});//Eo POST /reset-password

app.post('/api/upload-avatar', expressJWT(tokenSettings), (req, res) => {

	console.log('Requête sur /upload-avatar');

    let upload = multer({ storage: storage, fileFilter: helpers.imageFilter, limits: { fileSize: 1572864 } }).single('avatar');

    upload(req, res, function(err) {
        // req.file contains information of uploaded file
        // req.body contains information of text fields, if there were any

        if (req.fileValidationError) {
        	console.log('Erreur validation avatar');
        	console.log(req.fileValidationError);
            return res.send(req.fileValidationError);
        }
        else if (!req.file) {
            return res.send('Please select an image to upload');
        }
        else if (err instanceof multer.MulterError) {
        	console.log(err)
            return res.send(err);
        }
        else if (err) {
        	console.log('else if err')
            return res.send(err);
        }

        Member.findOne({email: req.user.email}).then(data => {
        	let avatarToDelete = data.avatar;
        	console.log(avatarToDelete);

	        const pathToFile = 'uploads/' + avatarToDelete;

		    if(pathToFile != 'uploads/avatar-default.jpg') {
		    	console.log("Removing : " + pathToFile);
				fs.unlink(pathToFile, function(err) {
				  	if (err) {
				    	throw err
				  	} else {
				    	console.log("Successfully deleted the file.")
				  	}
				})
			}//Eo if

        });

        Member.updateOne({ email: req.user.email}, { $set: {avatar: req.file.filename}}).then();
        // Display uploaded image for user validation
        res.json({ message: 'Modification enregistrée !'});
    });
});//Eo POST /upload-avatar

app.post('/api/delete-avatar', expressJWT(tokenSettings), (req, res) => {

	console.log('Requête sur /delete-avatar');

    Member.updateOne({ email: req.body.email}, { $set: {avatar: 'avatar-default.jpg'}}).then();

    const pathToFile = 'uploads/' + req.body.avatar;

    if(pathToFile != 'uploads/avatar-default.jpg') {
    	console.log("Removing : " + pathToFile);
		fs.unlink(pathToFile, function(err) {
		  	if (err) {
		    	throw err
		  	} else {
		    	console.log("Successfully deleted the file.")
		  	}
		})
	}//Eo if
    
});

app.get('/api/stats', expressJWT(tokenSettings), isAdmin, (req, res) => {

	console.log('Requête sur /stats');

	let categories = [
		'Doctorant',
		'Post-doctorant', 
		'Etudiant du master TELENVI',
		'Enseignant-Chercheur',
		'Professionnel',
		'Organisme public',
		'Organisme privé'];

	let data = {
		"Doctorant": 0,
		"Post-doctorant": 0,
		"Etudiant du master TELENVI": 0,
		"Enseignant-Chercheur": 0,
		"Professionnel": 0,
		"Organisme public": 0,
		"Organisme privé": 0
	};

	for (let i = 0; i < categories.length; i++) {

		Member.countDocuments({status: categories[i], isVerified: true, isRejected: false}, function (err, count){
			if(err){}

			console.log('there are %d ' + categories[i], count);
			data[categories[i]] = count;
			console.log(data);
			console.log("member")

			if(i == categories.length - 1) {
				res.json(data);
			}
		});
	}//Eo for

});//Eo GET /stats

/* Route ALL pour servir l'application FRONT */

app.get('*', (req, res) => {
  console.log(`[TRACE] Server 404 request: `);
  res.status(200).sendFile(__dirname + '/dist/GeoLink/index.html');
});

/* LISTENING */
app.listen(port, () => console.log(`GeoLink app listening on port ${port}!`));