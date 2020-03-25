const User = require('../models/user');
const { check, body, validationResult } = require('express-validator')
const Role = require('../helper/role');
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt');

let validate = function(method) {
	switch (method) {
		case 'postUser':
			{
				return [
					check('profile.gender').exists().custom(value => {
						if ([1, 2].indexOf(value) == -1) {
							return Promise.reject('Invalid gender')
						}
						return true;
					}),
					check('profile.f_name').exists(),
					check('profile.l_name').exists(),
					check('profile.dob').exists(),
					check('status').exists().custom(value => {
						if ([0, 1].indexOf(value) == -1) {
							return Promise.reject('Invalid status')
						}
						return true;
					}),
					check('role').exists().custom(value => {
						if ([1, 2, 3].indexOf(value) == -1) {
							return Promise.reject('Invalid role')
						}
						return true;
					}),
					check('email').exists().isEmail().custom(value => {
						return User.findOne({ email: value }).then(user => {
							if (user) {
								return Promise.reject('E-mail already in use');
							}
						});
					}),
					check('password').exists()
					.isLength({ min: 5 }).withMessage('must be at least 5 chars long')
				]
			}
		case 'putUser':
			{
				return [
					check('profile.gender').custom(value => {
						if (value && [1, 2].indexOf(value) == -1) {
							return Promise.reject('Invalid gender')
						}
						return true;
					}),
					// check('profile.f_name').exists(),
					// check('profile.l_name').exists(),
					// check('profile.dob').exists(),
					check('status').custom(value => {
						if (value && [0, 1].indexOf(value) == -1) {
							return Promise.reject('Invalid status')
						}
						return true;
					}),
					check('role').custom((value, { req }) => {
						if (value && [1, 2, 3].indexOf(value) == -1) {
							return Promise.reject('Invalid role')
						}
						return true;
					}),
				]
			}
		case 'postLogin':
			{
				return [
					check('email').exists().isEmail(),
					// password must be at least 5 chars long
					check('password').exists()
				]
			}
	}
}

let getUsers = function(req, res) {
	let query = {};
	query = req.query;
	console.log('query')
	console.log(req.query)
	User.find(query).then((users) => {
			res.status(200).send(users);
		})
		.catch((error) => {
			res.status(400).send(error);
		})
};

let getUser = function(req, res) {
	User.findById(req.params.id).then((user) => {
			res.status(200).send(user);
		})
		.catch((error) => {
			res.status(404).send(error);
		});
};

let putUser = function(req, res) {
	const errors = validationResult(req); // Finds the validation errors in this request and wraps them in an object with handy functions

	if (!errors.isEmpty()) {
		res.status(422).json({ errors: errors.array() });
		return;
	}
	User.findById(req.params.id).then((user) => {
			if (Role.isAdmin(req.role) || (!Role.isAdmin(user.role) && !Role.isAdmin(req.role) && Role.isTeacher(req.role))) {
				user.role = req.body.role || user.role;
				user.status = req.body.status==undefined ? user.status : req.body.status;

				user.profile.f_name = req.body.f_name || user.profile.f_name;
				user.profile.l_name = req.body.l_name || user.profile.l_name;
				user.profile.gender = req.body.gender || user.profile.gender;
				user.profile.dob = req.body.dob || user.profile.dob;

			} else if (Role.isStudent(req.role) && req.body.id == req.id) {
				user.profile.f_name = req.body.f_name || user.profile.f_name;
				user.profile.l_name = req.body.l_name || user.profile.l_name;
				user.profile.gender = req.body.gender || user.profile.gender;
				user.profile.dob = req.body.dob || user.profile.dob;
			}
			else {
				res.status(400).send({ error: "You are not allowed to perform this action" });
				return;
			}

			user.updated_by = req.id;
			user.save();

			res.status(200).send(user);
		})
		.catch((error) => {
			console.log(error)
			res.status(404).send({ error: "User not found" });
		})
};

let postUser = function(req, res) {
	const errors = validationResult(req); // Finds the validation errors in this request and wraps them in an object with handy functions
	if (!errors.isEmpty()) {
		res.status(422).json({ errors: errors.array() });
		return;
	}

	let user = new User(req.body);
	user.created_by = req.id;

	if (Role.isAdmin(req.role) || (!Role.isAdmin(user.role) && Role.isTeacher(req.role))) {
		user.save(user).then(() => {
				res.status(201).send(user);
			})
			.catch((error) => {
				console.log(error)
				res.status(400).send("Something went wrong");
			})
	} else {
		res.status(400).send({ error: "You are not allowed to perform this action" });
	}
};

let postLogin = function(req, res) {
	const errors = validationResult(req); // Finds the validation errors in this request and wraps them in an object with handy functions

	if (!errors.isEmpty()) {
		res.status(422).json({ errors: errors.array() });
		return;
	}
	
	User.findOne({ email: req.body.email }).then((user) => {
			let result = {};
			
			if(user.status === 0) {
				result.message = 'User is Inactive';
				res.status(401).send(result)
				return;
			}

			const options = { expiresIn: '2d', issuer: 'http://localhost' };
			const secret = "mohitkadel";
			const payload = { id: user._id, role: user.role };

			const token = jwt.sign(payload, secret, options);

			bcrypt.compare(req.body.password, user.password).then(match => {
				if (match) {
					res.status(200)
					result.data = user;
					result.token = token;
				} else {
					res.status(401)
					result.message = 'Invalid email or password';
				}
				console.log(result)
				res.send(result);
			})
		})
		.catch((error) => {
			console.log(error)
			res.status(404).send({ error: "User not found" });
		})
};

module.exports = {
	postLogin: postLogin,
	postUser: postUser,
	putUser: putUser,
	getUsers: getUsers,
	getUser: getUser,
	validate: validate
}