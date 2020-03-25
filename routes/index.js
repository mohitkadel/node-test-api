const routes = require('express').Router();
const authorize = require('../helper/authorize');
const Role = require('../helper/role');
const userController = require('../controllers/user');


routes.post('/login', userController.validate('postLogin'), userController.postLogin);
routes.post('/users', authorize([Role.Admin]), userController.validate('postUser'), userController.postUser);
routes.put('/users/:id', authorize([Role.Admin]), userController.validate('putUser'), userController.putUser);
routes.get('/users/:id', authorize([Role.Admin, Role.Teacher, Role.Student]), userController.getUsers);
routes.get('/users', authorize([Role.Admin, Role.Teacher, Role.Student]), userController.getUsers);

module.exports = routes;