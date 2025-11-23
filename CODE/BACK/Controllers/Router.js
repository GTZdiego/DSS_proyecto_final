// router.js

const express = require('express');
const router = express.Router();
const users = require('../Routes/users');
const path = require('path');
const exercises = require('../Routes/exercises');
const clases = require('../Routes/clases');


// Definir las rutas y los controladores
router.use('/users', users);
router.use('/exercises', exercises);
router.use('/clases', clases);

router.get('/home', (req, res) => {
    res.sendFile(path.join(__dirname, '../../FRONT/VIEWS/User/home.html'));
});

router.get('/homecoach', (req, res) => {
    res.sendFile(path.join(__dirname, '../../FRONT/VIEWS/Coach/homecoach.html'));
});

router.get('/profile', (req, res) => {
    res.sendFile(path.join(__dirname, '../../FRONT/VIEWS/User/profile.html'));
})


router.get('/about', (req, res) => {
    res.sendFile(path.join(__dirname, '../../FRONT/VIEWS/User/aboutus.html'));
});

router.get('/help', (req, res) => {
    res.sendFile(path.join(__dirname, '../../FRONT/VIEWS/User/help.html'));
});

router.get('/calculator', (req, res) => {
    res.sendFile(path.join(__dirname, '../../FRONT/VIEWS/User/calculator.html'));
});

router.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../../FRONT/VIEWS/login.html'));
});

router.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, '../../FRONT/VIEWS/register.html'));
})

router.get('/routines', (req, res) => {
    res.sendFile(path.join(__dirname, '../../FRONT/VIEWS/User/routines.html'));
});

router.get('/clases', (req, res) => {
    res.sendFile(path.join(__dirname, '../../FRONT/VIEWS/User/clases.html'));
});

router.get('/aboutus', (req, res) => {
    res.sendFile(path.join(__dirname, '../../FRONT/VIEWS/User/aboutus.html'));
});

router.get('/clasescoach', (req, res) => {
    res.sendFile(path.join(__dirname, '../../FRONT/VIEWS/Coach/clasescoach.html'));
});

router.get('/routinescoach', (req, res) => {
    res.sendFile(path.join(__dirname, '../../FRONT/VIEWS/Coach/routinescoach.html'));
});

router.get('/exercises', (req, res) => {
    res.sendFile(path.join(__dirname, '../../FRONT/VIEWS/Coach/exercises.html'));
});

module.exports = router;

