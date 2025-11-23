const express = require('express');
const router = express.Router();
const {getExercisesByName, getExerciseByName, agregarEjercicio, getAllExercises, getExerciseByMuscle, deleteExerciseByName } = require('../Controllers/Exercises');

router.post('/add', async (req, res) => {
    try {
        const newExercise = req.body;
        const ejercicioAgregado = await agregarEjercicio(newExercise);
        res.json(ejercicioAgregado);
    } catch (error) {
        console.error('Error al agregar ejercicio:', error);
        res.status(500).json({ error: 'Error al agregar ejercicio' });
    }
});

router.get('/all', async (req, res) => {
    try {
        const exercises = await getAllExercises();
        res.json(exercises);
    } catch (error) {
        console.error('Error al obtener todos los ejercicios:', error);
        res.status(500).json({ error: 'Error al obtener todos los ejercicios' });
    }
});

router.get('/muscle/:muscle', async (req, res) => {
    try {
        const muscle = req.params.muscle;
        const exercises = await getExerciseByMuscle(muscle);
        res.json(exercises);
    } catch (error) {
        console.error('Error al obtener ejercicios por musculo:', error);
        res.status(500).json({ error: 'Error al obtener ejercicios por musculo' });
    }
});

router.delete('/delete/:name', async (req, res) => {
    try {
        const name = req.params.name;
        const ejercicioEliminado = await deleteExerciseByName(name);
        res.json(ejercicioEliminado);
    } catch (error) {
        console.error('Error al eliminar ejercicio:', error);
        res.status(500).json({ error: 'Error al eliminar ejercicio' });
    }
});

router.get('/find/:name', async (req, res) => {
    try {
        const name = req.params.name;
        const exercise = await getExerciseByName(name);
        res.json(exercise);
    } catch (error) {
        console.error('Error al buscar ejercicio:', error);
        res.status(500).json({ error: 'Error al buscar ejercicio' });
    }
});

router.get('/finds/:name', async (req, res) => {
    try {
        const name = req.params.name;
        const exercise = await getExercisesByName(name);
        res.json(exercise);
    } catch (error) {
        console.error('Error al buscar ejercicio:', error);
        res.status(500).json({ error: 'Error al buscar ejercicio' });
    }
});

module.exports = router;