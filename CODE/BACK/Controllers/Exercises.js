const mongoose = require('mongoose');

const exerciseSchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: { type: String, required: true },
    muscle: { type: String, required: true },
    link : { type: String, required: true }
});

const Exercise = mongoose.model('exercises', exerciseSchema);

async function agregarEjercicio(exercise) {
    try {
        const newExercise = new Exercise(exercise);
        const savedExercise = await newExercise.save();
        return savedExercise;
    } catch (error) {
        console.error('Error al agregar el ejercicio:', error);
        throw error;
    }
}

async function getAllExercises() {
    try {
        const exercises = await Exercise.find({});
        return exercises;
    } catch (error) {
        console.error('Error al obtener todos los ejercicios:', error);
        throw error;
    }
}

async function getExerciseByMuscle(muscle) {
    try {
        const exercises = await Exercise.find({ muscle: muscle });
        return exercises;
    } catch (error) {
        console.error('Error al obtener los ejercicios por musculo:', error);
        throw error;
    }
}

async function deleteExerciseByName(name) {
    try {
        const exercise = await Exercise.findOneAndDelete({ name: name });
        return exercise;
    } catch (error) {
        console.error('Error al eliminar el ejercicio:', error);
        throw error;
    }
}

async function getExerciseByName(name) {
    try {
        const regex = new RegExp(name, 'i');
        const exercise = await Exercise.findOne({ name: regex });
        return exercise;
    } catch (error) {
        console.error('Error al buscar el ejercicio:', error);
        throw error;
    }
}

async function getExercisesByName(name) {
    try {
        const regex = new RegExp(name, 'i');
        const exercise = await Exercise.find({ name: regex });
        return exercise;
    } catch (error) {
        console.error('Error al buscar el ejercicio:', error);
        throw error;
    }
}

module.exports = {
    getExercisesByName,
    getAllExercises,
    getExerciseByMuscle,
    deleteExerciseByName,
    agregarEjercicio,
    getExerciseByName
}
