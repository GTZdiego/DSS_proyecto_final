const mongoose = require('mongoose');

const claseSchema = new mongoose.Schema({
    name: { type: String, required: true },
    hour: { type: String, required: true },
    day: { enum : ['Lunes', 'Martes', 'Miercoles', 'Jueves', 'Viernes', 'Sabado', 'Domingo'], type: String, required: true },
    reservations: { type: Array, default: [] },
    capacity: { type: Number, required: true },
});

const Clase = mongoose.model('clases', claseSchema);

async function agregarClase(clase) {
    try {
        // Verificar que la clase no exista
        const claseExistente = await Clase.findOne({ name: clase.name, hour: clase.hour, day: clase.day });
        if (claseExistente) {
            throw new Error('La clase ya existe');
        }
        const nuevaClase = new Clase(clase);
        await nuevaClase.save();
        return nuevaClase;
    } catch (error) {
        console.error('Error al agregar la clase:', error);
        throw error;
    }
}

async function getAllClases() {
    try {
        const clases = await Clase.find({});
        return clases;
    } catch (error) {
        console.error('Error al obtener todas las clases:', error);
        throw error;
    }
}

async function getClassById(claseId){
    try{
        const clase= await Clase.findOne({_id:claseId});
        return clase;
    }
    catch (error) {
        console.error('Error al encontrar la clase:', error);
        throw error;
    } 
}

async function deleteClaseById(id) {
    try {
        const deletedClase = await Clase.findOneAndDelete({_id:id });
        return deletedClase;
    } catch (error) {
        console.error('Error al eliminar la clase:', error);
        throw error;
    }
}

async function addReservation(id, reservation) {
    try {
        const claseExistente = await Clase.findById(id);
        const reservations = claseExistente.reservations;

        // Verificar si la reserva ya existe en la lista de reservas
        if (reservations.includes(reservation)) {
            return error;
        }

        // Verificar que la clase exista
        // Buscar la clase por nombre y agregar la reserva si hay espacio disponible
       
        
        const clase = await Clase.findOneAndUpdate({ _id: id }, { $push: { reservations: reservation } }, { new: true });
        if (!clase) {
            throw new Error('La clase no existe');
        }
        if (clase.reservations.length >= clase.capacity) {
            throw new Error('No hay espacio disponible');
        }
        return clase;
    }
     catch (error) {
        console.error('Error al agregar la reserva:', error);
    }
}

async function deleteReservation(id, reservation) {
    try {
        const claseExistente = await Clase.findById(id);
        const reservations = claseExistente.reservations;

        // Verificar si la reserva ya existe en la lista de reservas
        if (!reservations.includes(reservation)) {
            return error;
        }
        const updatedClase = await Clase.findOneAndUpdate({ _id: id }, { $pull: { reservations: reservation } }, { new: true });
        return updatedClase;
    } catch (error) {
        console.error('Error al eliminar la reserva:', error);
    }
}

async function deleteAllReservations(claseName, claseHour, claseDay) {
    try {
        const updatedClase = await Clase.findOneAndUpdate(
            { name: claseName, hour: claseHour, day: claseDay },  { reservations: [] }, { new: true }
        );
        return updatedClase;
    } catch (error) {
        console.error('Error al eliminar todas las reservas:', error);
        throw error;
    }
}



module.exports = {
    agregarClase,
    getAllClases,
    getClassById,
    deleteClaseById,
    addReservation,
    deleteReservation,
    deleteAllReservations
}

