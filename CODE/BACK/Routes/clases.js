const express = require('express');
const router = express.Router();
const { agregarClase,
    getAllClases,
    getClassById,
    deleteClaseById,
    addReservation,
    deleteReservation,
    deleteAllReservations } = require('../Controllers/Clases');

router.get('/all', async (req, res) => {
    try {
        const clases = await getAllClases();
        res.json(clases);
    } catch (error) {
        console.error('Error al obtener todas las clases:', error);
        res.status(500).json({ error: 'Error al obtener todas las clases' });
    }
});

router.get('/:id', async(req, res)=>{
    try{
        const clase = await getClassById(req.params.id);
        res.json(clase);
    } catch (error) {
        console.error('Error al obtesner la clases:', error);
        res.status(500).json({ error: 'Error al obtener la clases' });
    }
})

router.post('/add', async (req, res) => {
    try {
        const newClase = req.body;
        const claseAgregada = await agregarClase(newClase);
        res.json(claseAgregada);
    } catch (error) {
        console.error('Error al agregar clase:', error);
        res.status(500).json({ error: 'Error al agregar clase' });
    }
});

router.delete('/delete/:id', async (req, res) => {
    try {
        const deletedClase = await deleteClaseById(req.params.id);
        res.json(deletedClase);
    } catch (error) {
        console.error('Error al eliminar clase:', error);
        res.status(500).json({ error: 'Error al eliminar clase' });
    }
});

router.post('/addReservation', async (req, res) => {
    try {
        const {id, reservation } = req.body;
        const updatedClase = await addReservation(id, reservation);
        res.status(200).json(updatedClase);
    } catch (error) {
        console.error('Error al agregar reserva:', error);
        res.status(500).json({ error: 'Error al agregar reserva' });
    }
});

router.delete('/deleteReservation', async (req, res) => {
    try {
        const { id, reservation } = req.body;
        const updatedClase = await deleteReservation(id, reservation);
        res.json(updatedClase);
    } catch (error) {
        console.error('Error al eliminar reserva:', error);
        res.status(500).json({ error: 'Error al eliminar reserva' });
    }
});


router.delete('/deleteAllReservations', async (req, res) => {
    try {
        const { name, hour, day } = req.body;
        const updatedClase = await deleteAllReservations(name, hour, day);
        res.json(updatedClase);
    } catch (error) {
        console.error('Error al eliminar todas las reservas:', error);
        res.status(500).json({ error: 'Error al eliminar todas las reservas' });
    }
});

module.exports = router;