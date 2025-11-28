// Server.js
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const router = require('./BACK/Controllers/Router');
const path = require('path');

const app = express();
app.use(express.static(path.join(__dirname, './BACK')));
app.use(express.static(path.join(__dirname, './FRONT')));

const port = 3000;
app.use(express.json());
app.use(cors());

// Conexión a la base de datos
const mongoConnection = "mongodb+srv://admin:dss_2025*@myapp.tkoa9ty.mongodb.net/?appName=MyApp";
mongoose.connect(mongoConnection)
    .then(() => console.log('Conexión exitosa a la base de datos'))
    .catch((error) => console.error('Error de conexión a la base de datos:', error));

// Usar el enrutador
app.use('/', router);

// Iniciar el servidor
app.listen(port, () => {
    console.log(`Servidor ejecutándose en el puerto ${port}`);
});
