const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    file: { type: String, required: true },
    email: { type: String, required: true },
    password: { type: String, required: true },
    loginDate: { type: Date, default: Date.now },
    type: { type: String, required: true, enum: ['coach', 'user'] },
    routine : { type: Object, default: [] },
    progress : { type: Object, default: [] }
});

const User = mongoose.model('User', userSchema); 

// Función para agregar un nuevo usuario a la base de datos
async function agregarUsuario(newUser) {
    try {
        // Verificar si el usuario ya existe en la base de datos
        const usuarioExistente = await User.findOne({ file: newUser.file });
        const emailExistente = await User.findOne({ email: newUser.email });
        if (usuarioExistente || emailExistente) {
            throw new Error('El usuario ya existe en la base de datos');
        }
        else if (newUser.type !== 'user' && newUser.type !== 'coach') {
            throw new error;
        }
        else if (newUser.password.length < 8) {
            throw new error;
        }
        else {
        const encryptedPassword = await bcrypt.hash(newUser.password, 10);
        newUser.password = encryptedPassword;
        const usuario = new User(newUser);
        await usuario.save();
        console.log('Usuario agregado correctamente:', usuario);
        return usuario;
        }
    } catch (error) {
        console.error('Error al agregar usuario:', error);
        throw error;
    }
}

// Función para buscar un usuario por su campo "file"
async function buscarUsuarioPorFile(userFile) {
    try {
        const usuario = await User.findOne({ file: userFile });
        if (usuario && usuario.type === 'user') {
            usuario.password = '******';
            return usuario;
        }
        else if (usuario.type === 'coach') {
            return null;
        }
    } catch (error) {
        console.error('Error al buscar usuario por file:', error);
        throw error;
    }
}

// Función para buscar un usuarios nombre 
async function buscarUsuariosPorName(name) {
    try {
        const regex = new RegExp(name, 'i'); 
                const usuarios = await User.find({ name: regex });
        for (const usuario of usuarios) {
            usuario.name = usuario.name+' '+usuario.file;
            usuario.password = '******';
        }
        return usuarios.filter(user => user.type === 'user');
    } catch (error) {
        console.error('Error al buscar usuario por name:', error);
        throw error;
    }
}

// Función para eliminar un usuario de la base de datos por su campo "file"
async function eliminarUsuarioPorFile(userFile) {
    try {
        const usuario = await User.findOneAndDelete({ file: userFile });
        usuario.password = '******';
        console.log('Usuario eliminado correctamente:', usuario);
        return usuario;
    } catch (error) {
        console.error('Error al eliminar usuario por file:', error);
        throw error;
    }
}

// Función para modificar los atributos de un usuario en la base de datos por su campo "file"
async function modificarUsuarioPorFile(userFile, newAttributes) {
    try {
        const usuario = await User.findOneAndUpdate({ file: userFile }, newAttributes, { new: true });
        usuario.password = '******';
        console.log('Usuario modificado correctamente:', usuario);
        return usuario;
    } catch (error) {
        console.error('Error al modificar usuario por file:', error);
        throw error;
    }
}

async function getAllUsers() {
    // Obtener usuarios pero sin la contraseña
    try {
        const usuarios = await User.find();
        for (const usuario of usuarios) {
            usuario.password = '******';
        }
        return usuarios;
    }
    catch (error) {
        console.error('Error al obtener todos los usuarios:', error);
    }
}

// Función para buscar un usuario por su email y password
async function buscarUsuarioPorEmailAndPassword(email, password) {
    try {
        const usuario = await User.findOne({ email: email});
        //Comparar password con la contraseña hasheada
        const match = await bcrypt.compare(password, usuario.password);
        if (match) {
        usuario.password = '******';
        return usuario;
        }
        else {
            throw new Error('Email o password incorrectos');
        }
    } catch (error) {
        console.error('Email o password incorrectos', error);
        throw error;
    }
}

async function addRoutine(userFile, routine) {
    try {
        const usuario = await User.findOneAndUpdate({ file: userFile }, { routine: routine });
        usuario.password = '******';
        return usuario;
    } catch (error) {
        console.error('Error al agregar rutina:', error);
        throw error;
    }
}

async function addProgress(userFile, progress) {
    try {
        const usuario = await User.findOneAndUpdate({ file: userFile }, { progress: progress });
        usuario.password = '******';
        return usuario;
    } catch (error) {
        console.error('Error al agregar progreso:', error);
        throw error;
    }
}


module.exports = {addProgress, buscarUsuariosPorName, agregarUsuario, buscarUsuarioPorFile, eliminarUsuarioPorFile, modificarUsuarioPorFile, getAllUsers, buscarUsuarioPorEmailAndPassword, addRoutine };
