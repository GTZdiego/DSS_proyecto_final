document.addEventListener('DOMContentLoaded', function() {
    console.log('login.js loaded');
    // Obtener referencias a los elementos del DOM
    const loginButton = document.getElementById('loginButton');
    const usernameInput = document.getElementById('mail');
    const passwordInput = document.getElementById('password');
    const lottie = document.getElementById('animation');

    // Agregar evento click al botón de login
    loginButton.addEventListener('click', function() {
        console.log('loginButton clicked');
        // Obtener los valores de los campos de usuario y contraseña
        
        let email = usernameInput.value;
        let password = passwordInput.value;

        // Verificar si los campos están vacíos
        if (email === '' || password === '') {
            lottie.style.display = 'block';
        setTimeout(()=> {
            alert('Por favor, rellene todos los campos');
            lottie.style.display = 'none';
            }, 1000);
            return; // Detener la ejecución si falta algún campo
        }

        // Crear una nueva solicitud XMLHttpRequest
        let xhr = new XMLHttpRequest();
        xhr.open('POST', 'http://localhost:3000/users/login');
        xhr.setRequestHeader('Content-Type', 'application/json');

        // Enviar los datos del usuario al servidor
        xhr.send(JSON.stringify({
            email: email, // Ajustar el nombre de la propiedad a 'email'
            password: password,
        }));

        // Manejar la respuesta del servidor cuando la solicitud esté completa
        
        lottie.style.display = 'block';
        xhr.onreadystatechange = function() {
            if (xhr.readyState === XMLHttpRequest.DONE) {
                if (xhr.status === 200) {
                    // Manejar la respuesta del servidor
                    let response = JSON.parse(xhr.responseText);
                    // Verificar si se recibió el expediente del usuario
                    if (response) {
                        // Almacenar el expediente del usuario en sessionStorage
                        sessionStorage.setItem('user', JSON.stringify(response));
                        // Redirigir al usuario a la página de inicio
                        if(response.type=='user'){
                        window.location.href = '/home';
                        }
                        else if (response.type=='coach'){
                            window.location.href = '/homecoach';
                        }
                         // Ajusta la ruta según sea necesario
                    } else {
                        lottie.style.display = 'block';
                        setTimeout(()=> {
                            alert('Error: Usuario no encontrado');
                            lottie.style.display = 'none';
                        }, 1000);
                    }
                } else {
                    // Manejar errores de la solicitud
                    lottie.style.display = 'block';
                    setTimeout(()=> {
                        alert('Error al iniciar sesión: ');
                        lottie.style.display = 'none';
                    }, 1000);
                }
            }
        };

    });
});
