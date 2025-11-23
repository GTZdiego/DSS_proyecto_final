document.addEventListener("DOMContentLoaded", function() {
    let keycompare = "sudosu";
    let name = document.getElementById("name");
    let email = document.getElementById("mail");
    let password = document.getElementById("password");
    let passwordconfirm = document.getElementById("passwordconfirm");
    let file = document.getElementById("filenumber");
    let butonRegister = document.getElementById("register");
    let errorContainer = document.getElementById("errorContainer"); // Contenedor para mensajes de error
    const lottie = document.getElementById('animation');


    butonRegister.addEventListener("click", function() {
        console.log("Botón Registrar clickeado");
        errorContainer.innerHTML = "";

    
        let coach = document.getElementById("coach");
        let valor = coach.checked ? "coach" : "user";
        let usuario = document.getElementById("user");
        
        // Validar campos obligatorios
        if (!name.value || !email.value || !password.value || !passwordconfirm.value || !file.value || (!coach.checked && !usuario.checked)) {
            mostrarError('Todos los campos son obligatorios.');
            console.log("Todos los campos son obligatorios");
        }
        else if (password.value !== passwordconfirm.value) {
            mostrarError('Las contraseñas no coinciden.');
            console.log("Las contraseñas no coinciden");
        }
        else if (valor === "coach") {
            let key = document.getElementById("key");
            if (key.value !== keycompare) {
                mostrarError('La clave ingresada no es válida.');
                error = true;
            }
            else {
                const data = {
                    name: name.value,
                    file: file.value,
                    email: email.value,
                    password: password.value,
                    type: valor
                };
                lottie.style.display = 'block';
                console.log("Enviando solicitud fetch...");
                fetchData(data);   
            }
        }
        else if (password.value.length < 8 || passwordconfirm.value.length < 8) {
            mostrarError('La contraseña debe tener al menos 8 caracteres.');
        }
        else {
            console.log("Enviando solicitud fetch...");
            lottie.style.display = 'block';

            const data = {
                name: name.value,
                file: file.value,
                email: email.value,
                password: password.value,
                type: valor
            };
            fetchData(data);
        }    
    });
    

    // Función para mostrar mensajes de error
    function mostrarError(mensaje) {
        lottie.style.display = 'block';
        setTimeout(() => {
            let errorElement = document.createElement('div');
            errorElement.classList.add('alert', 'alert-danger');
            errorElement.textContent = mensaje;
            errorContainer.appendChild(errorElement);
            lottie.style.display = 'none';
        }, 1000);
        
    }

    function fetchData(data) {
        fetch('http://localhost:3000/users/add', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(data)
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            })
            .then(data => {
                console.log('Success:', data);
                window.location.href = "/";
            })
            .catch(error => {
                console.error('Error al enviar la solicitud:', error);
                mostrarError('Error al enviar la solicitud (el correo o expediente ya existen)');
            });
    }
});
