document.addEventListener("DOMContentLoaded", function() {
    let user = JSON.parse(sessionStorage.getItem("user"));
    if (!user || user.type !== "user") {
        window.location.href = "/";
    }
    
    fetch("http://localhost:3000/users/find/" + user.file)
        .then(response => response.json())
        .then(userData => {
            console.log(userData);
            sessionStorage.setItem('user', JSON.stringify(userData));
            loadData(userData);
        })
        .catch(error => {
            console.error("Error al obtener los datos del usuario:", error);
        });

    function loadData(user) {
        // Cargar en los inputs los datos del usuario
        document.getElementById("username").innerHTML = "Nombre de usuario: " + user.name;
        document.getElementById("email").innerHTML = "Email: " + user.email;
        if(!user.progress == null || (user.progress).length != 0){
        document.getElementById("height").value = user.progress[user.progress.length - 1].height;
        document.getElementById("weight").value = user.progress[user.progress.length - 1].weight;
        document.getElementById("age").value = user.progress[user.progress.length - 1].age;
        }

        // Calcular la fecha de expiración de la membresía
        const loginDate = new Date(user.loginDate);
        const expirationDate = new Date(loginDate.getTime() + (365*5 * 24 * 60 * 60 * 1000 )); // Sumar 365 días
        document.getElementById("membership").innerHTML = "Inicio de membresía: " + loginDate.toLocaleDateString();
        document.getElementById("expiration").innerHTML = "Fin de membresía: " + expirationDate.toLocaleDateString();

        //Mostrar progreso
        let progressText = '';
        user.progress.forEach((entry) => {
            progressText += `Fecha ${entry.date}:<br>
            Altura: ${entry.height} cm<br>
            Peso: ${entry.weight} kg<br>
            Edad: ${entry.age} años<br><br>`;
        });
        document.getElementById("historial").innerHTML = progressText;
    }

    const saveButton = document.getElementById("save");

    // Agregar evento click al botón de guardar
    saveButton.addEventListener("click", function() {
        const height = document.getElementById("height").value;
        const weight = document.getElementById("weight").value;
        const age = document.getElementById("age").value;
        const progressObject = {
            height: height,
            weight: weight,
            age: age,
            date : new Date().toLocaleDateString()
        };
        // Actualizar el progreso del usuario
        let progreso = JSON.parse(sessionStorage.getItem("user")).progress;
        progreso.push(progressObject);

        // Realizar la solicitud PUT para actualizar los datos del usuario
        fetch("http://localhost:3000/users/addprogress/" + user.file, {
            method: "PUT",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(progreso, null, 2)
        })
        .then(response => {
            if (!response.ok) {
                throw new Error("Error al actualizar los datos del usuario");
            }
            alert("Datos actualizados exitosamente");
            location.reload();
        })
        .catch(error => {
            console.error("Error al actualizar los datos del usuario:", error);
            alert("Error al actualizar los datos del usuario. Por favor, inténtelo de nuevo.");
        });
    });


    //Boton pull de historial
    const pullHistoryBtn = document.getElementById("saveHistoryBtn");
    pullHistoryBtn.addEventListener("click", function() {
        let progreso = JSON.parse(sessionStorage.getItem("user")).progress;
        if (progreso.length === 0) {
            alert("No hay datos para mostrar");
            return;
        }
        progreso.pop();
        fetch("http://localhost:3000/users/addprogress/" + user.file, {
            method: "PUT",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(progreso, null, 2)
        })
        .then(response => {
            if (!response.ok) {
                throw new Error("Error al actualizar los datos del usuario");
            }
            alert("Datos actualizados exitosamente");
            location.reload();
        })
        .catch(error => {
            console.error("Error al actualizar los datos del usuario:", error);
            alert("Error al actualizar los datos del usuario. Por favor, inténtelo de nuevo.");
        });
        
    })
});
