document.addEventListener("DOMContentLoaded", function() {
    const userString = sessionStorage.getItem("user");
    let lottie = document.getElementById("animation");
    if (!userString) {
        window.location.href = "/";
    }
    const user = JSON.parse(userString);
    if (!user || user.type !== "user") {
        window.location.href = "/";
    }
    fetch("http://localhost:3000/users/find/" + user.file)
        .then(response => response.json())
        .then(userData => {
            console.log(userData);
            sessionStorage.setItem('user', JSON.stringify(userData));
            lottie.style.display = "block";
            setTimeout(() => {
                displayStudentRoutines(userData.routine); // Mostrar rutinas del usuario
                lottie.style.display = "none";
            }, 500);
        })
        .catch(error => {
            console.error("Error al obtener los datos del usuario:", error);
        });
});

function displayStudentRoutines(routines) {
    if (routines.length === 0) {
        const div = document.getElementById("routinediv");
        const p = document.createElement("p");
        p.textContent = "No hay rutinas disponibles";
        div.appendChild(p);
        return;
    }
    else {
    const div = document.getElementById("routinediv"); // Obtener el div correcto
    
    routines.forEach(routine => {
        const card = document.createElement("div");
        card.classList.add("card", "mb-3", "text-dark");

        const cardHeader = document.createElement("div");
        cardHeader.classList.add("card-header");
        cardHeader.textContent = routine.name;
        cardHeader.style.fontSize ="25px";

        const cardBody = document.createElement("div");
        cardBody.classList.add("card-body");

        const exerciseList = document.createElement("ul");
        exerciseList.classList.add("list-group", "list-group-flush");

        card.style.backgroundColor = "rgba(137, 43, 226, 0.785)";
        card.style.borderColor = "black";

        
        routine.exercises.forEach(exercise => {
            const exerciseItem = document.createElement("li");
            exerciseItem.classList.add("list-group-item", "d-flex", "justify-content-between", "align-items-center");
            
            const exerciseName = document.createElement("span");
            exerciseName.textContent = exercise.exercise;

            exerciseName.style.color = "white";

            const exerciseDetails = document.createElement("span");
            exerciseDetails.textContent = `Series: ${exercise.sets}, Reps: ${exercise.reps}`;
            exerciseDetails.style.color = "white";

            const link = document.createElement("a");
            link.href = exercise.link;
            link.textContent = "Ver más"; // Agregar texto al enlace
            link.style.color = "white";

            exerciseItem.style.backgroundColor = "rgba(137, 43, 226, 0.785)";
            
            exerciseItem.appendChild(exerciseName);
            exerciseItem.appendChild(exerciseDetails);
            exerciseItem.appendChild(link); // Agregar el enlace al elemento de la lista
            exerciseList.appendChild(exerciseItem);
        });

        cardBody.appendChild(exerciseList);
        card.appendChild(cardHeader);
        card.appendChild(cardBody);
        
        div.appendChild(card); // Agregar la tarjeta al div correcto
    });
}}
