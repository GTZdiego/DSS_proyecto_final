document.addEventListener("DOMContentLoaded", function() {
    
    let user = JSON.parse(sessionStorage.getItem("user"));
    if (!user || user.type !== "coach") {
        window.location.href = "/";
    }
    

    const studentSearch = document.getElementById("studentSearch");
    const divStudentSearchResults = document.getElementById("divStudentSearchResults");
    const addExerciseBtn = document.getElementById("saveExerciseBtn");
    const divStudentRoutines = document.getElementById("studentRoutines");
    const exerciseSearch = document.getElementById("searchInput");
    const searchResults = document.getElementById("searchResults");
    const addRoutineBtn = document.getElementById("saveRoutineBtn");
    const ejs = document.getElementById("ejer");
    const cancelBtn = document.getElementById("cancelBtn");
    const errores = document.getElementById("errores"); // Contenedor para mostrar los errores

    // Función para limpiar los resultados de la búsqueda de estudiantes
    function clearStudentSearchResults() {
        divStudentSearchResults.innerHTML = "";
    }

    // Función para limpiar el contenido del div de rutinas de estudiante
    function clearStudentRoutines() {
        divStudentRoutines.innerHTML = "";
    }

    // Función para mostrar las rutinas del estudiante como tarjetas
    function displayStudentRoutines(routines) {
        clearStudentRoutines();
        const routinesContainer = document.getElementById("studentRoutines"); // Obtener el contenedor de rutinas
    
        routines.forEach(routine => {
            const card = document.createElement("div");
            card.classList.add("card", "mb-3", "border-dark");
            card.style.backgroundColor = "rgba(137, 43, 226, 0.912)";
    
            const cardHeader = document.createElement("div");
            cardHeader.classList.add("card-header" ,"text-white");
            cardHeader.textContent = routine.name;
            cardHeader.style.backgroundColor = "black";
    
            const cardBody = document.createElement("div");
            cardBody.classList.add("card-body");
    
            const exerciseList = document.createElement("ul");
            exerciseList.classList.add("list-group", "list-group-flush");
    
            routine.exercises.forEach(exercise => {
                const exerciseItem = document.createElement("li");
                exerciseItem.classList.add("list-group-item", "d-flex", "justify-content-between", "align-items-center","text-white");
                exerciseItem.style.backgroundColor = "rgba(137, 43, 226, 0.912)";
                exerciseItem.innerHTML = `<span>${exercise.exercise}</span><span>Series: ${exercise.sets}, Reps: ${exercise.reps}</span>`;
                
                exerciseList.appendChild(exerciseItem);
            });
    
            cardBody.appendChild(exerciseList);
    
            const deleteButton = document.createElement("button");
            deleteButton.classList.add("btn", "btn-secondary", "btn-sm", "float-end");
            deleteButton.textContent = "Eliminar";
            deleteButton.addEventListener("click", function() {
                const filteredRoutines = routines.filter(r => r.name !== routine.name);
                updateStudentRoutines(filteredRoutines);
            });
    
            card.appendChild(cardHeader);
            card.appendChild(cardBody);
            card.appendChild(deleteButton);
    
            routinesContainer.appendChild(card);
        });
    }
    
    // Funcion para actualizar las rutinas del estudiante en el servidor
    function updateStudentRoutines(newRoutines) {
        const expediente = studentSearch.value.trim().split(" ").pop();
        fetch(`http://localhost:3000/users/addroutine/${expediente}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(newRoutines)
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Error al actualizar las rutinas del usuario');
            }
            displayStudentRoutines(newRoutines);
        })
        .catch(error => {
            console.error('Error al actualizar las rutinas del usuario:', error);
        });
    }

    // Función para buscar estudiantes
    studentSearch.addEventListener("input", function() {
        sessionStorage.setItem("rutine", JSON.stringify([]));
        const searchTerm = studentSearch.value.trim();

        if (searchTerm.length === 0) {
            clearStudentSearchResults();
            return;
        }

        fetch(`http://localhost:3000/users/name/${searchTerm}`)
            .then(response => response.json())
            .then(users => {
                clearStudentSearchResults();
                users.forEach(user => {
                    const div = document.createElement("div");
                    div.textContent = user.name;
                    div.addEventListener("click", function() {
                        studentSearch.value = user.name;
                        clearStudentSearchResults();
                        displayStudentRoutines(user.routine);
                    });
                    divStudentSearchResults.appendChild(div);
                });
            });
    });

    // Función para buscar ejercicios
    exerciseSearch.addEventListener('input', function() {
        const exerciseName = exerciseSearch.value.trim();
        if (exerciseName.length === 0) {
            return;
        }
        searchResults.textContent = '';
        fetch(`http://localhost:3000/exercises/finds/${exerciseName}`)
            .then(response => response.json())
            .then(exercises => {
                console
                exercises.forEach(exercise => {
                    const div = document.createElement("div");
                    div.textContent = exercise.name;
                    div.addEventListener("click", function() {
                        exerciseSearch.value = exercise.name;
                        searchResults.innerHTML = "";
                    });
                    searchResults.appendChild(div);
                });
            })
            .catch(error => {
                console.error('Error al buscar ejercicios:', error);
            });
    });

    // Función para agregar ejercicios al estudiante
    addExerciseBtn.addEventListener("click", function() {
        const sets = document.getElementById("series").value;
        const reps = document.getElementById("reps").value;

        if (sets === "" || reps === "") {
            alert("Por favor, rellene todos los campos");
            return;
        }
        const exerciseName = exerciseSearch.value.trim();

        fetch(`http://localhost:3000/exercises/find/${exerciseName}`)
            .then(response => response.json())
            .then(exercise => {
                const newRoutine = {
                    exercise: exercise.name,
                    description: exercise.description,
                    link: exercise.link,
                    sets: sets,
                    reps: reps,
                };
                const routines = JSON.parse(sessionStorage.getItem('rutine')) || [];
                routines.push(newRoutine);
                sessionStorage.setItem("rutine", JSON.stringify(routines));
                // Suponiendo que `ejs` es el elemento HTML donde deseas agregar la lista
ejs.innerHTML += `
<br><div class="routine-item" style="display: flex; justify-content: space-between;">
    <div class="routine-info">
        <li>Ejercicio: ${newRoutine.exercise}<br>Series: ${newRoutine.sets}<br>Reps: ${newRoutine.reps}<br></li>
    </div>
    <button type="button" class="btn btn-secondary delete-button" data-index="${routines.length-1}"><i class="fas fa-trash"></i></button>
</div><br>
`;

// Luego, puedes agregar un event listener para manejar el evento de clic en el botón de eliminar
const deleteButtons = document.querySelectorAll('.delete-button');
deleteButtons.forEach(button => {
button.addEventListener('click', function() {
    const indexToRemove = button.getAttribute('data-index') ; // índice del elemento que deseas eliminar
    const routines = JSON.parse(sessionStorage.getItem('rutine')) || [];
    routines.splice(indexToRemove, 1); // Elimina 1 elemento en la posición indexToRemove
    sessionStorage.setItem("rutine", JSON.stringify(routines));

    
    const routineItem = this.parentNode;
    // Eliminar el elemento padre
    routineItem.parentNode.removeChild(routineItem);
    if(parseInt(indexToRemove) === 0 || indexToRemove === 0){
        ejs.innerHTML = "";
    }
});
});

            })
            .catch(error => {
                console.error('Error al buscar el ejercicio:', error);
            });

        exerciseSearch.value = "";
        document.getElementById("series").value = "";
        document.getElementById("reps").value = "";
    });

    // Función para agregar rutinas al estudiante
    addRoutineBtn.addEventListener("click", function() {
        const name = studentSearch.value;
        const ejercicios = JSON.parse(sessionStorage.getItem('rutine')) || [];
        if (ejercicios.length === 0) {
            alert("Por favor, agrega al menos un ejercicio");
            return;
        }
        const routinename = document.getElementById("routineName").value;
        const expediente = name.trim().split(" ").pop();
        const rutina = { name: routinename, exercises: ejercicios };

        fetch(`http://localhost:3000/users/find/${expediente}`)
            .then(response => {
                if (!response.ok) {
                    throw new Error('Error al buscar el usuario');
                }
                return response.json();
            })
            .then(userData => {
                const previousRoutines = userData.routine || [];
                previousRoutines.push(rutina);
                updateStudentRoutines(previousRoutines);
                ejs.innerHTML = ``;

            })
            .catch(error => {
                alert('Error al buscar el usuario:');
            });
    });

    // Funcion para borrar todo de los inputs y session storage
    cancelBtn.addEventListener("click", function() {
        exerciseSearch.value = "";
        document.getElementById("series").value = "";
        document.getElementById("reps").value = "";
        sessionStorage.setItem("rutine", JSON.stringify([]));
        ejs.innerHTML = "";
        errores.innerHTML = ""; // Limpiar mensajes de error
        document.getElementById("routineName").value = "";
        clearStudentRoutines(); 
        clearStudentSearchResults();
        document.getElementById("studentSearch").value = "";
        document.getElementById("divStudentSearchResults").innerHTML = "";
    });
});
