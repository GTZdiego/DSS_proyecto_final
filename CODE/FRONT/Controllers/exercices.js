document.addEventListener("DOMContentLoaded", function() {
    let lottie = document.getElementById("animation");
    let user = JSON.parse(sessionStorage.getItem("user"));
    if (!user || user.type !== "coach") {
        window.location.href = "/";
    }
    
    const userString = sessionStorage.getItem("user");
    if (!userString || JSON.parse(userString).type !== "coach") {
        window.location.href = "/";
    }
    const exerciseContainer = document.getElementById("exerciseContainer");
    const editModal = document.getElementById("editModal");
    const exerciseModal=document.getElementById("exerciseModal");
    const currentExerciseName='';
    sessionStorage.setItem("name", " ");

    // Función para cargar los ejercicios al inicio
    // Función para cargar los ejercicios al inicio

    function clearModals() {
        window.location.reload();
    }

function loadExercises() {
    lottie.style.display = "block";
    setTimeout(() => {
        fetch("http://localhost:3000/exercises/all")
        .then(response => response.json())
        .then(exercises => {
            exercises.forEach(exercise => {
                const card = createExerciseCard(exercise);
                exerciseContainer.appendChild(card); // Agregar esta línea
            });
        })
        .catch(error => {
            console.error("Error al cargar los ejercicios:", error);
        });
        lottie.style.display = "none";
    }, 500);
    
}


    // Función para crear una tarjeta de ejercicio
    function createExerciseCard(exercise) {
        const card = document.createElement("div");
        card.classList.add("card", "p-3", "mb-3", "border-dark");
        card.style.backgroundColor = "rgba(137, 43, 226, 0.912)"; // Color de fondo más suave
        card.style.border = "2px solid #674ea7"; // Borde más grueso y color púrpura
    
        const exerciseName = document.createElement("h4");
        exerciseName.classList.add("text-center", "mb-3");
        exerciseName.textContent = exercise.name;
        exerciseName.style.color = "black"; // Color de texto púrpura
    
        const exerciseDetails = document.createElement("p");
        exerciseDetails.classList.add("text-center", "mb-2");
        exerciseDetails.textContent = `Músculo: ${exercise.muscle}`;
        exerciseDetails.style.color = "white"; // Color de texto más oscuro
    
        const description = document.createElement("p");
        description.classList.add("text-center", "mb-2");
        description.textContent = `Descripción: ${exercise.description}`;
        description.style.color = "white"; // Color de texto más oscuro
    
        const link = document.createElement("p");
        link.classList.add("text-center", "mb-3");
        link.innerHTML = `<strong>Link:</strong> <a href="${exercise.link}" target="_blank">${exercise.link}</a>`;
        link.style.color = "white"; // Color de texto más oscuro
    
        const deleteButton = document.createElement("button");
        deleteButton.classList.add("btn", "btn-secondary", "me-2");
        const trashIcon = document.createElement("i");
        trashIcon.classList.add("fas", "fa-trash");
        deleteButton.appendChild(trashIcon);
        deleteButton.addEventListener("click", function() {
            deleteExercise(exercise.name);
        });
    
        const editButton = document.createElement("button");
        editButton.classList.add("btn", "btn-dark");
        editButton.textContent = "Editar";
        editButton.addEventListener("click", function() {
            openEditModal(exercise);
        });
    
        const buttonContainer = document.createElement("div");
        buttonContainer.classList.add("text-center");
        buttonContainer.appendChild(deleteButton);
        buttonContainer.appendChild(editButton);
    
        card.appendChild(exerciseName);
        card.appendChild(exerciseDetails);
        card.appendChild(description);
        card.appendChild(link);
        card.appendChild(buttonContainer);
    
        return card;
    }
    
    // Función para eliminar un ejercicio
    function deleteExercise(exerciseName) {
        if (confirm(`¿Estás seguro de que deseas eliminar el ejercicio "${exerciseName}"?`)) {
            fetch(`http://localhost:3000/exercises/delete/${exerciseName}`, {
                method: "DELETE"
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error("Error al eliminar el ejercicio");
                }
                // Recargar los ejercicios después de la eliminación
                exerciseContainer.innerHTML = "";
                loadExercises();
                alert(`El ejercicio "${exerciseName}" se eliminó correctamente`);
            })
            .catch(error => {
                console.error("Error al eliminar el ejercicio:", error);
                alert("Error al eliminar el ejercicio. Por favor, inténtelo de nuevo.");
            });
        }
    }


    
    // Función para abrir el modal de edición
    function openEditModal(exercise) {
        // Llenar el formulario de edición con los datos del ejercicio existente
        const exerciseNameInput = document.getElementById("exerciseNamemodal");
        const muscleGroupInput = document.getElementById("muscleGroupmodal");
        const descriptionInput = document.getElementById("descriptionmodal");
        const linkInput = document.getElementById("linkmodal");

        exerciseNameInput.value = exercise.name;
        muscleGroupInput.value = exercise.muscle;
        descriptionInput.value = exercise.description;
        linkInput.value = exercise.link;

        // Mostrar el modal
        const modal = new bootstrap.Modal(document.getElementById("editModal"));
        sessionStorage.setItem("name", exercise.name);
        
        modal.show();
    }




    // Agregar el evento al botón de guardar del modal de edición
    const addExerciseBtn = document.getElementById("addExerciseBtn");
    addExerciseBtn.addEventListener("click", function() {
        const exerciseNameInput = document.getElementById("exerciseName").value;
        const muscleGroupInput = document.getElementById("muscleGroup").value;
        const descriptionInput = document.getElementById("description").value;
        const linkInput = document.getElementById("link").value;

        const newExercise = {
            name: exerciseNameInput,
            muscle: muscleGroupInput,
            description: descriptionInput,
            link: linkInput
        };

        console.log(newExercise);

        // Eliminar ejercicio si ya existe
        fetch(`http://localhost:3000/exercises/delete/${exerciseNameInput.replace(' ', '%20')}`, {
            method: "DELETE"
        });

        // Agregar el nuevo ejercicio al servidor
        fetch("http://localhost:3000/exercises/add", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(newExercise)
        })
        .then(response => {
            if (!response.ok) {
                throw new Error("Error al agregar el ejercicio");
            }
            // Recargar los ejercicios después de agregar uno nuevo
            clearModals();
            alert(`El ejercicio "${newExercise.name}" se agregó correctamente`);
        })
        .catch(error => {
            console.error("Error al agregar el ejercicio:", error);
            alert("Error al agregar el ejercicio. Por favor, inténtelo de nuevo.");
        });
    });

    const editButton = document.getElementById('edExerciseBtn');
    editButton.addEventListener('click', function() {
    const exerciseName = document.getElementById('exerciseNamemodal').value;
    const muscleGroup = document.getElementById('muscleGroupmodal').value;
    const description = document.getElementById('descriptionmodal').value;
    const link = document.getElementById('linkmodal').value;
    const name = sessionStorage.getItem('name');
    console.log(name);

    const updatedExercise = {
        name: exerciseName,
        muscle: muscleGroup,
        description: description,
        link: link
    };

    fetch(`http://localhost:3000/exercises/delete/${name.replace(' ', '%20')}`, {
        method: "DELETE"
    });

    fetch(`http://localhost:3000/exercises/add`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(updatedExercise)
    });
    clearModals();

    loadExercises();

    });
    



    // Cargar los ejercicios al inicio
    loadExercises();
});
