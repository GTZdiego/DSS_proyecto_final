document.addEventListener("DOMContentLoaded", function() {
    let lottie = document.getElementById('animation');
    let user = JSON.parse(sessionStorage.getItem("user"));
    if (!user || user.type !== "coach") {
        window.location.href = "/";
    }
    lottie.style.display = "block";
    setTimeout(() => {
    
    fetch(`http://localhost:3000/clases/all`)
        .then(response =>{
            if(!response.ok){
                throw new Error('Error al encontrar las clases');
            }
            return response.json();
        })
        .then(clasesData =>{
            clasesData.sort((a,b)=>{
                return new Date(`2024/01/01 ${a.hour}`) - new Date(`2024/01/01 ${b.hour}`);
            })
            let diasConClase = {
                "Lunes":false,
                "Martes":false,
                "Miercoles":false,
                "Jueves":false,
                "Viernes":false,
            };
            
                clasesData.forEach(clase => {
                    const htmlCode = `
                    <div class="card p-3 border border-dark position-relative" style="background-color: rgba(137, 43, 226, 0.912)">
                        <button type="button" class="btn btn-secondary deleteClassBtn position-absolute top-0 end-0" data-id=`+clase._id+`><i class="fas fa-trash"></i></button>
                        Nombre: `+clase.name+`<br>
                        Hora: `+clase.hour+`
                        <button type="button" class="btn btn-dark memberClassBtn" data-id=`+clase._id+` data-bs-toggle="modal" data-bs-target="#memberClassModal">Ver inscritos</button>
                    </div>`;
                    const divDay = document.getElementById(clase.day);
                    divDay.innerHTML += htmlCode;
                    diasConClase[clase.day]=true;
                });
                lottie.style.display = "none";
            
            const deleteClassBtns = document.querySelectorAll('.deleteClassBtn');
            deleteClassBtns.forEach(button =>{
                button.addEventListener('click', function(){
                    console.log("click");
                    const classId = this.getAttribute('data-id');
                    fetch(`http://localhost:3000/clases/delete/`+classId, {
                        method:'DELETE',
                    })
                        .then(response => response.json())
                        .then(result => {
                            console.log('Clase eliminada:', result);
                            // Recargar la página para mostrar las clases actualizadas
                            location.reload();
                        })
                        .catch((error) => {
                            console.error('Error:', error);
                        });
                })
            })

            for(let dia in diasConClase){
                if(!diasConClase[dia]){
                    const divDay = document.getElementById(dia);
                    divDay.innerHTML += '<div class="card p-3 border border-dark" style="background-color: rgba(137, 43, 226, 0.912)">No hay clases</div>';
                }
            }
            const memberClassBtn = document.querySelectorAll('.memberClassBtn');
            memberClassBtn.forEach(button =>{
                button.addEventListener('click', function(){
                    const classId = this.getAttribute('data-id');
                    fetch(`http://localhost:3000/clases/`+classId+``)
                        .then(response => response.json())
                        .then(clase =>{
                            console.log(clase);
                            const nameClassModal = document.getElementById("nameClassModal");
                            nameClassModal.innerHTML = '';
                            nameClassModal.innerHTML += `: `+clase.name;
                            const membersDiv = document.getElementById("membersDiv");
                            membersDiv.innerHTML = '';
                            if(clase.reservations.length === 0){
                                membersDiv.innerHTML = 'No hay reservaciones';
                            }else{
                                clase.reservations.forEach(member => {
                                    const htmlMember = `<p>`+member+`</p>`;
                                    membersDiv.innerHTML += htmlMember;
                                });
                            }
                            
                        })
                })
            })
        })

    const addClass = document.getElementById("addClassBtn");
    addClass.addEventListener('click', ()=>{
        const classTime = document.getElementById("classTime");
        const className = document.getElementById("classType");
        const daySelect = document.getElementById("dayselect");       
        const newClase ={
            name:className.value,
            hour:classTime.value,
            day:daySelect.value,
            reservations:[],
            capacity:20
        }
        fetch('http://localhost:3000/clases/add', {
            method: 'POST',
            headers: {'Content-Type': 'application/json',},
            body: JSON.stringify(newClase),
            })
            .then(response => response.json())
            .then(clase => {
                console.log('Clase agregada:', clase);
                // Recargar la página para mostrar la clase creada
                location.reload();
            })
            .catch((error) => {
                console.error('Error:', error);
            });
    })
},500);
});