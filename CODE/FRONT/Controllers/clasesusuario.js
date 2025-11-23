document.addEventListener("DOMContentLoaded", function() {
    let lottie = document.getElementById("animation");
    let user = JSON.parse(sessionStorage.getItem("user"));
    if (!user || user.type !== "user") {
        window.location.href = "/";
    }
    lottie.style.display = "block";
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
            console.log(clasesData);
            let diasConClase = {
                "Lunes":false,
                "Martes":false,
                "Miercoles":false,
                "Jueves":false,
                "Viernes":false,
            };
            setTimeout(() => {
                clasesData.forEach(clase => {
                    let user = JSON.parse(sessionStorage.getItem('user'));
                    let reserv = user.name + ' ' + user.file;
                    let isReserved = clase.reservations.includes(reserv); // Asume que 'reservations' es un array de reservas en el objeto 'clase'
                    const htmlCode = `
                    <div class="card p-3 border border-dark position-relative" style="background-color: rgba(137, 43, 226, 0.912)">
                    Nombre: `+clase.name+`<br>
                    Hora: `+clase.hour+`
                    <button type="button" class="btn btn-dark memberClassBtn" data-id="`+clase._id+`" style="display: `+(isReserved ? 'none' : 'block')+`;">Reservar clase</button>
                    <button type="button" class="btn btn-secondary deleteClassBtn" data-id="`+clase._id+`" style="display: `+(isReserved ? 'block' : 'none')+`;">Anular Reservación</button>
                    </div>
                    `;
                    const divDay = document.getElementById(clase.day);
                    divDay.innerHTML += htmlCode;
                    diasConClase[clase.day]=true;
                });
                for(let dia in diasConClase){
                    if(!diasConClase[dia]){
                        const divDay = document.getElementById(dia);
                        divDay.innerHTML += '<div class="card p-3 border border-dark" style="background-color: rgba(137, 43, 226, 0.912)">No hay clases</div>';
                    }
                }
                lottie.style.display = "none";
            
            


            const memberClassBtn = document.querySelectorAll('.memberClassBtn');
            memberClassBtn.forEach(button =>{
                button.addEventListener('click', function(){
                    const classId = this.getAttribute('data-id');
                    console.log(classId);
                    let user = JSON.parse(sessionStorage.getItem('user'));
                    let reserv = user.name + ' ' + user.file;
                    console.log(reserv);
                    fetch(`http://localhost:3000/clases/addReservation`,{
                        method:'POST',
                        headers: {'Content-Type': 'application/json',},
                        body: JSON.stringify({id:classId, reservation:reserv}),
                    })
                        .then(response => response.json())
                        .then(result => {
                            const resultado=JSON.stringify(result);
                            alert("Reserva realizada");
                            this.style.display = 'none'; // Oculta el botón de reserva
                            const deleteButton = this.nextElementSibling; // Obtiene el botón de eliminar reserva
                            deleteButton.style.display = 'block';
                        })
                        .catch((error) => {
                           alert("Error, la reserva ya existe");
                        })
                })
                    
            })

            const deleteClassBtns = document.querySelectorAll('.deleteClassBtn');
            deleteClassBtns.forEach(button =>{
                button.addEventListener('click', function(){
                    let user = JSON.parse(sessionStorage.getItem('user'));
                    let reserv = user.name + ' ' + user.file;
                    console.log("click");
                    const classId = this.getAttribute('data-id');
                    console.log(classId, reserv);
                    fetch(`http://localhost:3000/clases/deleteReservation`,{                        
                        method:'DELETE',
                        headers: {'Content-Type': 'application/json',},
                        body: JSON.stringify({id:classId, reservation:reserv}),
                    })
                        .then(response => response.json())
                        .then(result => {
                            alert("Se elimino la reserva");
                            this.style.display = 'none'; // Oculta el botón de eliminar reserva
                            const reserveButton = this.previousElementSibling; // Obtiene el botón de reserva
                            reserveButton.style.display = 'block';
                            // Recargar la página para mostrar las clases actualizadas
                        })
                        .catch((error) => {
                            alert("No hay reserva existente para eliminar");
                        });
                })
            })

        })
        }, 500);
    });
    