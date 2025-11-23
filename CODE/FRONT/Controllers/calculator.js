document.addEventListener("DOMContentLoaded", function() {
    const userString = sessionStorage.getItem("user");
    if (!userString) {
        window.location.href = "/";
    }
    const user = JSON.parse(userString);
    if (!user || user.type !== "user") {
        window.location.href = "/";
    }   
    boton = document.getElementById("calculate");

    boton.addEventListener("click", function() {
        let age = parseInt(document.getElementById("age").value);
        let gender = document.getElementById("gender").value;
        let height = parseFloat(document.getElementById("height").value);
        let weight = parseFloat(document.getElementById("weight").value);
        let activity = parseFloat(document.getElementById("activity").value);
        let tbm = (10 * weight) + (6.25 * height) - (5 * age);
        if (gender == "Masculino") {
            tbm = tbm + 5;
        } else if (gender == "Femenino") {
            tbm = tbm - 161;
        }

        let bmrresult = document.getElementById("bmr");
        bmrresult.removeAttribute("disabled");
        tmbmantained = tbm * activity;
        tbmdeficit = tmbmantained - 350
        tmbsuperavite = tmbmantained + 350;
        bmrresult.value = "TMB: " + tbm.toFixed(2) + " kcal" + "\n" + "TMB mantenimiento: " + tmbmantained.toFixed(2) + " kcal" + "\n" + "TMB deficit: " + tbmdeficit.toFixed(2) + " kcal" + "\n" + "TMB superavit: " + tmbsuperavite.toFixed(2) + " kcal";
        bmrresult.setAttribute("disabled", "disabled");
        
        // Indice de masa corporal
        let imc = weight / ((height / 100) * (height / 100));
        let imcresult = document.getElementById("bmi");
        imcresult.removeAttribute("disabled");
        imcresult.value = imc.toFixed(2) + " kg/m²";
    });

    document.getElementById("reset").addEventListener("click", function() {
        window.location.reload();
    })


  });