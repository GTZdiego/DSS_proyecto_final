document.addEventListener("DOMContentLoaded", function() {
    const userString = sessionStorage.getItem("user");
    if (!userString) {
        window.location.href = "/";
    }
    const user = JSON.parse(userString);
    if (!user || user.type !== "user") {
        window.location.href = "/";
    }   
});