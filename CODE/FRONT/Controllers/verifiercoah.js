document.addEventListener("DOMContentLoaded", function() {
    let user = JSON.parse(sessionStorage.getItem("user"));
    if (!user || user.type !== "coach") {
        window.location.href = "/";
    }
});
