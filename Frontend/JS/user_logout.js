document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("logout-form");
    if (form) {
        form.addEventListener("submit", async(event) => {
            event.preventDefault();

            try{
                const response = await fetch("/logout/", {method: "GET", credentials: "include", redirect: "follow"});

                if (response.ok) {
                    window.location.href = "/";
                }

                else {
                    const result = await response.json();
                    alert(result.message || "Logout failed.");
                }
            }

            catch(error){
                alert(error);
            }
        })
    }
})