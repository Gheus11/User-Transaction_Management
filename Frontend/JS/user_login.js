document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("login-form");
    if (form) {
        form.addEventListener("submit", async(event) => {
            event.preventDefault();
            
            const formData = new FormData(form);
            const credentials = {
                username: formData.get("username"),
                password: formData.get("password")
            };

            try {
                const response = await fetch("/login/", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(credentials)});
                const result = await response.json();

                if (response.ok) {
                    document.cookie = `auth_token=${result.jwt}; path=/; SameSite=Lax`;
                    const hubUrl = result.admin_status ? "/hub-admin/" : "/hub/";
                    window.location.href = hubUrl;

                } else {
                    alert(result.message);
                }
            }

            catch(error) {
                alert(error);
            }
        })
    }
})