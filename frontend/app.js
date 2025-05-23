document.getElementById("login-form").addEventListener("submit", function (e) {
    e.preventDefault();

    const scopes = Array.from(document.querySelectorAll("input[name='scope']:checked"))
        .map(cb => cb.value)
        .join(" ");

    const clientId = "frontend";
    const redirectUri = "http://localhost:8083/callback.html"; // frontend hosted on port 8083
    const authUrl = `http://localhost:9090/oauth2/authorize?` +
        `response_type=code&` +
        `client_id=${clientId}&` +
        `scope=${encodeURIComponent(scopes)}&` +
        `redirect_uri=${encodeURIComponent(redirectUri)}`;

    window.location.href = authUrl;
});
