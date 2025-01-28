// mud oAuth flows.


function oAuthMudFlow(){
    const redirect_uri="https://mudmaker.org/apis/oauth2/response";
    const client_id = "Ov23licSoRbhBHkeDqPJ";
    const state = crypto.randomBytes(16).toString("hex");
    localStorage.setItem("latestCSRFToken", state);
    const link = `https://github.com/login/oauth/authorize?client_id=${client_id}&response_type=code&scope=repo&redirect_uri=${redirect_uri}/integrations/github/oauth2/callback&state=${state}`;
    window.location.assign(link);
}

