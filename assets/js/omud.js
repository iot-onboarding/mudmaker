// mud oAuth flows.

function oAuthP1(){
    const redirect_uri="https://www.ofcourseimright.com/test/mudmaker/oauth/mudpublish.html";
    const client_id = "Ov23licSoRbhBHkeDqPJ";
    const csrfkey = new Uint8Array(16);
    self.crypto.getRandomValues(csrfkey);
    const state = csrfkey.toHex();
    localStorage.setItem("latestCSRFToken", state);
    const link = `https://github.com/login/oauth/authorize?client_id=${client_id}&response_type=code&scope=repo&redirect_uri=${redirect_uri}/integrations/github/oauth2/callback&state=${state}`;
    window.location.assign(link);
}

function oAuthP2(){ 
  // const { code, state } = queryString.parse(router.asPath.split("?")[1]);
  const myURL = new URL(window.location);
  let params=myURL.searchParams();
  if (typeof params.state == 'undefined' || typeof params.code == 'undefined') {
    return;
  }
  let state = params.state;
  let code = params.code;
  // validate the state parameter
  if (state !== localStorage.getItem("latestCSRFToken")) {
    localStorage.removeItem("latestCSRFToken");
    return;
  }
  localStorage.removeItem("latestCSRFToken");
  // send the code to the backend
  jsonbody = {
    mudFile : b64_encode(sessionStorage.getItem("mudfile")),
    "code" : code
  };
  fetch("/test/mudmaker/gitmud", {
    method : "POST",
    body : JSON.stringify(jsonbody),
    headers :{
      "Content-type" : "application/json"
    }
  })
  .then(response => {
    if ( ! response.ok ) {
      throw("Bad response");
    }
    return response.json;
  });
}
