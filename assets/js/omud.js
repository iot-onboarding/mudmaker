// mud oAuth flows.

function oAuthP1(){
    const redirect_uri="https://www.ofcourseimright.com/test/mudmaker/mudpublish.html";
    const client_id = "Ov23licSoRbhBHkeDqPJ";
    const csrfkey = new Uint8Array(16);
    self.crypto.getRandomValues(csrfkey);
    const state = csrfkey.toHex();
    localStorage.setItem("latestCSRFToken", state);
    localStorage.setItem("email",document.getElementById("email_addr"))
    const link = `https://github.com/login/oauth/authorize?client_id=${client_id}&response_type=code&scope=repo&redirect_uri=${redirect_uri}&state=${state}`;
    window.location.assign(link);
}

function oAuthP2(){ 
  // const { code, state } = queryString.parse(router.asPath.split("?")[1]);
  const myURL = new URL(window.location);
  
  let state = myURL.searchParams.get("state");
  let code = myURL.searchParams.get("code");
  if (state != null||  code != null) {
    document.getElementById("two").style.visibility = "inherit"
      // validate the state parameter
    if (state !== localStorage.getItem("latestCSRFToken")) {
      localStorage.removeItem("latestCSRFToken");
      return;
    }
    localStorage.removeItem("latestCSRFToken");
    // send the code to the backend
    email = localStorage.getItem("email")
    jsonbody = {
      mudFile : b64_encode(sessionStorage.getItem("mudfile")),
      "code" : code,
      "email" : email,
      "next-redirect" : "https://" + window.location.hostname
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
      let results=response.json();
      let innerhtml = '<h2>Yay!  Your PR has been created</h2><p>You can click' +
        '<a href="https://github.com/' + user + '/mudfiles">here</a> to take you' +
        'to your repo, which is ' + user + '/mudfiles.</p>';
      let s = document.getElementById("two");
      s.innerHTML = innerhtml;
      return;
    });
    return;
  }
  document.getElementById("one").style.visibility = "inhereit";
  return;
 
}
