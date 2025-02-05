// mud oAuth flows.

function oAuthP1(){
    const redirect_uri="https://www.ofcourseimright.com/test/mudmaker/mudpublish.html";
    const client_id = "Ov23licSoRbhBHkeDqPJ";
    const csrfkey = new Uint8Array(16);
    self.crypto.getRandomValues(csrfkey);
    const state = csrfkey.toHex();
    localStorage.setItem("latestCSRFToken", state);
    localStorage.setItem("email",document.getElementById("email_addr").value)
    const link = `https://github.com/login/oauth/authorize?client_id=${client_id}&response_type=code&scope=repo&redirect_uri=${redirect_uri}&state=${state}`;
    window.location.assign(link);
}

function oAuthP2(){ 
  // const { code, state } = queryString.parse(router.asPath.split("?")[1]);
  const myURL = new URL(window.location);
  
  let state = myURL.searchParams.get("state");
  let code = myURL.searchParams.get("code");
  let mudFile = JSON.parse(sessionStorage.getItem("mudfile"));
  let mudurl = mudFile["ietf-mud:mud"]["mud-url"];

  if (state != null &&  code != null) {
      // validate the state parameter
    if (state !== localStorage.getItem("latestCSRFToken")) {
      localStorage.removeItem("latestCSRFToken");
      return;
    }
    localStorage.removeItem("latestCSRFToken");
    // send the code to the backend
    email = localStorage.getItem("email")
    let s = document.getElementById("two");
    s.innerHTML = "Completing authorization...";
    fetch("/gitShove/completeAuth",{
      method: "POST",
      body: JSON.stringify(
        {
          "mudurl" : mudurl,
          "code" : code
        }
      )
    })
    .then(response => {
      if ( ! response.ok )
        return response.text();
      return response.json();
    })
    .then( jsonortext=> {
      let s = document.getElementById("status");
      if (typeof jsonortext != "object") {
        s.innerHTML = s.innerHTML + "fail: " + jsonortext;
        return null;
      }
      s.innerHTML = s.innerHTML + "[ok]<br>Starting the commit...";
      token = jsonortext["token"];
      jsonbody = {
        "token" : token,
        "mudFile"  : b64_encode(mudFile),
        "email" : email,
        "next-redirect" : "https://" + window.location.hostname
      };
      return fetch("/gitShovel", {
        method : "POST",
        body : JSON.stringify(jsonbody),
        headers :{
          "Content-type" : "application/json"
        }
      })
      .then(response => {
        if ( response == null ){
          return; // error, fetch wasn't called.
        }
        if (! response.ok ) {
          return response.text();
        }
        return response.json();
      })
      .then ( jsonortext => {
        let s = document.getElementById("two");
        if (typeof jsonortext == "object") {
          let user = jsonortext['user'];
          let innerhtml = '<h2>Yay!  Your PR has been created</h2><p>You can click ' +
            '<a href="https://github.com/' + user + '/mudfiles">here</a> to take you' +
            'to your repo, which is ' + user + '/mudfiles.</p><h2>Next Steps</h2>' +
            '<p>Next someone will review your PR.  You will see git notivations to' +
            'as it is evaluated.</p>';

          s.innerHTML = innerhtml;
          return;
        }
        s.innerHTML = jsonortext;
      }
    )});
    return;
  }
  document.getElementById("one").style.visibility = "inherit";
}
