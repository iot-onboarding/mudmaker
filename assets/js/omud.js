// mud oAuth flows.

function oAuthP1(){
    const re = /(?<dirname>.*)\/[^\/]+.html/;
    const redirect_uri=window.location.href.match(re)[1] + "/mudpublish.html";
    const client_id = "Ov23licSoRbhBHkeDqPJ";
    const csrfkey = new Uint8Array(16);
    let tok = sessionStorage.getItem("gottoken");
    if (tok == "true") {
      // skip git.  we're already there.
      window.location.assign(redirect_uri + "?got_token=true");
    }
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
  let got_tok = myURL.searchParams.get("got_token");
  let state = myURL.searchParams.get("state");
  let code = myURL.searchParams.get("code");
  let gitstat = document.getElementById("gitstatus");
  gitstat.innerHTML = "Authenticating..."
  if (got_tok != null || (state != null &&  code != null)) {
    email = localStorage.getItem("email")
      // validate the state parameter
    let jsonbody = {
      mudFile : b64_encode(sessionStorage.getItem("mudfile")),
      email : email
    }
    if ( got_tok != null ) {
      jsonbody["got_tok"] = true;
    } else {
      if (state !== localStorage.getItem("latestCSRFToken")) {
        localStorage.removeItem("latestCSRFToken");
        return;
      }
      localStorage.removeItem("latestCSRFToken");
      jsonbody["code"] = code;
      jsonbody["next-redirect"] = "https://" + window.location.hostname;
    }
    // send the code to the backend
    fetch("/gitShovel/oAuthv2",{
      method : "POST",
      body : JSON.stringify(jsonbody),
      headers :{
        "Content-type" : "application/json",
      }
    })
    .then(response=> {
      if (! response.ok) {
        gitstat.innerHTML +='<span style="color: red">failed</span>';
        return "Oauth Fail";
      }
      gitstat.innerHTML += '<span color="green">[ok]</span>.<br>Doing the rest...'
      return fetch("/gitShovel/therest", {
      method : "POST",
      body : JSON.stringify({
        mudFile : b64_encode(sessionStorage.getItem("mudfile")),
        email : email
      }),
      headers :{
        "Content-type" : "application/json"
      }
      })})
    .then(response => {
      if ( typeof response != 'object') {
        return response;
      }
      if ( ! response.ok ) {
        return response.text();
      }
      return response.json();
    })
    .then ( jsonortext => {
      let s = document.getElementById("two");
      if (typeof jsonortext == "object") {
        let user = jsonortext['user'];
        let innerhtml = '<h2>PR Created</h2>' +
          '<p>Your PR has been created.  You can click on ' +
          '<a href="https://github.com/' + user + '/mudfiles">here</a> to take you' +
          'to your repo, which is ' + user + '/mudfiles.</p>' + 
          '<h2>Next Steps</h2><p>Someone will review your PR.  If it needs changes,' +
          ' you will see a notification from Github.</p>';
        s.innerHTML = innerhtml;
        return;
      }
      s.innerHTML = jsonortext;
    }
  );
    return;
  }
  document.getElementById("one").style.visibility = "inherit";
}
