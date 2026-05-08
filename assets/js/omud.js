/**
 * Copyright 2017-2025 Eliot Lear
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// mud oAuth flows.

function gitStatusClear(gitstat) {
  window.MudSafeDom.clear(gitstat);
}

function gitStatusAppend(gitstat) {
  window.MudSafeDom.append.apply(window.MudSafeDom, [gitstat].concat(Array.prototype.slice.call(arguments, 1)));
}

function gitStatusOK(gitstat) {
  gitStatusAppend(gitstat, window.MudSafeDom.statusText("[ok]", { style: { color: "green" } }));
}

function gitStatusFailed(gitstat) {
  gitStatusAppend(gitstat, window.MudSafeDom.statusText("failed", { style: { color: "red" } }));
}

function appendPRCreated(gitstat, user) {
  const dom = window.MudSafeDom;
  const repoURL = new URL("https://github.com/");
  repoURL.pathname = "/" + encodeURIComponent(user) + "/mudfiles";

  gitStatusAppend(
    gitstat,
    dom.element("br"),
    dom.element("h2", null, "PR Created"),
    dom.element(
      "p",
      null,
      "Your PR has been created. You can click on ",
      dom.link(repoURL.href, "here"),
      " to take you to your repo, which is ",
      user,
      "/mudfiles."
    ),
    dom.element("h2", null, "Next Steps"),
    dom.element(
      "p",
      null,
      "Someone will review your PR. If it needs changes, you will see a notification from Github."
    )
  );
}

function oAuthP1(){
    const redirectURL = new URL("mudpublish.html", window.location.href);
    const redirect_uri = redirectURL.href;
    const client_id = "Ov23licSoRbhBHkeDqPJ";
    const csrfkey = new Uint8Array(16);
    let tok = sessionStorage.getItem("gottoken");
    if (tok == "true") {
      // skip git.  we're already there.
      redirectURL.searchParams.set("got_token", "true");
      window.location.assign(redirectURL.href);
    }
    self.crypto.getRandomValues(csrfkey);
    const state = csrfkey.toHex();
    localStorage.setItem("latestCSRFToken", state);
    localStorage.setItem("email",document.getElementById("email_addr").value)
    const authURL = new URL("https://github.com/login/oauth/authorize");
    authURL.searchParams.set("client_id", client_id);
    authURL.searchParams.set("response_type", "code");
    authURL.searchParams.set("scope", "repo");
    authURL.searchParams.set("redirect_uri", redirect_uri);
    authURL.searchParams.set("state", state);
    window.location.assign(authURL.href);
}

function oAuthP2(){ 
  // const { code, state } = queryString.parse(router.asPath.split("?")[1]);
  const myURL = new URL(window.location);
  let got_tok = myURL.searchParams.get("got_token");
  let state = myURL.searchParams.get("state");
  let code = myURL.searchParams.get("code");
  let gitstat = document.getElementById("gitstatus");
  let mudFile = JSON.parse(sessionStorage.getItem("mudfile"));
  let mudurl = mudFile['ietf-mud:mud']['mud-url'];
  let user='';

  gitStatusClear(gitstat);
  gitStatusAppend(gitstat, "Authenticating...");
  if (got_tok != null || (state != null &&  code != null)) {
    email = localStorage.getItem("email")
      // validate the state parameter
    let jsonbody = {
      mudurl : mudurl,
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
        gitStatusFailed(gitstat);
        return response.text();
      }
      return response.json();
    })
    .then(resporjson=> {
      if (typeof resporjson != 'object') {
        return resporjson;
      }
      user = resporjson['user'];
      gitStatusOK(gitstat);
      gitStatusAppend(gitstat, ".", window.MudSafeDom.element("br"), "Checking/creating a repo...");
      return fetch('/gitShovel/dorepo', {
        method : "POST",
        body : JSON.stringify({ 'mudurl' : mudurl }),
        headers :{
        "Content-type" : "application/json"
      }})
      .then(response => {
        if (! response.ok ) {
          gitStatusFailed(gitstat);
          return "repo check / fork failed";
        }
        
        return response.json();
      })
      .then(responsejson => {
        if (typeof responsejson != 'object') {
          return "Failed: " + responsejson;
        }
        user = responsejson['user'];
        mfg = mudFile['ietf-mud:mud']['mfg-name'];
        model = mudFile['ietf-mud:mud']['systeminfo'];
        gitStatusOK(gitstat);
        gitStatusAppend(gitstat, ".", window.MudSafeDom.element("br"), "created ", user, "/mudfiles", window.MudSafeDom.element("br"));
        gitStatusAppend(gitstat, "Looking for/creating a branch...");
        return fetch("/gitShovel/branch",{
          method : "POST",
          body : JSON.stringify({
            mudurl: mudurl,
            mfg : mfg,
            model : model,
	          user : user
          }),
          headers :{
            "Content-type" : "application/json"
          }
        })
        .then(response=>{
          if ( typeof response != 'object') {
            gitStatusAppend(gitstat, "Failed: ", response);
            return;
          }
          return response.json();
        })
        .then(responsejson=> {
          if (typeof responsejson != 'object') {
            return responsejson;
          }
          branch_name = responsejson['branch'];
          gitStatusAppend(gitstat, window.MudSafeDom.element("br"), "Branch is called ", branch_name, ".", window.MudSafeDom.element("br"));
          let m64=b64_encode(JSON.stringify(mudFile));
          let jsonbody = {
              mudFile : m64,
              email : email,
              user : user
          }
          let pcap = sessionStorage.getItem('pcap');
          if ( pcap ) {
            jsonbody['pcap'] = pcap;
            gitStatusAppend(gitstat, "Will also include PCAP file. Uploading/creating PR...");
          }
          return fetch("/gitShovel/therest", {
            method : "POST",
            body : JSON.stringify(jsonbody),
            headers :{
              "Content-type" : "application/json"
            }
            })
          })
        }) 
      })
    .then(response => {
      if (typeof response != 'object') {
        return response;
      }
      if ( ! response.ok ) {
        return response.text();
      }
      return response.json();
    })
    .then ( jsonortext => {
      if (typeof jsonortext == "object") {
        appendPRCreated(gitstat, user);
        return;
      }
      gitStatusAppend(gitstat, jsonortext);
    }
  );
    return;
  }
  //document.getElementById("one").style.visibility = "inherit";
}
