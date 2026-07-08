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

// Read every File from <input id="pcapfile"> into sessionStorage so
// the selection survives the OAuth round-trip from mudmaker.html to
// mudpublish.html.  Stores a JSON array of {name, type, b64}.  Returns
// a Promise that resolves with the count (0 if nothing to stash).  If
// the combined size overflows sessionStorage's quota the promise
// rejects so the caller can warn the user.
function stashPcapsForPublish() {
  return new Promise(function(resolve, reject) {
    const picker = document.getElementById('pcapfile');
    if (!picker || !picker.files || picker.files.length === 0) {
      try { sessionStorage.removeItem('pcaps'); } catch (e) {}
      resolve(0);
      return;
    }
    const files = Array.from(picker.files);
    const out = new Array(files.length);
    let pending = files.length;
    files.forEach(function(f, idx) {
      const r = new FileReader();
      r.onload = function() {
        const comma = r.result.indexOf(',');
        out[idx] = {
          name: f.name,
          type: f.type || 'application/vnd.tcpdump.pcap',
          b64: comma >= 0 ? r.result.slice(comma + 1) : ''
        };
        pending -= 1;
        if (pending === 0) {
          try {
            sessionStorage.setItem('pcaps', JSON.stringify(out));
            resolve(out.length);
          } catch (e) {
            try { sessionStorage.removeItem('pcaps'); } catch (e2) {}
            reject(e);
          }
        }
      };
      r.onerror = function() { reject(r.error); };
      r.readAsDataURL(f);
    });
  });
}

function _oAuthP1Navigate(){
    const redirectURL = new URL("mudpublish.html", window.location.href);
    const redirect_uri = redirectURL.href;
    const client_id = "Ov23licSoRbhBHkeDqPJ";
    const csrfkey = new Uint8Array(16);
    // Phase 3/4: cached-token shortcut is gone.  If the browser has a
    // live session bearer, /whoami will return the login and the
    // publish flow can skip the OAuth redirect.  Otherwise fall
    // through and do a fresh OAuth dance.
    const sess = sessionStorage.getItem("mudmaker_session");
    if (sess) {
      fetch("/gitShovel/whoami", {
        method: "GET",
        headers: { "Authorization": "Bearer " + sess, "Accept": "application/json" }
      }).then(function(r) {
        if (r.ok) {
          // Already signed in; jump straight to publish page.  No
          // ``got_token`` query param is needed any more -- oAuthP2
          // detects the stored session on the destination page.
          window.location.assign(redirectURL.href);
        } else {
          // Stale bearer; clear it and fall through to OAuth.
          try { sessionStorage.removeItem("mudmaker_session"); } catch (e) {}
          _oAuthP1DoDance(client_id, redirect_uri, csrfkey);
        }
      }).catch(function() {
        try { sessionStorage.removeItem("mudmaker_session"); } catch (e) {}
        _oAuthP1DoDance(client_id, redirect_uri, csrfkey);
      });
      return;
    }
    _oAuthP1DoDance(client_id, redirect_uri, csrfkey);
}

function _oAuthP1DoDance(client_id, redirect_uri, csrfkey) {
    self.crypto.getRandomValues(csrfkey);
    const state = csrfkey.toHex();
    localStorage.setItem("latestCSRFToken", state);
    localStorage.setItem("email",document.getElementById("email_addr").value)
    const authURL = new URL("https://github.com/login/oauth/authorize");
    authURL.searchParams.set("client_id", client_id);
    authURL.searchParams.set("response_type", "code");
    // ``public_repo`` is sufficient: the publish flow only writes to a
    // fork of the public iot-onboarding/mudfiles repo.  Downgrading
    // from ``repo`` keeps the OAuth consent screen honest and closes
    // the T-01 blast radius even before the operator switches this to
    // a GitHub App proper.
    authURL.searchParams.set("scope", "public_repo");
    authURL.searchParams.set("redirect_uri", redirect_uri);
    authURL.searchParams.set("state", state);
    window.location.assign(authURL.href);
}

function oAuthP1(){
    // Stash any selected pcaps in sessionStorage before navigating to
    // GitHub for OAuth — the file input lives on mudmaker.html but
    // the publish flow resumes on mudpublish.html where the picker is
    // gone.  sessionStorage is the project's existing cross-page
    // carrier (the MUD JSON itself travels the same way).
    stashPcapsForPublish().catch(function(err) {
      console.warn("Could not stash pcaps for publish:", err);
      alert(
        "Selected PCAP files are too large to attach during publish " +
        "(browser session storage limit). Continuing without pcaps."
      );
      try { sessionStorage.removeItem('pcaps'); } catch (e) {}
    }).then(_oAuthP1Navigate);
}

function _authHeaders(extra) {
  // Return a headers object that includes the current session bearer
  // (if any) plus any caller-supplied fields.  Used by every fetch
  // that hits the gitmud API in the publish flow.
  const out = extra ? Object.assign({}, extra) : {};
  const sess = sessionStorage.getItem("mudmaker_session");
  if (sess) {
    out["Authorization"] = "Bearer " + sess;
  }
  return out;
}

function oAuthP2(){
  const myURL = new URL(window.location);
  const state = myURL.searchParams.get("state");
  const code = myURL.searchParams.get("code");
  const gitstat = document.getElementById("gitstatus");
  const mudFile = JSON.parse(sessionStorage.getItem("mudfile"));
  const mudurl = mudFile['ietf-mud:mud']['mud-url'];
  let user = '';
  let haveSession = !!sessionStorage.getItem("mudmaker_session");

  gitStatusClear(gitstat);
  gitStatusAppend(gitstat, "Authenticating...");

  // Two entry conditions:
  //   1. We arrived here from GitHub with (state, code) -- do the
  //      OAuth exchange and mint a session bearer.
  //   2. We arrived here with a live session bearer already in
  //      sessionStorage -- skip the exchange and go straight to the
  //      /whoami-driven publish flow.
  if (!haveSession && !(state != null && code != null)) {
    // Nothing to do.  Publish flow requires an OAuth completion.
    return;
  }

  const email = localStorage.getItem("email");
  let oauthPromise;
  if (haveSession) {
    // Confirm the cached bearer still resolves.
    oauthPromise = fetch("/gitShovel/whoami", {
      method: "GET",
      headers: _authHeaders({ "Accept": "application/json" })
    }).then(function(r) {
      if (!r.ok) {
        try { sessionStorage.removeItem("mudmaker_session"); } catch (e) {}
        throw new Error("stale session");
      }
      return r.json();
    });
  } else {
    // Validate the CSRF state parameter, then exchange the code.
    if (state !== localStorage.getItem("latestCSRFToken")) {
      localStorage.removeItem("latestCSRFToken");
      gitStatusFailed(gitstat);
      return;
    }
    localStorage.removeItem("latestCSRFToken");
    const jsonbody = {
      mudurl: mudurl,
      email: email,
      code: code,
      "next-redirect": "https://" + window.location.hostname
    };
    oauthPromise = fetch("/gitShovel/oAuthv2", {
      method: "POST",
      body: JSON.stringify(jsonbody),
      headers: { "Content-type": "application/json" }
    }).then(function(response) {
      if (!response.ok) {
        gitStatusFailed(gitstat);
        return response.text().then(function(t) { throw new Error(t); });
      }
      return response.json();
    }).then(function(resporjson) {
      // Store the freshly-minted session bearer for subsequent calls.
      if (resporjson && resporjson.session) {
        try {
          sessionStorage.setItem("mudmaker_session", resporjson.session);
        } catch (e) { /* quota exceeded is not fatal here */ }
      }
      return resporjson;
    });
  }

  oauthPromise.then(function(resporjson) {
    user = (resporjson && (resporjson.user || resporjson.login)) || "";
    gitStatusOK(gitstat);
    gitStatusAppend(gitstat, ".", window.MudSafeDom.element("br"),
                    "Checking/creating a repo...");
    return fetch('/gitShovel/dorepo', {
      method: "POST",
      body: JSON.stringify({ mudurl: mudurl }),
      headers: _authHeaders({ "Content-type": "application/json" })
    });
  }).then(function(response) {
    if (!response.ok) {
      gitStatusFailed(gitstat);
      throw new Error("repo check / fork failed");
    }
    return response.json();
  }).then(function(responsejson) {
    user = responsejson['user'];
    const mfg = mudFile['ietf-mud:mud']['mfg-name'];
    const model = mudFile['ietf-mud:mud']['systeminfo'];
    gitStatusOK(gitstat);
    gitStatusAppend(gitstat, ".", window.MudSafeDom.element("br"),
                    "created ", user, "/mudfiles",
                    window.MudSafeDom.element("br"));
    gitStatusAppend(gitstat, "Looking for/creating a branch...");
    return fetch("/gitShovel/branch", {
      method: "POST",
      body: JSON.stringify({
        // ``mudurl`` is kept in the body so the legacy fallback path
        // (Phase 3 transition window) can still identify the caller
        // when a browser cache serves a stale JS build with no
        // Authorization header.  ``user`` is intentionally omitted --
        // the server takes it from the session, not from the request.
        mudurl: mudurl,
        mfg: mfg,
        model: model
      }),
      headers: _authHeaders({ "Content-type": "application/json" })
    });
  }).then(function(response) {
    return response.json();
  }).then(function(responsejson) {
    const branch_name = responsejson['branch'];
    gitStatusAppend(gitstat, window.MudSafeDom.element("br"),
                    "Branch is called ", branch_name, ".",
                    window.MudSafeDom.element("br"));
    const m64 = b64_encode(JSON.stringify(mudFile));

    const fd = new FormData();
    fd.append('mudFile', m64);
    fd.append('email', email);
    let pcapCount = 0;
    try {
      const stashed = JSON.parse(sessionStorage.getItem('pcaps') || '[]');
      if (Array.isArray(stashed)) {
        stashed.forEach(function(entry) {
          if (!entry || typeof entry.b64 !== 'string' || !entry.name) {
            return;
          }
          const bin = atob(entry.b64);
          const buf = new Uint8Array(bin.length);
          for (let i = 0; i < bin.length; i++) {
            buf[i] = bin.charCodeAt(i);
          }
          const blob = new Blob([buf], {
            type: entry.type || 'application/vnd.tcpdump.pcap'
          });
          fd.append('pcap', blob, entry.name);
          pcapCount++;
        });
      }
    } catch (e) {
      console.warn("Could not decode stashed pcaps:", e);
    }
    try { sessionStorage.removeItem('pcaps'); } catch (e) {}
    try { sessionStorage.removeItem('pcap'); } catch (e) {}

    if (pcapCount > 0) {
      gitStatusAppend(gitstat, "Will also include " + pcapCount +
        " PCAP file" + (pcapCount === 1 ? "" : "s") +
        ". Uploading/creating PR...");
    } else {
      gitStatusAppend(gitstat, "Uploading MUD JSON/creating PR...");
    }
    return fetch("/gitShovel/therest", {
      method: "POST",
      // No Content-type header -- the browser sets the multipart
      // boundary automatically.
      body: fd,
      headers: _authHeaders({})
    });
  }).then(function(response) {
    if (!response.ok) {
      return response.text().then(function(t) { throw new Error(t); });
    }
    return response.json();
  }).then(function(jsonobj) {
    appendPRCreated(gitstat, user);
  }).catch(function(err) {
    gitStatusAppend(gitstat, String((err && err.message) || err || "failed"));
  });
}

// Called by the "Sign out" button on the publish tab.  Revokes the
// current session on both sides (local sessionStorage + the GitHub
// OAuth grant, via the /signout backend route).  Idempotent.
function mudmakerSignOut() {
  const sess = sessionStorage.getItem("mudmaker_session");
  const done = function() {
    try { sessionStorage.removeItem("mudmaker_session"); } catch (e) {}
    const el = document.getElementById("gitstatus");
    if (el) {
      gitStatusClear(el);
      gitStatusAppend(el, "Signed out.");
    }
  };
  if (!sess) {
    done();
    return;
  }
  fetch("/gitShovel/signout", {
    method: "POST",
    headers: { "Authorization": "Bearer " + sess }
  }).then(done, done);
}
