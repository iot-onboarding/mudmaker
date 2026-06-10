"""
App to manage oauth tokens for mud files, and to generate PRs.
"""

import json
import logging
import os
import re
import sqlite3
import base64
import configparser
from pathlib import Path
from time import sleep
from flask import Flask,request, jsonify
import requests

log = logging.getLogger("gitmud")


def _load_config():
    """
    Locate and parse the gitmud configuration file.

    Search order:
      1. $GITMUD_CONFIG (if set)
      2. /etc/gitmud/config.ini
      3. ../../config.ini relative to this module (the top of the
         gitmud subproject in a source checkout)
    """
    candidates = []
    env_path = os.environ.get("GITMUD_CONFIG")
    if env_path:
        candidates.append(Path(env_path))
    candidates.append(Path("/etc/gitmud/config.ini"))
    candidates.append(Path(__file__).resolve().parent.parent / "config.ini")

    for path in candidates:
        if path.is_file():
            parser = configparser.ConfigParser()
            parser.read(path, encoding="utf-8")
            return parser, path

    raise RuntimeError(
        "gitmud config file not found. Set GITMUD_CONFIG or install one of: "
        + ", ".join(str(p) for p in candidates)
    )


_CONFIG, _CONFIG_PATH = _load_config()

app = Flask(__name__)
app.url_map.strict_slashes = False
app.secret_key = _CONFIG["flask"]["secret_key"]

GITHUB_API_URL = _CONFIG["github"].get("api_url", "https://api.github.com")
GITHUB_CLIENT_ID = _CONFIG["github"]["client_id"]
GITHUB_SECRET_KEY = _CONFIG["github"]["client_secret"]
MUD_REPO = _CONFIG["github"].get("mud_repo", "/repos/iot-onboarding/mudfiles")

MUD_DB = _CONFIG["storage"]["db_path"]

class GithubProblem(Exception):
    """
    When soemething blows up with Github
    """


def github_dance(code):
    """
    Take a code and turn it into a bearer token.
    """
    resp= requests.request("POST",
                           "https://github.com/login/oauth/access_token",
                           json={
                               'client_id' : GITHUB_CLIENT_ID,
                               'client_secret' : GITHUB_SECRET_KEY,
                               'code' : code
                           },
                           headers = {
                               'Accept' : 'application/json'
                           },
                           timeout=10
                           )
    return resp

def db_store(gitresp,mudurl):
    """
    Remove old information, store new information for a given mud-url.
    """
    con=sqlite3.connect(MUD_DB)
    cur = con.cursor()
    auth_code = gitresp["access_token"]
    scope = gitresp["scope"]
    token_type = gitresp["token_type"]
    cur.execute("DELETE from gitmud where mudurl = ?",(mudurl,))
    cur.execute("INSERT INTO gitmud VALUES (?,?,?,?)",
                (mudurl,auth_code,scope,token_type))
    con.commit()
    return True

def token_in_db(mudurl):
    """
    Check to see if a token is indeed already stored, and return if so.
    """
    con=sqlite3.connect(MUD_DB)
    cur = con.cursor()

    cur.execute("SELECT token from gitmud where mudurl = ?",(mudurl,))
    ans = cur.fetchone()
    if not ans:
        return False
    return ans[0]


def delete_token(mudurl):
    """
    Drop any stored token for this mudurl. Used when GitHub rejects the
    cached token (revoked, expired, wrong client, etc.) so the next request
    falls through to a fresh OAuth dance.
    """
    con = sqlite3.connect(MUD_DB)
    cur = con.cursor()
    cur.execute("DELETE FROM gitmud WHERE mudurl = ?", (mudurl,))
    con.commit()


def git_get(endpoint, token, key = None):
    """
    Do a get and retrieve one or more objects.
    """
    resp = requests.request("GET",GITHUB_API_URL + endpoint,
                            headers = {
                                "Authorization" : "Bearer " + token,
                                "Accept" : "application/vnd.github+json",
                                "X-GitHub-Api-Version" : "2022-11-28"
                                },
                            timeout = 10)

    if not resp.ok:
        log.warning("git_get %s -> %s: %s",
                    endpoint, resp.status_code, resp.text[:200])
        return False
    rsp_json = resp.json()
    if key:
        if key in rsp_json:
            return rsp_json[key]
        return False
    return rsp_json

def git_putpost(which, endpoint, token, content):
    """
    Do either a git PUT or POST and return the results.
    """
    resp = requests.request(which, GITHUB_API_URL + endpoint,
                            headers = {
                                "Authorization" : "Bearer " + token,
                                "Accept" : "application/vnd.github+json",
                                "X-GitHub-Api-Version" : "2022-11-28"
                            },
                            json = content,
                            timeout = 10
                            )

    if not resp.ok:
        log.warning("git_%s %s -> %s: %s",
                    which.lower(), endpoint, resp.status_code, resp.text[:200])
        raise GithubProblem("request failed: " + resp.text)
    return resp.json()

def git_post(endpoint, token, content):
    """
    Do a POST and return the results.
    """
    return git_putpost("POST",endpoint, token,content)

def git_put(endpoint, token, content):
    """
    Do a PUT and return the results.
    """
    return git_putpost("PUT",endpoint,token,content)


def get_gituser(token):
    """
    get user information.
    """
    return git_get("/user",token,"login")

def repo_exists(user,token):
    """
    Check to see if MUD file repo already exists.
    """
    return git_get("/repos/" + user + "/mudfiles", token)

def fork_repo(token):
    """
    Fork the mudfiles repo.
    """
    return git_post(MUD_REPO + "/forks", token, {
        "name" : "mudfiles",
        "default_branch_only" : False
    })

def branch_exists(branch_name, user, token):
    """
    Check to see if a branch already exists.
    """
    return git_get("/repos/" + user + "/mudfiles/branches/" + branch_name, token)

def create_branch(branch_name,head,user,token):
    """
    Create a new branch for MUD file.
    """
    return git_post("/repos/" + user + "/mudfiles/git/refs", token,
                    {
                        "ref" : "refs/heads/" + branch_name,
                        "sha" : head
                    })

def existing_file(user, branch, filename, token):
    """
    return the SHA of the file if it exists, or False
    """
    resp= git_get("/repos/" + user + "/mudfiles/contents/" + filename + "?ref=" + branch, token)
    if resp:
        return resp['sha']
    return False


def upload_file(upload):
    """
    Generic upload.  Takes an upload struct of the form:
    {
        branch_name :
        user :
        filename : 
        content :
        email : 
        token :
    }
    """

    branch_name=upload["branch_name"]
    filename = upload['filename']
    user = upload['user']
    email = upload['email']
    token = upload['token']
    content = upload['content']
    jsonbody = {
        "message" : "add " + filename + " to repo",
        "committer[name]" : user,
        "committer[email]" : email,
        "branch" : branch_name,
        "content" : content
    }
    sha = existing_file(user, branch_name, filename, token)
    if sha:
        jsonbody['sha'] = sha

    return git_put("/repos/" + user + "/mudfiles/contents/" + filename,
                token,
                jsonbody
                )

def pr_exists(user, branch_name, token):
    """
    Checks the existence of a PR.
    """
    return git_get(MUD_REPO + f'/pulls?head={user}:{branch_name}',token)


def create_pr(branch_name,token, user, mfg, model):
    """
    Generate a PR
    """
    return git_post(MUD_REPO + "/pulls",token, {
        "title" : "Proposed MUD file for a " + mfg + " " + model,
        "head" : user + ":" + branch_name,
        "body" : "This PR was generated by the gitmud tool",
        "base" : "main"
    }
    )

@app.route('/gottoken',methods=['GET'])
def got_token():
    """
    return a yes/no answer.  Takes argument "mudurl".
    """
    mudurl=request.args.get("mudurl")
    if token_in_db(mudurl):
        return jsonify({"answer" : "yes"}), 200
    return jsonify({"answer" : "no"}), 400


def _exchange_code(code, mudurl):
    """
    Run the GitHub OAuth code-for-token exchange, store the result, and
    return (token, error_response). On success error_response is None; on
    failure token is None and error_response is a (body, status) tuple
    suitable for returning directly from a Flask view.
    """
    resp = github_dance(code)
    if not resp.ok:
        return None, ("github_dance: " + resp.text, 400)
    response_json = resp.json()
    if 'error' in response_json:
        return None, ("github_dance: error " + response_json['error'], 400)
    if 'access_token' not in response_json or not response_json['access_token']:
        return None, ("github_dance: no access_token in response", 400)
    if not db_store(response_json, mudurl):
        return None, ("db_store fail", 500)
    return response_json["access_token"], None


@app.route('/oAuthv2',methods=['POST'])
def complete_oauth():
    """
    Just complete the oauth transaction.  Takes as input:
       mudFile (b64) and one of:
        token: a token to commplete OAUTH
        OR
        got_token, signalling that no github dance is required.
    Returns: 200/400/401
    """
    req=request.json

    try:
        mudurl = req['mudurl']
        code = None
        if "got_token" not in req:
            code = req["code"]
    except KeyError as e:
        return 'KeyError: ' + str(e), 400

    token = token_in_db(mudurl)
    user = get_gituser(token) if token else False

    if not user:
        # Either no row, or the cached token no longer works (revoked,
        # expired, or minted by a different OAuth app). Drop it and try a
        # fresh dance if the client supplied a fresh code.
        if token:
            log.info("stored token for %s rejected by GitHub; evicting", mudurl)
            delete_token(mudurl)
        if not code:
            return "no valid token and no code to exchange", 401
        token, err = _exchange_code(code, mudurl)
        if err:
            return err
        user = get_gituser(token)
        if not user:
            # Token came back from GitHub but won't authenticate /user.
            # Don't keep it.
            log.warning("freshly minted token for %s failed /user lookup", mudurl)
            delete_token(mudurl)
            return "github token did not authenticate", 401

    return jsonify({"user" : user}), 200

@app.route("/dorepo",methods=['POST'])
def do_repo():
    """
    Fork the repo if it doesn't exist.
    """
    req=request.json

    try:
        mudurl=req['mudurl']
    except KeyError as e:
        return "Repo Check: Bad Parameter: " + str(e), 400

    token = token_in_db(mudurl)
    if not token:
        return "not authenticated", 401
    user = get_gituser(token)
    if not user:
        log.info("do_repo: stored token for %s rejected; evicting", mudurl)
        delete_token(mudurl)
        return "github token did not authenticate", 401
    resp = repo_exists(user,token)
    if not resp:
        resp = fork_repo(token)
        if not resp:
            return "fork failed", 400
        # give github a chance to create the fork.
        resp = repo_exists(user,token)
        loop = 0
        while not repo_exists(user,token) and loop < 5:
            loop=loop + 1
            sleep(3)
    # even when the repo claims to exist, it might not yet.  Give a few
    # more seconds.
    sleep(3)
    return jsonify({"user" : user}), 200


@app.route("/branch",methods=['POST'])
def do_branch():
    """
    Handle branching.
    """
    req=request.json
    try:
        mudurl = req['mudurl']
        mfg = req["mfg"]
        model = req["model"]
        user = req["user"]

    except KeyError as e:
        return "Parameter problem: " + str(e), 400

    token = token_in_db(mudurl)
    if not token:
        return "not authenticated", 401
    # Confirm the caller-supplied user matches the token holder; otherwise
    # an attacker who knows a mudurl could direct writes to an arbitrary
    # account name.
    token_user = get_gituser(token)
    if not token_user:
        log.info("do_branch: stored token for %s rejected; evicting", mudurl)
        delete_token(mudurl)
        return "github token did not authenticate", 401
    if token_user != user:
        return "user does not match token", 403
    # capture head
    ref_obj  = git_get("/repos/" + user + "/mudfiles/git/refs/heads/main",
                    token, "object")
    if not ref_obj:
        return "could not read repo head", 400
    head = ref_obj['sha']
    # branch name
    mfg = re.sub(' ','-',mfg)
    model = re.sub(' ','-',model)
    branch_name = mfg +  "-" + model

    # check if branch exists, and create it if it does not.
    if not branch_exists(branch_name, user, token):
        try:
            resp=create_branch(branch_name, head, user, token)
            if not resp:
                return "failed to create branch", 400
        except GithubProblem as e:
            return str(e), 400

    return jsonify({"branch" : branch_name}), 200

@app.route("/therest",methods=['POST'])
def do_the_rest():
    """
    Branch and PR code.
    """
    req=request.json
    pcap= None
    try:
        mud64 = req["mudFile"]
        email = req["email"]
        user = req["user"]
        mud = json.loads(base64.b64decode(mud64))
        mudurl = mud["ietf-mud:mud"]["mud-url"]
        if 'pcap' in req:
            pcap = req['pcap']

    except KeyError as e:
        return "Parameter problem: " + str(e), 400

    token = token_in_db(mudurl)
    if not token:
        return "not authenticated", 401
    token_user = get_gituser(token)
    if not token_user:
        log.info("do_the_rest: stored token for %s rejected; evicting", mudurl)
        delete_token(mudurl)
        return "github token did not authenticate", 401
    if token_user != user:
        return "user does not match token", 403

    # branch name
    mfg = re.sub(' ','-',mud["ietf-mud:mud"]["mfg-name"])
    model = re.sub(' ','-',mud["ietf-mud:mud"]["systeminfo"])
    branch_name = mfg +  "-" + model
    # upload b64 file
    try:
        upload = {
                "branch_name" : branch_name,
                "user" : user,
                "filename" : mfg + "/" + model + ".json",
                "content" : mud64,
                "email" :    email,
                "token" : token
        }
        resp = upload_file(upload)
        if not resp:
            return "upload failed", 400
        if pcap:
            upload["filename"]  = mfg + "/" + model + ".pcap"
            upload["content"] = pcap
            resp = upload_file(upload)
            if not resp:
                return "PCAP upload failed."

    except GithubProblem as e:
        return str(e), 400

    # create the PR only if the branch doesn't already exist
    resp =  pr_exists(user,branch_name,token)
    if not resp:
        resp = create_pr(branch_name,token, user, mfg, model)
        if not resp:
            return "PR failed", 400

    return {
        "mfg" : mfg,
        "model" : model,
        "user" : user,
        "mudurl" : mudurl
    }, 200


#       return redirect("mudpublish.html?stored=ok")
#    return redirect("mudbad.html")

# if __name__ == '__main__':
#    app.run(debug=False, port=5000)
