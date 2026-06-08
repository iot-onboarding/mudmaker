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

// This code adopted from Allen Liu on Random Snippets
// http://www.randomsnippets.com/2008/02/21/how-to-dynamically-add-form-elements-via-javascript/
 

var nref = [ 0, 0, 0, 0 ];
var prev_sbom = 'none';
var limit = 50;

function normalizeDirection(direction) {
	if (direction == 'thing') {
		return 'from-device';
	}
	if (direction == 'remote') {
		return 'to-device';
	}
	return direction;
}

function normalizePort(port) {
	var parsed = Number(port);
	if (!Number.isInteger(parsed) || parsed < 0 || parsed > 65535) {
		return null;
	}
	return parsed;
}

function normalizePortMatch(match) {
	if (typeof match == 'undefined' || typeof match.port == 'undefined') {
		return;
	}
	var port = normalizePort(match.port);
	if (port != null) {
		match.port = port;
	}
}

function canonicalValue(value) {
	var normalized = {};

	if (Array.isArray(value)) {
		return value.map(canonicalValue);
	}
	if (value != null && typeof value == 'object') {
		Object.keys(value).sort().forEach(function(key) {
			normalized[key] = canonicalValue(value[key]);
		});
		return normalized;
	}
	return value;
}

function aceSemanticKey(ace) {
	return JSON.stringify({
		matches: canonicalValue(ace && ace.matches || {}),
		actions: canonicalValue(ace && ace.actions || {})
	});
}

function removeDuplicateAces(acl) {
	var seen = {};

	if (typeof acl == 'undefined' ||
		typeof acl.aces == 'undefined' ||
		!Array.isArray(acl.aces.ace)) {
		return;
	}
	acl.aces.ace = acl.aces.ace.filter(function(ace) {
		var key = aceSemanticKey(ace);

		if (seen[key]) {
			return false;
		}
		seen[key] = true;
		return true;
	});
}

function normalizeAcls(acls) {
	if (typeof acls == 'undefined' || !Array.isArray(acls.acl)) {
		return;
	}
	acls.acl.forEach(function(acl) {
		if (typeof acl.aces == 'undefined' || !Array.isArray(acl.aces.ace)) {
			return;
		}
		acl.aces.ace.forEach(function(ace) {
			var matches = ace.matches || {};
			['tcp', 'udp'].forEach(function(proto) {
				if (typeof matches[proto] == 'undefined') {
					return;
				}
				normalizePortMatch(matches[proto]['source-port']);
				normalizePortMatch(matches[proto]['destination-port']);
			});
			if (typeof matches.tcp != 'undefined' &&
				typeof matches.tcp['ietf-mud:direction-initiated'] != 'undefined') {
				matches.tcp['ietf-mud:direction-initiated'] =
					normalizeDirection(matches.tcp['ietf-mud:direction-initiated']);
			}
		});
		removeDuplicateAces(acl);
	});
}

function addMudExtension(mudFile, extension) {
	if (typeof mudFile == 'undefined' ||
		typeof mudFile['ietf-mud:mud'] == 'undefined') {
		return;
	}
	var mud = mudFile['ietf-mud:mud'];
	if (!Array.isArray(mud['extensions'])) {
		mud['extensions'] = [];
	}
	if (!mud['extensions'].includes(extension)) {
		mud['extensions'].push(extension);
	}
}

function ensureOlExtension(mudFile) {
	if (typeof mudFile == 'undefined' ||
		typeof mudFile['ietf-mud:mud'] == 'undefined') {
		return;
	}
	var mud = mudFile['ietf-mud:mud'];
	addMudExtension(mudFile, 'ol');
	if (typeof mud['ol'] == 'undefined') {
		mud['ol'] = {};
	}
	if (typeof mud['ol']['spdx-tag'] == 'undefined') {
		mud['ol']['spdx-tag'] = '0BSD';
	}
}

function setOlOwner(owner) {
	if (typeof owner == 'undefined' || owner == '') {
		return;
	}
	ensureOlExtension(document.mudFile);
	document.mudFile['ietf-mud:mud']['ol']['owners'] = [ owner ];
}

function syncOlOwnerFromForm() {
	var publisher = document.getElementById('pub_name');
	if (publisher != null && publisher.value != '') {
		setOlOwner(publisher.value);
	}
}

function normalizeMUDFile(mudFile) {
	if (typeof mudFile == 'undefined' ||
		typeof mudFile['ietf-mud:mud'] == 'undefined') {
		return mudFile;
	}
	var mud = mudFile['ietf-mud:mud'];
	ensureOlExtension(mudFile);
	if (typeof mud['last-update'] == 'undefined' &&
		typeof mud['last-change'] != 'undefined') {
		mud['last-update'] = mud['last-change'];
	}
	delete mud['last-change'];
	if (typeof mud['ietf-access-control-list:acls'] != 'undefined') {
		if (typeof mudFile['ietf-access-control-list:acls'] == 'undefined') {
			mudFile['ietf-access-control-list:acls'] = mud['ietf-access-control-list:acls'];
		}
		delete mud['ietf-access-control-list:acls'];
	}
	normalizeAcls(mudFile['ietf-access-control-list:acls']);
	return mudFile;
}

function getAcls() {
	normalizeMUDFile(document.mudFile);
	return document.mudFile['ietf-access-control-list:acls'];
}

function ensureAcls() {
	normalizeMUDFile(document.mudFile);
	if (typeof document.mudFile['ietf-access-control-list:acls'] == 'undefined') {
		document.mudFile['ietf-access-control-list:acls'] = {"acl": []};
	}
	return document.mudFile['ietf-access-control-list:acls'];
}

function mudFileHasAcls(mudFile) {
	var aclContainer;

	normalizeMUDFile(mudFile);
	aclContainer = mudFile && mudFile['ietf-access-control-list:acls'];
	return typeof aclContainer != 'undefined' &&
		Array.isArray(aclContainer.acl) &&
		aclContainer.acl.length > 0;
}

function restoreAclBaseFromMUDFile() {
	if (!mudFileHasAcls(document.mudFile)) {
		return false;
	}
	document.aclBase = document.aclBase || 'loaded';
	return true;
}

function resetAclBaseFromMUDFile() {
	delete document.aclBase;
	return restoreAclBaseFromMUDFile();
}

function updateLastUpdate(mudFile) {
	mudFile['ietf-mud:mud']['last-update'] = new Date().toISOString();
	delete mudFile['ietf-mud:mud']['last-change'];
}

function initMUDFile() {
	delete document.aclBase;
	document.mudFile=window.sessionStorage.getItem("mudfile");
	if ( document.mudFile == null ) {
		document.mudFile = JSON.parse('{"ietf-mud:mud" : {"mud-version" : 1, "extensions" : [ "ol"], "ol" : { "spdx-tag" : "0BSD"}, "cache-validity": 48, "is-supported" : true}}');
		updateLastUpdate(document.mudFile);
		window.sessionStorage.setItem('mudfile',JSON.stringify(document.mudFile));
	} else {
		document.mudFile=JSON.parse(document.mudFile);
		normalizeMUDFile(document.mudFile);
	}
	restoreAclBaseFromMUDFile();
}

function mudUrlPartsFromMudUrl(mudUrl) {
	var matchres;

	if (typeof mudUrl == 'undefined' || mudUrl == '') {
		return null;
	}
	matchres = String(mudUrl).match(/^https:\/\/([^\/]+)\/(.+)\.json$/);
	if (matchres == null) {
		return null;
	}
	return {
		hostname: matchres[1],
		model_name: matchres[2]
	};
}

function updateMudUrlPreview(host, model, fallbackUrl) {
	var preview = document.getElementById('mud-url-preview');

	if (preview == null) {
		return;
	}
	if (host != '' && model != '') {
		preview.textContent = 'https://' + host + '/' + model + '.json';
	} else if (typeof fallbackUrl != 'undefined' && fallbackUrl != '') {
		preview.textContent = fallbackUrl;
	} else {
	    preview.textContent = 'Your device in the network';
	}
}

function syncMudUrlPreviewFromForm() {
	var mh = document.getElementById('mudhost');
	var mm = document.getElementById('model_name');

	updateMudUrlPreview(mh != null ? mh.value : '', mm != null ? mm.value : '');
}

function syncMudUrlPreviewFromMudFile() {
	var mf;
	var parts;

	if (typeof document.mudFile == 'undefined' ||
		typeof document.mudFile['ietf-mud:mud'] == 'undefined') {
		syncMudUrlPreviewFromForm();
		return;
	}
	mf = document.mudFile['ietf-mud:mud'];
	parts = mudUrlPartsFromMudUrl(mf['mud-url']);
	if (parts != null) {
		document.getElementById('mudhost').value = parts.hostname;
		document.getElementById('model_name').value = parts.model_name;
		updateMudUrlPreview(parts.hostname, parts.model_name);
	} else {
		updateMudUrlPreview('', '', mf['mud-url']);
	}
}


function resetSite() {
	window.sessionStorage.clear();
	delete document.mudFile;
	delete document.aclBase;
	initMUDFile();
	clearAclUI();
	[ "sbomany", "sbcloud", "sblocal", "sbtel", "sbinfourl","vulnview"].forEach((field) => {
		document.getElementById(field).style.display='none';
	});
	document.getElementById('loadsaved').value = null;
	Array.from(document.getElementsByTagName("details")).forEach((det) => {
		det.open = false;
	});
	document.getElementById('mudform').reset();
	updateMudUrlPreview('', '');
}

// js update
function addEntry(entry){
    var newdiv= document.createElement('div');
	var typefield;
	var pattern;
	var hidden;
	var any;
	var placeholder;
	var fieldinfo;
	var dnsorurl='';
	var entryType = entry.id;
	var fieldName = {
		'cl': 'ietf-acldns:src-dnsname',
		'myctl': 'my-controller',
		'loc': 'local-networks',
		'ctl': 'controller',
		'mymfg': 'same-manufacturer',
		'mfg': 'manufacturer'
	}[entryType] || entryType + 'name';
	
	if (entry.id == 'cl' || entry.id == 'mfg') {
		dnsorurl = 'dns';
	} else if (entry.id == 'ctl') {
		dnsorurl = 'url';
	}


	if ( dnsorurl == 'dns' ) {
	    typefield="'text'";
	    pattern = " pattern='[a-z0-9.-]+\.[a-z]{2,3}$'";
	    readonly=0;
	    placeholder=" placeholder='hostname.manufacturer.com'";
	} else if ( dnsorurl == 'url' ) {
	    typefield="'url'";
	    pattern = "";
	    placeholder=" placeholder='https://class name..'";
	    readonly=0;
	} else {
	    typefield="'text'";
	    pattern="";
	    placeholder="";
	    readonly=1;
	}

	if ( entryType == 'loc' ) {
        hidden="' style='visibility: hidden'";
	    pattern = " ";
	    fieldinfo = 'readonly="" value="any" ';
	} else {
	    if ( entryType == 'myctl' ) {
	    hidden ="' style='visibility: hidden' ";
	    pattern = " ";
	    fieldinfo = 'readonly="" value="(filled in by local admin)" ';
	    } else { 
		if (entryType == 'mymfg' ) {
		    hidden ="' style='visibility: inherit' ";
		    pattern = " ";
		    fieldinfo = 'readonly="" value="(filled in by system)" ';
		}
		 else {
		     hidden="' style='visibility: hidden'";
		     fieldinfo="maxlength='255'";
		 }
	    }
	}

        newdiv.innerHTML = 
            "<input type=" + typefield + " name='" + fieldName + "'" + pattern +
	    " size='40' " + placeholder + fieldinfo + ">&nbsp;&nbsp;&nbsp;" +
	    " Protocol&nbsp;&nbsp;<select class='proto' name='proto'>" +
	    "<option value='any'>Any</option>" +
	    "<option value='tcp'>TCP</option>" +
	    "<option value='udp'>UDP</option>" +
	    "</select>" + "&nbsp;<input type='button' class='delete' value='-'><br>" +
	    "<span class='portinfo' style='visibility: hidden'>"
	    + "&nbsp;&nbsp;&nbsp;" + 
	    "Local Port&nbsp; <input pattern='([0-9]{1,5}|any)' value='any' " +
	    "class='lport' style='width:60px'>" 
	    + "&nbsp;&nbsp;&nbsp;" + 
	    "Remote Port&nbsp; <input pattern='([0-9]{1,5}|any)' value='any' " +
	    "class='rport' style='width:60px'></span>" +
	    "<span class='coninit' style='visibility: hidden'>"
	    + "&nbsp;&nbsp;&nbsp;" + 
	    "Initiated by&nbsp; <select "  + 'name="direction" value="any">' +
	    "<option value='either'>Either</option>" +
	    "<option value='from-device'>Thing</option>" +
	    "<option value='to-device'>Remote</option>" +
	    "</select></span>";

        entry.appendChild(newdiv);
}

// js update
function tcporudp(papa,val) {
	var ports=papa.children[4];
	var dir=papa.children[5];
    if (val == 'any') {
	ports.style.visibility='hidden';
	dir.style.visibility='hidden';
    } else {
	ports.style.visibility='inherit';
	if (val == 'udp' ) {
	    ports.style.visibility='inherit';
	    dir.style.visibility='hidden';
	} else {
	   dir.style.visibility='inherit';
	   ports.style.visibility='inherit';
	}
    }
}

// js update
function fillpub(cur) {
    var p=document.getElementById('pub_name');
    if (p.value == '') {
		p.value = cur.value;
    }
	setOlOwner(p.value);
}

// js update
function saveMUD() {
	normalizeMUDFile(document.mudFile);
	syncOlOwnerFromForm();
	updateLastUpdate(document.mudFile);
	window.sessionStorage.setItem('mudfile',JSON.stringify(document.mudFile));
}

function savework(){
	normalizeMUDFile(document.mudFile);
	syncOlOwnerFromForm();
	var toSave = structuredClone(document.mudFile);

	var dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(toSave));
	var dlAnchorElem = document.getElementById('downloadAnchorElem');
	var model_name = document.getElementById('model_name').value;
	if ( model_name == ''){
		alert("Please first set your model name");
		return;
	}
	dlAnchorElem.setAttribute("href", dataStr);
	dlAnchorElem.setAttribute("download", model_name + '.json');
	dlAnchorElem.click();
}


function getSignedMUDfile(){
	let country = document.getElementById('country').value;
	let email = (document.getElementById('email_addr').value || '').trim();
	let mfgr = (document.getElementById('mfg-name').value || '').trim();
	let model = (document.getElementById('model_name').value || '').trim();
	normalizeMUDFile(document.mudFile);
	syncOlOwnerFromForm();
	let mudb64 = b64_encode(JSON.stringify(document.mudFile,null,2));

	if ( country == '0' || email == '' || mfgr == '' || model == '' ||
		!document.mudFile['ietf-mud:mud']['mud-url'] ) {
		alert("Manufacturer Name, Model, Country, Email must all be set to retrieve a signed MUD file");
		return;
	}
	let pinfo = {
		"Manufacturer" : mfgr,
		"Model" : model,
		"CountryCode" : country,
		"MudUrl" : document.mudFile['ietf-mud:mud']['mud-url'],
		'SerialNumber' : "Demo12345",
		"Mudfile" : mudb64,
		"EmailAddress" : email
	};
	const request = new Request("/mudzip", {
		method: "POST",
		body: JSON.stringify(pinfo),
		headers: {
			"Content-type" : "application/json",
			"Accept" : "application/zip"
		}
	})
	fetch(request)
		.then(response => {
			if (! response.ok ) {
				throw new Error("bad answer");
			}
			return response.blob();
		})
		.then(zipdata => {
			var url = URL.createObjectURL(zipdata),
				dlAnchorElem = document.getElementById('downloadZip');
			dlAnchorElem.setAttribute("href", url);
			dlAnchorElem.setAttribute("download", model + ".zip");
			dlAnchorElem.click();
		})
}

function clearAclUI(){
	Array.from(document.getElementsByClassName("addable")).forEach(function(aclgroup){
		if (aclgroup.children.length > 2) {
			let nchild = aclgroup.children.length;
			for (let i = 2; i< nchild; i++) {
				aclgroup.children[2].remove();
			}
		}
		var thegroup = aclgroup.children[1];
		if (thegroup.children[0].readOnly != true ) {
			thegroup.children[0].value=null;
		}
		if (typeof thegroup['aceBase'] != 'undefined') {
			delete thegroup['aceBase'];
		}
		thegroup.children[1].value = 'any'; // protocol
		thegroup.children[4].children[0].value = 'any'; // lport
		thegroup.children[4].children[1].value = 'any'; // rport
		thegroup.children[4].style.visibility = 'hidden';
		thegroup.children[5].children[0].value = 'either';
		thegroup.children[5].style.visibility = 'hidden';
		aclgroup.open = false;
	})
}


function findNextAce(aceType){
	let block=document.getElementById(aceType);
	if (typeof block.children[1]['aceBase'] == 'undefined') {
		return block.children[1];
	}
	addEntry(block);
	return block.children[block.children.length-1];
}

function setProto(nextAce,ace,ipVer) {
	var pstring;
	var p1;
	var p0;
	const re = /^(..).+/;
	const matches = ace['matches'];

	let tofro = ace.name.match(re)[1];

	if ( typeof matches[ipVer] == 'undefined') {
		return;
	}
	if ( typeof matches[ipVer]['protocol'] == 'undefined' ) {
		return;
	}
	nextAce.children[1].value = matches[ipVer]['protocol'];
	let proto = nextAce.children[4];
	proto.style.visibility = 'inherit';
	if ( matches[ipVer]['protocol'] == 6 ){
		let cominit = nextAce.children[5];
		cominit.style.visibility = "inherit";
		pstring = 'tcp';
		nextAce.children[1].value='tcp';
		if (typeof matches['tcp'] != 'undefined' &&
			typeof matches['tcp']["ietf-mud:direction-initiated"] != 'undefined') {
			cominit.children[0].value = matches['tcp']["ietf-mud:direction-initiated"];
		}
	} else if ( matches[ipVer]['protocol'] == 17 ){
		pstring = 'udp';
		nextAce.children[1].value = 'udp';
	} else {
		return;
	}
	if ( tofro == 'to' ) {
		p1 = 1;
		p0 = 0;
	} else {
		p1 = 0;
		p0 = 1;
	}
	if (typeof matches[pstring] != 'undefined' &&
		typeof matches[pstring]['source-port'] != 'undefined') {
		proto.children[p1].value = matches[pstring]['source-port']['port'];
	}
	if (typeof matches[pstring] != 'undefined' &&
		typeof matches[pstring]['destination-port'] != 'undefined') {
		proto.children[p0].value = matches[pstring]['destination-port']['port'];
	}
}

function reloadFields(){
	normalizeMUDFile(document.mudFile);
	resetAclBaseFromMUDFile();
	var mf = document.mudFile['ietf-mud:mud'];
	const inbasic = ['mfg-name', 'systeminfo', 'documentation'];
	document.getElementById('country').value=document.mudFile['country'] || 0;
	delete document.mudFile['country'];
	document.getElementById('email_addr').value=document.mudFile['email_addr'] || '';
	delete document.mudFile['email_addr'];
	document.getElementById('sbom').value = document.mudFile['sbomtype'] || 'none';
	var sbomtype = document.mudFile['sbomtype'] || 'none';
	delete document.mudFile['sbomtype'];
	var sbomcc = document.mudFile['sbomcc'] || '';
	var sbomnr = document.mudFile['sbomnr'] || '';
	delete document.mudFile['sbomcc'];
	delete document.mudFile['sbomnr'];

	inbasic.forEach(function(item){
		if (typeof mf[item] != 'undefined') {
			document.getElementById(item).value = mf[item];
		}
	});
	if (typeof mf['ol'] != 'undefined' && typeof mf['ol']['owners'] != 'undefined') {
		document.getElementById('pub_name').value = mf['ol']['owners'][0];
	}
	if ( typeof mf['mud-url'] != 'undefined') {
		syncMudUrlPreviewFromMudFile();
	} else {
		syncMudUrlPreviewFromForm();
	}
	if (Array.isArray(mf['extensions']) && mf['extensions'].includes('transparency')){
		var tx= mf['mudtx:transparency'];
		if (sbomtype == 'local') {
			document.getElementById('sbom-local-well-known').value=tx['sbom-local-well-known'];
		} else if ( sbomtype == 'infourl' ){
			document.getElementById(sbomtype).value = tx['contact-info'];
		} else if ( sbomtype == 'tel' ) {
			// stuffed this stuff in the json file for safe keeping as well
			document.getElementById('sbomcc').value = sbomcc;
			document.getElementById('sbomnr').value = sbomnr;
		} else if ( sbomtype == 'cloud' ) {
			document.getElementById('sbomcloudurl').value = tx['sboms'][0]['sbom-url'];
			document.getElementById('sbomswver').value = tx['sboms'][0]['version-info'];
		}
		
		if ( typeof tx['vuln-url'] != 'undefined') {
			document.getElementById('vulntype').value = 'url';
			document.getElementById('vuln-url').value = tx['vuln-url'];
			document.getElementById('vulnview').style.display='inherit';
		}
		setVisibility(document.getElementById('sbom'));
	}
	clearAclUI();
	var acls = getAcls();
	if (typeof acls != 'undefined'){
		// we only need to look at one ACL/one set of ACEs.
		acls.acl[0].aces.ace.forEach(
			function(ace){
				mudtypes = {
					'myctl' : 'my-controller',
					'mymfg' : 'same-manufacturer',
					'ctl' : 'controller',
					'loc' : 'local-networks'
				}

				var nextAce;
				let ipVer = null;
				// get aceBase value
				let re = /^..(ace.*)/;
				let aceBase = ace.name.match(re)[1];
				// figure out type and then proceed.
				if (typeof ace['matches']["ipv4"] != 'undefined') {
					ipVer = 'ipv4';
				} else if (typeof ace['matches']["ipv6"] != 'undefined') {
					ipVer = 'ipv6';
				}
				if (typeof ace['matches']["ietf-mud:mud"] != 'undefined'){
					for (let val in mudtypes ) {
						if ( typeof ace['matches']["ietf-mud:mud"][mudtypes[val]] != 'undefined') {
							document.getElementById(val).open = true;
							nextAce = findNextAce(val);
							if (! nextAce.children[0].readOnly) {
								nextAce.children[0].value = ace['matches']["ietf-mud:mud"][mudtypes[val]];
							}
						}
					}
				} else {
					var hostname;
					nextAce=findNextAce('cl');
					if(typeof ace['matches'][ipVer]['ietf-acldns:src-dnsname'] != 'undefined') {
						hostname = ace['matches'][ipVer]['ietf-acldns:src-dnsname'];
					} else {
						hostname =  ace['matches'][ipVer]['ietf-acldns:dst-dnsname'];
					}
					nextAce.children[0].value = hostname;
				}
				nextAce.aceBase = aceBase;
				nextAce.parentElement.open = true;
				setProto(nextAce,ace,ipVer);
				})
	}
}

 // js update
 function loadPCAP(input) {
	let file = input.files[0];
	let reader = new FileReader();

	reader.readAsDataURL(file);
	reader.onload = function () {
		let pcap = reader.result;
		re= /.*,/;
		sessionStorage.setItem('pcap',pcap.replace(re,''));
	}
 }


// js update
function makemudurl() {
    p=document.getElementById('controller');
    mh=document.getElementById('mudhost');
	mm=document.getElementById('model_name');
	updateMudUrlPreview(mh.value, mm.value);
    if (mh.value != '') {
		p.placeholder = 'https://' + mh.value + '/controllers';
		if (mm.value != '') {
			var mudurlbits = 'https://' + mh.value + '/' + mm.value;
			document.mudFile['ietf-mud:mud']['mud-url'] = mudurlbits + '.json';
			document.mudFile['ietf-mud:mud']['mud-signature'] = mudurlbits + '.p7s';
			saveMUD();
		}
    }
}

function setvulnvis(v) {
    var me=document.getElementById('vulntype');
    if ( me.value != 'none' ) {
	v.style.display='inherit';
    } else {
	v.style.display='none';
	v.value='';
    }
}

function setVisibility(outer) {
	if ( outer.value == prev_sbom ) {
		return; // nothing changed?!
	}

    if (outer.value != 'none') {
		var elid='sb' + outer.value;
		document.getElementById('sbomany').style.display= 'inherit';
		document.getElementById(elid).style.display= 'inline-block';
		if (prev_sbom != 'none') {
			document.getElementById(sb+prev_sbom).style.display= 'none';
		}
    } else {
		document.getElementById('sbomany').style.display= 'none';
		delete document.mudFile['mudtx:transparency'];
    	document.getElementById('sbomswver').value='';
		document.getElementById('sbomcloudurl').value='';
    	document.getElementById('sbomcc').value='';
    	document.getElementById('sbomnr').value='';
    	document.getElementById('sbinfourl').value='';
		saveMUD();
    }
}
// js update
function addbasics(cur) {
	if ( cur.value == '') {
		delete document.mudFile['ietf-mud:mud'][cur.name];
	} else {
		if ( cur.validity.valid == false ) {
			return;
		}
		document.mudFile['ietf-mud:mud'][cur.name] = cur.value;
		if (cur.name == 'mfg-name') {
			fillpub(cur);
		}
	}
	saveMUD();
}

function makeAcl(name,atype){
	ensureAcls()['acl'].push({ "name" : name, "type" : atype + "-acl-type", "aces" : { "ace": []}});
}

function makeAcls(){
	var mud = document.mudFile['ietf-mud:mud'];
	var acltype= document.getElementById("ipchoice").value;
	var bn;
	var toacls;
	var fracls;

	if (typeof document.aclBase != 'undefined') {
		return;
	}
	if (restoreAclBaseFromMUDFile()) {
		return;
	}
	document.mudFile["ietf-access-control-list:acls"] = {"acl": []};

	document.aclBase= 'acl' + Math.floor(Math.random()*100000);
	bn = document.aclBase;
	mud['from-device-policy'] = {
		"access-lists" : {"access-list" : []}
	};
	mud['to-device-policy'] = {
		"access-lists" : {"access-list" : []}
	};
	toacls=mud['to-device-policy']['access-lists']["access-list"];
	fracls=mud['from-device-policy']['access-lists']["access-list"];
	if ( acltype == 'ipv4' || acltype == 'both') {
		toacls.push({'name' : 'toipv4-' + bn});
		makeAcl('toipv4-' + bn, "ipv4");
		fracls.push({'name' : 'fripv4-' + bn});
		makeAcl('fripv4-' + bn, "ipv4");
	}
	if ( acltype == 'ipv6' || acltype == 'both') {
		toacls.push({'name' : 'toipv6-' + bn});
		makeAcl('toipv6-' + bn, "ipv6");
		fracls.push({'name' : 'fripv6-' + bn});
		makeAcl('fripv6-' + bn, "ipv6");
	}
}

function makeproto(acl_entry,proto,sport,dport,cominit){
	var ret = {};
	var hasval = false;



	if (proto === 'tcp' && cominit != 'either'){
		ret['ietf-mud:direction-initiated'] = normalizeDirection(cominit);
		hasval = true;
	}

	if ( sport != "any" ) {
		var sportNum = normalizePort(sport);
		if (sportNum != null) {
			ret['source-port'] = {
				"operator" : "eq",
				"port" : sportNum
			};
			hasval = true;
		}
	}
	if (dport != "any") {
		var dportNum = normalizePort(dport);
		if (dportNum != null) {
			ret['destination-port'] = {
				"operator" : "eq",
				"port" : dportNum
			};
			hasval= true;
		}
	}
	if (hasval) {
		return ret;	
	}
	return null;
}

function updateAce(acl,ace_entry,aceBase,p){
	// distinguish between to and from.  just means choosing src or dst fields; also for transport.
	const actions = { "forwarding" : "accept"};
	const re=/^fr.*/;
	var direction;
	var ace_name;
	var matchname;
	var matchobj;
	var p;
	var proto;
	var lport;
	var rport;
	var ace;
	var aIndex;
	var mudMatchNames = {
		'myctl': 'my-controller',
		'loc': 'local-networks',
		'ctl': 'controller',
		'mymfg': 'same-manufacturer',
		'mfg': 'manufacturer'
	};
	var mudMatchName = mudMatchNames[p.id] || ace_entry.children[0].name;

	if (acl["type"] == "ipv4-acl-type"){
		ipver = "ipv4";
	} else {
		ipver = "ipv6";
	}

	if (acl.name.match(re) == null) {
		direction='to';
		ace_name = 'to' + aceBase;
	} else {
		direction='from';
		ace_name = 'fr' + aceBase;
	}

	if ( p.id == 'cl') {
		if ( direction == 'to') {
			matchname = 'ietf-acldns:src-dnsname';
		} else {
			matchname = 'ietf-acldns:dst-dnsname';
		}
		matchobj=JSON.parse('{"' + ipver + '": {"' + matchname + '":"' +
			ace_entry.children[0].value + '"}}');
	} else {
		matchobj = {
			"ietf-mud:mud" : {
			}
		}
		if (p.id == 'myctl' || p.id == 'loc' || p.id == 'mymfg') {
			matchobj['ietf-mud:mud'][mudMatchName] = [ null ];
		} else if ( p.id == 'ctl' || p.id == 'mfg') {
			matchobj['ietf-mud:mud'][mudMatchName] = ace_entry.children[0].value;
		}
	}

	proto = ace_entry.children[1].value;
	if ( proto != 'any') {
		lport = ace_entry.children[4].children[0].value;
		rport = ace_entry.children[4].children[1].value;
		cominit = ace_entry.children[5].children[0].value;
		if ( direction == 'to' ) {
			deviceProto = makeproto(ace_entry,proto,rport,lport,cominit);
		} else {
			deviceProto = makeproto(ace_entry,proto,lport,rport,cominit);
		}
	} else {
		deviceProto = null;
	}

	if ( proto == 'tcp' ) {
		if ( typeof matchobj[ipver] == 'undefined') {
			matchobj[ipver] = {'protocol' : 6};
		}else {
			matchobj[ipver]['protocol'] = 6;
		}
		if (deviceProto != null ){
			matchobj['tcp'] = deviceProto; 
		}
	}
	if ( proto == 'udp' ){
		if ( typeof matchobj[ipver] == 'undefined') {
			matchobj[ipver] =  {'protocol' : 17};
		} else {
			matchobj[ipver]['protocol'] = 17;
		}
		if (deviceProto != null ){
			matchobj['udp'] = deviceProto; 
		}
	}

	ace= { 
		"name": ace_name, 
		"matches" : matchobj,
		"actions" : actions
	};

	aIndex=-1;
	for (i in acl.aces.ace){
		if (acl.aces.ace[i].name == ace_name ) {
			aIndex=i;
		}
	}

	if ( aIndex >= 0 ) {
		acl.aces.ace[aIndex]= ace;
	} else {
		acl.aces.ace.push(ace);
	}

}

function updateAces(p,ace_entry) {
	var acls;
	// build an ace for both directions from ace_entry.  Store name in dom.
	// does name exist?
	if ( typeof ace_entry.aceBase == 'undefined') {
		aceBase = 'ace' + Math.floor(Math.random()*100000);
		ace_entry.aceBase = aceBase;
	} else {
		aceBase=ace_entry.aceBase;
	}
	if (ace_entry.children[0].value == '') {
		// entry must at some point be deleted, if it exists.
		return;
	}
	makeAcls();
	acls=ensureAcls()['acl'];
	for (i in acls) {
		updateAce(acls[i],ace_entry,aceBase,p);
	}
	saveMUD();
}

function updateOneAceGroup(p,ace_entry) {
	while ( p.nodeName != 'DETAILS' ) {
		ace_entry = p;
		p = p.parentNode;
	}
	updateAces(p,ace_entry);
}

function removeAces(cur){
	var aclContainer = getAcls();
	if ( typeof aclContainer == 'undefined' ){
		return;
	}
	if (typeof cur.aceBase == 'undefined') {
		return;
	}
	const re=new RegExp('.*' + cur.aceBase + '.*');
	var acls=aclContainer['acl'];
	var cleanup=false;
	for (i in acls) {
		if (acls[i].aces.ace.length == 0 ){
			return;
		}
		for (j in acls[i].aces.ace ) {
			if (acls[i].aces.ace[j].name.match(re) != null){
				acls[i].aces.ace.splice(j,1);
			}
		}
		if (acls[i].aces.ace.length == 0) {
			cleanup=true;
		}
	}
	if (cleanup == true){
		delete document.mudFile["ietf-access-control-list:acls"];
		delete document.mudFile['ietf-mud:mud']['to-device-policy'];
		delete document.mudFile['ietf-mud:mud']['from-device-policy'];
		delete document.aclBase;
	}
	saveMUD();
}

function forEachAceEntry(parent, callback) {
	Array.from(parent.children).slice(1).forEach(function(entry) {
		if (entry && entry.children && entry.children.length) {
			callback(entry);
		}
	});
}

function updateAceGroupEntries(parent) {
	forEachAceEntry(parent, function(entry) {
		updateAces(parent, entry);
	});
}

function removeAceGroupEntries(parent) {
	forEachAceEntry(parent, function(entry) {
		removeAces(entry);
	});
}

function sbomify(cur) {
	var whichsbom = document.getElementById("sbom").value;
	var mf;
	if ( cur.validity.valid == false ) {
		return;
	}

	mf = document.mudFile['ietf-mud:mud'];

	if (typeof mf['mudtx:transparency'] == 'undefined') {
		addMudExtension(document.mudFile, 'transparency');
	} else {
		if ( cur.name == "sbom-local-well-known"  && 
			typeof mf['mudtx:transparency']['vuln-url'] != undefined ) {
			var v= mf['mudtx:transparency']['vuln-url'];
			mf['mudtx:transparency'] = { 'vuln-url': v };
		}
	}
	if (whichsbom != "none" ) {
		var tx;
		if ( typeof mf['mudtx:transparency'] == 'undefined') {
			mf['mudtx:transparency'] = {};
		}
		tx=mf['mudtx:transparency'];
		if (whichsbom == 'local' || whichsbom == 'info' ) {
			tx[cur.name] = cur.value;
		} else if ( whichsbom == 'cloud' ) {
			var clurl = document.getElementById('sbomcloudurl').value;
			var clver = document.getElementById('sbomswver').value;
			if ( clurl == '' || clver == '' ) {
				return;
			}
			tx['sboms'] = [
				{
					"version-info" : clver,
					"sbom-url" : clurl
				}
			];
		} else {
			var cc = document.getElementById('sbomcc').value;
			var nr = document.getElementById('sbomnr').value	;
			if ( cc == '' || nr == '' ) {
				return;
			}
			tx['contact-info'] = 'tel:' + cc + nr;
		}
	}
	if ( cur.name == 'vuln-url') {
		if ( typeof mf['mudtx:transparency'] == 'undefined') {		
			mf['mudtx:transparency'] = {};
		}
		mf['mudtx:transparency']['vuln-url'] = [ cur.value ];
	}
	saveMUD();
}

$('summary').click(function() {
    var parent = $(this).parent()[0];
    var pbox = parent.id + 'box';
	if ( document.getElementById(pbox) == null ) {
		return;
	}
    if ( parent.open == false ) {
		document.getElementById(pbox).checked = true;
		updateAceGroupEntries(parent);
    } else {
		document.getElementById(pbox).checked = false;
		if ( parent.nodeName == "DETAILS" ) {
			removeAceGroupEntries(parent);
		}
    }
});

////////////////////// listeners



$(document).on('click','.addable',function(e){
	var cur=e.target;
	if ( cur.className == 'delete' ) {
		var parent = cur.parentElement;
		removeAces(parent);
		parent.remove();
	} else if ( cur.className == 'addItem' ) {	
		var grandparent = cur.parentElement.parentElement;
		addEntry(grandparent);
	}
})


$(document).on('change','.addable',function(e){
	var cur=e.target;

	if (cur.validity.valid  == false ) {
		return;
	}

	if (cur.className == 'proto') {
		var parent = cur.parentElement;
		var val = cur.value;
		tcporudp(parent,val);
		updateOneAceGroup(e.target.parentNode,cur);
		return;
	}
	if ( cur.name == 'direction') {
		updateOneAceGroup(e.target.parentNode,cur);
		return;
	}

	if ( cur.nodeName == 'INPUT' ) {
		updateOneAceGroup(e.target.parentNode,cur);
	}
})


$(document).on('change','.addbasics',function(e){
	addbasics(e.target);
})

$(document).on('change','#pub_name',function(e){
	setOlOwner(e.target.value);
	saveMUD();
})

$(document).on('input','#mudhost, #model_name',function(e){
	syncMudUrlPreviewFromForm();
})

$(document).on('change','#mudhost, #model_name',function(e){
	makemudurl();
})


$(document).on('change','.sbomstuff',function(e){
	sbomify(e.target);
})

////// initialize

initMUDFile();
syncMudUrlPreviewFromMudFile();
