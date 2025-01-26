// This code adopted from Allen Liu on Random Snippets
// http://www.randomsnippets.com/2008/02/21/how-to-dynamically-add-form-elements-via-javascript/
 

var nref = [ 0, 0, 0, 0 ];
var prev_sbom = 'none';
var limit = 50;

function initMUDFile() {
	document.mudFile=window.sessionStorage.getItem("mudfile");
	if ( document.mudFile == null ) {
		var d = new Date()
		document.mudFile = JSON.parse('{"ietf-mud:mud" : {"mud-version" : 1, "extensions" : [ "ol"], "ol" : { "spdx-tag" : "0BSD"}, "cache-validity": 48, "is-supported" : true}}');
		document.mudFile['ietf-mud:mud']["last-change"] = d.toISOString();
		window.sessionStorage.setItem('mudfile',JSON.stringify(document.mudFile));
	} else {
		document.mudFile=JSON.parse(document.mudFile);
	}
	document.mfChanged = false;
}




function removeIt(elemId) {
    var elem=document.getElementById(elemId);
    elem.parentNode.removeChild(elem);
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
		     fieldinfo="maxlength='120'";
		 }
	    }
	}

        newdiv.innerHTML = 
            "<input type=" + typefield + "name='" + entryType  + "name'" + pattern +
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
	    "<option value='thing'>Thing</option>" +
	    "<option value='remote'>Remote</option>" +
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

function localcheck(one2check,lport) {
    if (document.getElementById(one2check).value == 'local') {
	document.getElementById(lport).style.visibility="hidden";
    } else {
	document.getElementById(lport).style.visibility="inherit";
    }
}

function yesnoCheck(outer,inner,refind) {
    var box = inner + "box";
    if (document.getElementById(box).checked ) {
        document.getElementById(outer).style.display = 'block';
        document.getElementById(inner).style.display = 'block';
	nref[refind]++;
    } else {
        document.getElementById(inner).style.display = 'none';
	
	nref[refind]--;
        if ( nref[refind] < 1 ) {
            document.getElementById(outer).style.display = 'none';
        }
    }
}

// js update
function fillpub(cur) {
    var p=document.getElementById('pub_name');
    if (p.value == '') {
		p.value = cur.value;
		document.mudFile['ietf-mud:mud']['ol']['owners'] = [ cur.value ];
    }
}

// js update
function saveMUD() {
	var d = new Date();
	document.mudFile['ietf-mud:mud']["last-change"] = d.toISOString();
	window.sessionStorage.setItem('mudfile',JSON.stringify(document.mudFile));
	document.mfChanged = true;
}

function savework(){
	// we may need to add some extras
	var toSave = structuredClone(document.mudFile);
	toSave['country'] = document.getElementById('country').value;
	toSave['email_addr'] = document.getElementById('email_addr').value || '';
	toSave['sbomtype'] = document.getElementById('sbom').value;
	toSave['sbomcc'] = document.getElementById('sbomcc').value || '';
	toSave['sbomnr'] = document.getElementById('sbomnr').value || '';

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
	let email = document.getElementById('email_addr').value || '';
	let mfgr = document.getElementById('mfg-name').value || '';


	if ( country == '0' || email == '' || mfgr == '' || 
		typeof document.mudFile['ietf-mud:mud']['mud-url'] == 'undefined' ) {
		alert("Manufacturer Name, Model, Country, Email must all be set to retrieve a signed MUD file");
	}
	let model = document.mudFile['ietf-mud:mud']['systeminfo'];
	let pinfo = {
		"Manufacturer" : mfgr,
		"Model" : model,
		"MudURL" : document.mudFile['ietf-mud:mud']['mud-url'],
		'SerialNumber' : "Demo12345",
		"Mudfile" : document.MudFile,
		"EmailAddress" : email
	};
	const request = new Request("/mudnob64zip", {
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
			return response.body;
		})
		.then(zipdata => {
			var blob = new Blob(zipdata, {type: "application/zip"}),
				url = URL.createObjectURL(blob),
				dlAnchorElem = document.getElementById('downloadAnchorElem');
			dlAnchorElem.setAttribute("href", blob);
			dlAnchorElem.setAttribute("download", model + ".zip");
			dlAnchorElem.click();
			URL.revokeObjectURL(url);
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
			thegroup.children[0].value='';
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
		if (typeof matches['tcp']["ietf-mud:direction-initiated"] != 'undefined') {
			cominit.children[0].value = matches['tcp']["ietf-mud:direction-initiated"];
		}
	} else {
		pstring = 'udp';
		nextAce.children[1].value = 'tcp';
	}
	if ( tofro == 'to' ) {
		p1 = 1;
		p0 = 0;
	} else {
		p1 = 0;
		p0 = 1;
	}
	if (typeof matches[pstring]['source-port'] != 'undefined') {
		proto.children[p1].value = matches[pstring]['source-port']['port'];
	}
	if (typeof matches[pstring]['destination-port'] != 'undefined') {
		proto.children[p0].value = matches[pstring]['destination-port']['port'];
	}
}

function reloadFields(){
	var mf = document.mudFile['ietf-mud:mud'];
	const inbasic = ['mfg-name', 'systeminfo', 'documentation'];
	document.getElementById('country').value=document.mudFile['country'];
	delete document.mudFile['country'];
	document.getElementById('email_addr').value=document.mudFile['email_addr'];
	delete document.mudFile['email_addr'];
	document.getElementById('sbom').value = document.mudFile['sbomtype'];
	var sbomtype = document.mudFile['sbomtype'];
	delete document.mudFile['sbomtype'];
	var sbomcc = document.mudFile['sbomcc'];
	var sbomnr = document.mudFile['sbomnr'];
	delete document.mudFile['sbomcc'];
	delete document.mudFile['sbomnr'];

	inbasic.forEach(function(item){
		if (typeof mf[item] != 'undefined') {
			document.getElementById(item).value = mf[item];
		}
	});
	if (typeof mf['ol']['owners'] != 'undefined') {
		document.getElementById('pub_name').value = mf['ol']['owners'][0];
	}
	if ( typeof mf['mud-url'] != 'undefined') {
		re = /https:\/\/(?<hostname>[^\/]+)\/(?<model_name>.*)\.json/;
		matchres= mf['mud-url'].match(re);
		document.getElementById('mudhost').value = matchres.groups.hostname;
		document.getElementById('model_name').value = matchres.groups.model_name;
	}
	if (mf['extensions'].includes('transparency')){
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
	if (typeof mf['ietf-access-control-list:acls'] != 'undefined'){
		// we only need to look at one ACL/one set of ACEs.
		document.mudFile['ietf-mud:mud']['ietf-access-control-list:acls'].acl[0].aces.ace.forEach(
			function(ace){
				mudtypes = {
					'myctl' : 'my-controller',
					'mymfg' : 'same-manufacturer',
					'ctl' : 'controller',
					'loc' : 'local-networks'
				}

				var nextAce;
				let ipVer = null;
				let inputVal = '';
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
							nextAce = findNextAce(val);
							if (! nextAce.children[0].readOnly) {
								nextAce.children[0].value = ace['matches']["ietf-mud:mud"][mudtypes[va]];
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

function loadWork(input) {
	let file = input.files[0];
	let reader = new FileReader();
  
	reader.readAsText(file);
  
	reader.onload = function() {
		document.mudFile = JSON.parse(reader.result);
	  	reloadFields();
	}
}

  


// js update
function makemudurl() {
    p=document.getElementById('controller');
    mh=document.getElementById('mudhost');
	mm=document.getElementById('model_name');
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



function j2pp(b64) {
    var xhr = new XMLHttpRequest();
    var url = "/mudrest/mudpp/";
    var jsonText=atob(b64);
    if (document.getElementById("mudframe") != null )
        return;
    xhr.open("POST", url, true);
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            var iframe=document.createElement('iframe');
            iframe.id = "mudframe";
            iframe.src = "data:text/html;charset=utf-8," + this.responseText;
            iframe.style.width = "70%";
            document.body.insertBefore(iframe,document.getElementById('mudresults'));
        }
    };
    xhr.send(jsonText);
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
	document.mudFile['ietf-mud:mud']['ietf-access-control-list:acls']['acl'].push({ "name" : name, "type" : atype + "-acl-type", "aces" : { "ace": []}});
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
	mud["ietf-access-control-list:acls"] = {"acl": []};

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



	if (proto = 'tcp' && cominit != 'either'){
		ret['ietf-mud:direction-initiated'] = cominit;
		hasval = true;
	}

	if ( sport != "any" ) {
		ret['source-port'] = {
			"operator" : "eq",
			"port" : sport
		};
		hasval = true;
	}
	if (dport != "any") {
		ret['destination-port'] = {
			"operator" : "eq",
			"port" : dport
		};
		hasval= true;
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
			matchobj['ietf-mud:mud'][ace_entry.children[0].name] = [ null ];
		} else if ( p.id == 'ctl' || p.id == 'mfg') {
			matchobj['ietf-mud:mud'][ace_entry.children[0].name] = ace_entry.children[0].value;
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
	acls=document.mudFile['ietf-mud:mud']['ietf-access-control-list:acls']['acl'];
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
	if ( typeof document.mudFile['ietf-mud:mud']['ietf-access-control-list:acls'] == 'undefined' ){
		return;
	}
	if (typeof cur.aceBase == 'undefined') {
		return;
	}
	const re=new RegExp('.*' + cur.aceBase + '.*');
	var acls=document.mudFile['ietf-mud:mud']['ietf-access-control-list:acls']['acl'];
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
		delete document.mudFile['ietf-mud:mud']["ietf-access-control-list:acls"];
		delete document.mudFile['ietf-mud:mud']['to-device-policy'];
		delete document.mudFile['ietf-mud:mud']['from-device-policy'];
		delete document.aclBase;
	}
	saveMUD();
}

function sbomify(cur) {
	var whichsbom = document.getElementById("sbom").value;
	var mf;
	if ( cur.validity.valid == false ) {
		return;
	}

	mf = document.mudFile['ietf-mud:mud'];

	if (typeof mf['mudtx:transparency'] == 'undefined') {
		mf['extensions'] = [ "ol", "transparency" ];
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
		if ( parent.id == "myctl" || parent.id == "loc" || parent.id == 'mymfg') {
			updateOneAceGroup(parent,parent.children[1]);
		}
    } else {
		document.getElementById(pbox).checked = false;
		if ( parent.nodeName == "DETAILS" ) {
			removeAces(parent.children[1]);
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


$(document).on('change','.sbomstuff',function(e){
	sbomify(e.target);
})

////// initialize

initMUDFile();