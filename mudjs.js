// This code adopted from Allen Liu on Random Snippets
// http://www.randomsnippets.com/2008/02/21/how-to-dynamically-add-form-elements-via-javascript/
 

var nref = [ 0, 0, 0, 0 ];

var limit = 50;

document.mudFile=window.sessionStorage.getItem("mudFile");
if ( document.mudFile == null ) {
	d = new Date()
	document.mudFile = JSON.parse('{"ietf-mud:mud" : {"mud-version" : 1, "extensions" : [ "ol"], "ol" : { "spdx-tag" : "0BSD"}, "cache-validity": 48, "is-supported" : true}}');
	document.mudFile['ietf-mud:mud']["last-change"] = d.toISOString();
	window.sessionStorage.setItem('mudfile',JSON.stringify(document.mudFile));
} else {
	document.mudFile=JSON.parse(document.mudFile);
}

function removeIt(elemId) {
    var elem=document.getElementById(elemId);
    elem.parentNode.removeChild(elem);
}
    
// js update
function addEntry(entry){
    var newdiv= document.createElement('span');
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
            any = "<option value='any'>Any</option>";
	    pattern = " ";
	    fieldinfo = 'readonly="" value="any" ';
	} else {
	    if ( entryType == 'myctl' ) {
            any = "<option value='any'>Any</option>";
	    hidden ="' style='visibility: hidden' ";
	    pattern = " ";
	    fieldinfo = 'readonly="" value="(filled in by local admin)" ';
	    } else { 
		if (entryType == 'mymfg' ) {
		    onchange=
			"value='any' onchange=\"tcporudp('" + selname + "','" + portdivname + "');\"";
		    any = "<option value='any'>Any</option>";
		    hidden ="' style='visibility: inherit' ";
		    any = '';
		    pattern = " ";
		    fieldinfo = 'readonly="" value="(filled in by system)" ';
		}
		 else {
		     hidden="' style='visibility: hidden'";
		     any = "<option value='any'>Any</option>";
		     fieldinfo="maxlength='120'";
		 }
	    }
	}

        newdiv.innerHTML = 
            " <br><input type=" + typefield + "name='" + entryType  + "name'" + pattern +
	    " size='40' " + placeholder + fieldinfo + ">&nbsp;&nbsp;&nbsp;" +
	    " Protocol&nbsp;&nbsp;<select class='proto' name='proto'>" +
	    any +
	    "<option value='tcp'>TCP</option>" +
	    "<option value='udp'>UDP</option>" +
	    "</select>" + "&nbsp;<input type='button' class='delete' value='-'>" +
	    "<span class='portinfo' style='visibility: hidden'>"
	    + "&nbsp;&nbsp;&nbsp;" + 
	    "<br>Local Port&nbsp; <input pattern='([0-9]{1,5}|any)' value='any' " +
	    "class='lport' style='width:60px'>" +
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
    p=document.getElementById('pub_name');
    if (p.value == '') {
		p.value = cur.value;
		document.mudFile['ietf-mud:mud']['ol']['owners'] = [ cur.value ];
    }
}

// js update
function saveMUD() {
	d = new Date();
	document.mudFile['ietf-mud:mud']["last-change"] = d.toISOString();
	window.sessionStorage.setItem('mudfile',JSON.stringify(document.mudFile));
}

// js update
function makemudurl() {
    p=document.getElementById('entname1');
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
    me=document.getElementById('vulntype');
    if ( me.value != 'none' ) {
	v.style.display='inherit';
    } else {
	v.style.display='none';
	v.value='';
    }
}

function setVisibility(outer) {

    document.getElementById('sbcloud').style.display= 'none';
    document.getElementById('sblocal').style.display= 'none';
    document.getElementById('sbtel').style.display= 'none';
    document.getElementById('sbinfourl').style.display= 'none';
    document.getElementById('sbomcloudurl').value='';
    document.getElementById('sbomcc').value='';
    document.getElementById('sbomnr').value='';
    document.getElementById('sbinfourl').value='';
    if (outer.value != 'none') {
		var elid='sb' + outer.value;
		document.getElementById('sbomany').style.display= 'inherit';
		document.getElementById(elid).style.display= 'inline-block';
    } else {
		document.getElementById('sbomany').style.display= 'none';
		delete document.mudFile['mudtx:transparency'];
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
	var acls = document.mudFile['ietf-mud:mud']['ietf-access-control-list:acls']['acl'];
	acl = { "name" : name, "type" : atype + "-acl-type", "aces" : []};
}

function makeAcls(){
	var mud = document.mudFile['ietf-mud:mud'];
	var acltype= document.getElementById("ipchoice").value;
	
	if (typeof document.aclBase != 'undefined') {
		return;
	}
	mud["ietf-access-control-list:acls"] = {"acl": []};

	document.aclBase= 'acl' + Math.floor(Math.random()*100000);
	bn = document.aclBase;
	mud['from-device-policy'] = {
		"access-lists" : {"access-list" : [{}]}
	};
	toacls=mud['from-device-policy']['access-lists']["access-list"];
	mud['to-device-policy'] = structuredClone(mud['from-device-policy']);
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
	saveMUD();
}

function sbomify(cur) {
	var whichsbom = document.getElementById("sbom").value;

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
    if ( parent.open == false ) {
	document.getElementById(pbox).checked = true;
    } else {
	document.getElementById(pbox).checked = false;
    }
});

$(document).on('click','.addable',function(e){
	var cur=e.target;
	if ( cur.className == 'delete' ) {
		var parent = cur.parentElement;
		parent.remove()
	} else if ( cur.className == 'addItem' ) {	
		var grandparent = cur.parentElement.parentElement;
		addEntry(grandparent);
	}
})


$(document).on('change','.addable',function(e){
	var cur=e.target;
	if (cur.className == 'proto') {
		var parent = cur.parentElement;
		var val = cur.value;
		tcporudp(parent,val);
		return;
	}
	if ( cur.nodeName == 'INPUT' ) {
		var p = e.target.parentNode;
		var ace_entry = cur;
		while ( p.nodeName != 'DETAILS' ) {
			ace_entry = p;
			p = p.parentNode;
		}

		// build an ace for both directions from ace_entry.  Store name in dom.
		// does name exist?
		if ( typeof ace_entry.aceBase != 'undefined') {
			ace_entry.aceBase = 'ace' + Math.floor(Math.random()*100000);
		}
		if (ace_entry.children[0].value == '') {
			// entry must at some point be deleted, if it exists.
			return;
		}
		makeAcls();

	}
})

$(document).on('change','.addbasics',function(e){
	addbasics(e.target);
})


$(document).on('change','.sbomstuff',function(e){
	sbomify(e.target);
})
