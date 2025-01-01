// This code adopted from Allen Liu on Random Snippets
// http://www.randomsnippets.com/2008/02/21/how-to-dynamically-add-form-elements-via-javascript/
 
var counter = [ 1 , 1 , 1, 1, 1, 1, 1, 1, 1 , 1 , 1, 1, 1, 1, 1, 1,1 , 1 , 1, 1, 1, 1, 1, 1,1 , 1 , 1, 1, 1, 1, 1, 1,1 , 1 , 1, 1, 1, 1, 1, 1];

var nref = [ 0, 0, 0, 0 ];

var limit = 50;

function removeIt(elemId) {
    var elem=document.getElementById(elemId);
    elem.parentNode.removeChild(elem);
}
    

function addInput(divName,sectype,dnsorurl,i){

    if (counter[i] == limit)  {
        alert("You have gotten silly: you have reached the limit of adding "
	      + counter[i] + " inputs");
    }
    else {
	var names = sectype + "names[]";
	var port = sectype + "port[]";
	var lport = sectype + "portl[]";
	var proto = sectype + "proto[]";
	var init  = sectype + "init[]";
        var newdiv= document.createElement('span');
	var typefield;
	var pattern;
	var portdivname;
	var portldivname;
	var checkdivname;
	var seldivname;
	var onchange;
	var hidden;
	var any;
	var placeholder;
	var fieldinfo;
	var divid;

	divid= "ext-" + "i" + "-" + counter[i] + divName;
	newdiv.id=divid;

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

	portdivname= divid + counter[i] + 'portdiv';
	portldivname= divid + counter[i] + 'portdivl';
	checkdivname= divid + counter[i] + 'portdivc';
	checkid= checkdivname + "-id";
	selname= divid + counter[i] + 'sel';

	if ( divName == 'loclist' ) {
            hidden="' style='visibility: hidden'";
            any = "<option value='any'>Any</option>";
            onchange=
		 "value='any' onchange=\"tcporudp('" + selname + "','" + portdivname + "');\"";
	    pattern = " ";
	    fieldinfo = 'readonly="" value="any" ';
	} else {
	    if ( divName == 'myctllist' ) {
            any = "<option value='any'>Any</option>";
            onchange=
		 "value='any' onchange=\"tcporudp('" + selname + "','" + portdivname + "');\"";
	    hidden ="' style='visibility: hidden' ";
	    pattern = " ";
	    fieldinfo = 'readonly="" value="(filled in by local admin)" ';
	    } else { 
		if (divName == 'mymanlist' ) {
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
		     onchange=
			 "value='any' onchange=\"tcporudp('" + selname + "','" + portdivname + "');\"";
		     fieldinfo="maxlength='120'";
		 }
	    }
	}

        newdiv.innerHTML = 
            " <br><input type=" + typefield + "name='" + names  + "'" + pattern +
	    " size='40' " + placeholder + fieldinfo + ">&nbsp;&nbsp;&nbsp;" +
	    " Protocol&nbsp;&nbsp;<select id='" + selname + "' name='" + proto + "'" +
		onchange + ">" +
	    any +
	    "<option value='tcp'>TCP</option>" +
	    "<option value='udp'>UDP</option>" +
	    "</select>" + "&nbsp;<input type='button' value='-' " +
	    "onclick=\"removeIt('" + divid + "');\">" +
	    "<span id='" + portldivname + hidden + ">"
	    + "&nbsp;&nbsp;&nbsp;" + 
	    "<br>Local Port&nbsp; <input pattern='([0-9]{1,5}|any)' value='any' " +
	    "name='" + lport + "' style='width:60px'></span>" +
	    "<span id='" + portdivname + hidden + ">"
	    + "&nbsp;&nbsp;&nbsp;" + 
	    "Remote Port&nbsp; <input pattern='([0-9]{1,5}|any)' value='any' " +
	    "name='" + port + "' style='width:60px'></span>" +
	    "<span id='" + checkdivname + hidden + ">"
	    + "&nbsp;&nbsp;&nbsp;" + 
	    "Initiated by&nbsp; <select "  + "id='" + checkid + "' " +
             "value='any' onclick=\"localcheck('" + checkid + "','" + portldivname + "');\"" +
	    "name='" + init + "'>" +
	    "<option value='either'>Either</option>" +
	    "<option value='thing'>Thing</option>" +
	    "<option value='remote'>Remote</option>" +
	    "</select></span>";
	    

        document.getElementById(divName).appendChild(newdiv);
        counter[i]++;
    }
}

function tcporudp(selectid,portid) {
    var lport = portid + "l";
    var check = portid + "c";
    if (document.getElementById(selectid).value == 'any') {
	document.getElementById(portid).style.visibility='hidden';
	document.getElementById(lport).style.visibility='hidden';
	document.getElementById(check).style.visibility='hidden';
    } else {
	document.getElementById(portid).style.visibility='inherit';
	if (document.getElementById(selectid).value == 'udp' ) {
	    document.getElementById(lport).style.visibility='inherit';
	    document.getElementById(check).style.visibility='hidden';
	} else {
	    document.getElementById(check).style.visibility='inherit';
	    document.getElementById(lport).style.visibility='inherit';
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

function toggleANIMA(anid,anspan) {
    if (document.getElementById(anid).value == 'Yes') {
	document.getElementById(anspan).style.display = 'inherit';
    } else {
	document.getElementById(anspan).style.display ='none';
    }
}

function fillpub() {
    p=document.getElementById('pub_name').value;
    if (p == '') {
	p = document.getElementById('man_name').value;
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
    document.getElementById('sbc2').style.display= 'none';
    document.getElementById('sbinfourl').style.display= 'none';
    document.getElementById('sbomcloudurl').value='';
    document.getElementById('sbomcc').value='';
    document.getElementById('sbomnr').value='';
    document.getElementById('sbomc2').value='';
    document.getElementById('sbinfourl').value='';
    if (outer.value != 'none') {
	var elid='sb' + outer.value;
	document.getElementById('sbomany').style.display= 'inherit';
	document.getElementById(elid).style.display= 'inline-block';
    } else {
	document.getElementById('sbomany').style.display= 'none';
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

$('summary').click(function() {
    var parent = $(this).parent()[0];
    var pbox = parent.id + 'box';
    if ( parent.open == false ) {
	document.getElementById(pbox).checked = true;
    } else {
	document.getElementById(pbox).checked = false;
    }
});
