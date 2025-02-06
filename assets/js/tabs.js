

function getviz(){
	fetch("mudvisjs.html")
		.then(response => response.text())
		.then(htmltxt => updateVis(htmltxt))
}


function b64_encode(str) {
	return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g,
        function toSolidBytes(match, p1) {
            return String.fromCharCode('0x' + p1);
		}
	))
}

function refreshmans(){
	let mans = document.getElementById("mandatories");
	let gtg = true;
	let innerhtml='<ul style="list-style-type: none">';
	let displaytab = {
		"mudhost" : "Manufacturer Domain",
		"mfg-name" : "Manufacturer Name",
		"model_name" : "Device Model",
		"systeminfo" : "Device Description",
		"documentation" : "Documentation URL",
		"email_addr" : "EMail Address"
	};
	Object.keys(displaytab).forEach(
		(k) => {
			let v = document.getElementById(k);
			if (v.validity.valid && v.value != null & v.value != '' ) {
				innerhtml = innerhtml + '<li>' + 
					"<span style='color: green'>&#9989;</span>&nbsp;" + displaytab[k] + ": "  + v.value +"</li>";
			} else {
				innerhtml = innerhtml + '<li>' +
					"<span style='color: red'>&#10006;</span>&nbsp;" + displaytab[k] + ": not set</li>";
				gtg = false; 
			}
		});
	mans.innerHTML = innerhtml + '</ul>';
	let but = document.getElementById("pubbutton");
	if ( gtg ==  false ) {
		but.disabled = true;
	} else {
		but.disabled = false;
	}
}

function openTab(evt, tabName) {
	// Declare all variables
	var i, tabcontent, tablinks;
  
	// Get all elements with class="tabcontent" and hide them
	tabcontent = document.getElementsByClassName("tabcontent");
	for (i = 0; i < tabcontent.length; i++) {
	  tabcontent[i].style.display = "none";
	}
	if (tabName == "viewmudfile"){
		pre=document.getElementById("mudcontent");
		pre.innerText = JSON.stringify(document.mudFile,null,2);
		let mud=document.mudFile;
		if ( typeof mud['ietf-mud:mud']['mud-url'] == 'undefined' &&
			mud['ietf-mud:mud']['mud-url'].length > 0) {
				mudcode = new QRCode(document.getElementById("qrcontent"), {
					text: mud['ietf-mud:mud']['mud-url'],
					width: 128,
					height: 128,
					colorDark: "#000000",
					colorLight : "#ffffff",
					correctLevel : QRCode.CorrectLevel.H
				});
			document.getElementById("content-overlay").display = "inherit";
			} else {
				if (typeof mudcode != 'undefined') {
					mudcode.clear();
				}
			}

	} else if (tabName == 'visualize' && document.mfChanged == true) {
	    document.getElementById("vis2").remove();
	    let iframe = document.createElement("iframe");
		iframe.id="vis2";
	    iframe.width = window.innerWidth - 20;
	    iframe.height = window.innerHeight - 200;
	    iframe.src = "mudjsvis.html";
	    document.getElementById("visualize").appendChild(iframe);
		document.mfChanged = false;
	} else if (tabName == "publish") {
		refreshmans();
		let mud=document.mudFile["ietf-mud:mud"]
		if ( typeof mud["mud-url"] != 'undefined' ) {
			fetch("/gitShovel/gottoken?mudurl=" + mud["mud-url"], {
				method : "GET",
				headers :{
				"Accept" : "application/json"
				}
			})
			.then(response => {
				if ( ! response.ok ) {
				return;
				}
				sessionStorage.setItem("gottoken","true");
			})
		}
	}
	// Get all elements with class="tablinks" and remove the class "active"
	tablinks = document.getElementsByClassName("tablinks");
	for (i = 0; i < tablinks.length; i++) {
	  tablinks[i].className = tablinks[i].className.replace(" active", "");
	}
  
	// Show the current tab, and add an "active" class to the button that opened the tab
	document.getElementById(tabName).style.display = "block";
	evt.currentTarget.className += " active";
  }
