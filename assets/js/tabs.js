

function getviz(){
	fetch("mudvisjs.html")
		.then(response => response.text())
		.then(htmltxt => updateVis(htmltxt))
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
	} else if (tabName == 'visualize') {
	    vizdiv = document.getElementById("visualize");
		if (typeof vizdiv.children[0] != 'undefined' && document.mfChanged == true) {
			vizdiv.children[0].remove();
			document.mfChanged = false;
		}
	    iframe = document.createElement("iframe");
	    iframe.width = window.innerWidth - 20;
	    iframe.height = window.innerHeight - 200;
	    iframe.src = "mudjsvis.html";
	    vizdiv.appendChild(iframe);

	} else if (tabName == "publish") {
		let mans = document.getElementById("mandatories");
		let innerhtml='';
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
					innerhtml = innerhtml + '<div color="green">' + 
						displaytab[k] + " : "  + v.value + " &#2705;</div>";
				} else {
					innerhtml = innerhtml + '<div color="red">' +
						displaytab[k] + " : not set &#10006;</div>" 
				}
			});
		mans.innerHTML = innerhtml;
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
