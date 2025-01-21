

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
	    iframe = document.createElement("iframe");
	    iframe.width = window.innerWidth - 20;
	    iframe.height = window.innerHeight - 200;
	    iframe.src = "mudjsvis.html";
	    vizdiv.appendChild(iframe);

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
