
function getviz(){
	fetch("mudvisjs.html")
		.then(response => response.text())
		.then(htmltxt => {
				thediv=document.getElementById("visdiv");
				thediv.innerHTML=htmltxt;
				})

	if (!response.ok) {
		throw new Error(`Response status: ${response.status}`);
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
	} else if (tabName == 'visualize') {
		var incoming_mudfile = document.mudFile;
		newdiv = document.createElement("div");
		newdiv.id="visdiv";
		getviz();
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
