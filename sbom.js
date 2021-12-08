
function sbomselect(one,another) {
    var onview = document.getElementById(one);
    var offview = document.getElementById(another);

    if ( document.getElementById(one).checked ) {
	onview = document.getElementById(one);
	offview = document.getElementById(another);
    } else {
	offview = document.getElementById(one);
	onview = document.getElementById(another);
    }
    onview.style.display = "inline";
    offview.style.display = "none";
}

