function unhideURL() {
    var input=document.getElementById("themudfile");
    input.value='';
    document.getElementById('use_url').style.visibility="inherit";
    document.getElementById('use_file').style.visibility="hidden";
}
    
function unhideFile() {
    document.getElementById('use_file').style.visibility="inherit";
    document.getElementById('use_url').style.visibility="hidden";

}

