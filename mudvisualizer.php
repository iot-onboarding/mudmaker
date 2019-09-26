<!DOCTYPE html>
<?php 
  session_start();
  $mudfile=preg_replace("/\n/", '\n',$_SESSION['mudfile']);
?>
<!--
	Prism by TEMPLATED	templated.co @templatedco	Released for free under the Creative Commons Attribution 3.0 license (templated.co/license)-->
<html>
  <head>
    <meta http-equiv="content-type" content="text/html; charset=utf-8">
    <title>Visualize a MUD-enabled Network</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="assets/css/main.css">
    <link rel="stylesheet" href="MUD-Visualizer/css/mainWindow.css" type="text/css"
      media="all">
    <link rel="stylesheet" href="MUD-Visualizer/css/tooltip.css" type="text/css"
      media="all">
    <link rel="shortcut icon" href="MUD-Visualizer/favicon.ico" type="image/x-icon">
    <!--[if lte IE 9]><link rel="stylesheet" href="assets/css/ie9.css" /><![endif]-->
    <!-- <script type="text/javascript" src="aux.js" defer="defer"></script> -->
  </head>
  <body> <!-- Banner -->
    <section id="banner">
      <div class="inner split">
        <section>
          <h2>MUD Visualizer Tool</h2>
        </section>
        <section>
          <p>A tool to visualize your MUD files</p>
          <ul class="actions">
            <li><a href="mudvisualizer_help.html" class="button special">Help</a></li>
          </ul>
        </section>
      </div>
    </section>
    <!-- One -->
    <section class="wrapper style2">
      <div id="visualizerholder"> <input id="openfile-input" style="visibility: hidden;"
          multiple=""
          type="file">
        <div class="icon-bar">
          <div style="text-align: center; margin-top: 5px;"> <button id="openfile-button"
              class="icon-button"
              tooltip="Open Mud File(s)"
              flow="right"><img
                src="MUD-Visualizer/img/menu_icons/openfile.png"
                align="middle"
                height="35"
                width="35"
                vspace="5"></button>
            <button class="icon-button" tooltip="Refresh the Drawing" flow="right"><img
                src="MUD-Visualizer/img/menu_icons/refresh.png"
                onclick="drawer()"
                align="middle"
                height="35"
                width="35"
                vspace="5"></button>
            <button id="SelectMudFiles" class="icon-button" tooltip="Select/Deselect Mud Files"
              flow="right"><img
                src="MUD-Visualizer/img/menu_icons/select.png"
                align="middle"
                height="35"
                width="35"
                vspace="5"></button>
            <button id="button_incoming" class="icon-button" tooltip="Show Incmoing Traffic"
              flow="right"><img
                src="MUD-Visualizer/img/menu_icons/incoming.png"
                onclick="set_incoming()"
                align="middle"
                height="35"
                width="35"
                vspace="5"></button>
            <button id="button_outgoing" class="icon-button" tooltip="Show Outgoing Traffic"
              flow="right"><img
                src="MUD-Visualizer/img/menu_icons/outgoing.png"
                onclick="set_outgoing()"
                align="middle"
                height="35"
                width="35"
                vspace="5"></button>
            <button id="button_help" class="icon-button" tooltip="Open Help Page"
              flow="right"><img
                src="MUD-Visualizer/img/menu_icons/help.png"
                onclick="window.open('mudvisualizer_help.html')"
                align="middle"
                height="35"
                width="35"
                vspace="5"></button>
          </div>
        </div>
        <div id="mudSelectionDiv" class="select-deselect-muds">
          <div id="fileNotLoaded" style="text-align: center" class="select-deselect-muds__text">No
            Mud-file loaded <br>
            <img src="MUD-Visualizer/img/other_icons/file_not_loaded.svg" align="middle"
              height="100"
              width="100"
              vspace="30">
          </div>
        </div>
      </div>
      <div class="svg_board">
        <svg class="svg"></svg> </div>
    </section>
    <!-- Footer -->
    <footer id="footer">
      <div class="copyright"> Except as follows, this page is open source.<br>
        © Untitled. All rights reserved. Images: <a href="http://unsplash.com">Unsplash</a>.
        Design: <a href="http://templated.co">TEMPLATED</a>. </div>
    </footer>
    <!-- Scripts -->
    <!-- <script src="assets/js/jquery.min.js"></script>
    <script src="assets/js/skel.min.js"></script>    <script src="assets/js/util.js"></script> -->
    <!--[if lte IE 8]><script src="assets/js/ie/respond.min.js"></script><![endif]-->
    <!-- <script src="assets/js/main.js"></script> -->
    <script type="text/javascript" src="MUD-Visualizer/scripts/d3.v4.min.js"> </script>
    <script type="text/javascript" src="MUD-Visualizer/scripts/jquery.min.js"></script>
    <!-- <script type="text/javascript" src="scripts/jquery.min.js"></script> -->
    <script type="text/javascript" src="MUD-Visualizer/scripts/psl.min.js"></script>
    <script type="text/javascript" src="MUD-Visualizer/scripts/sweetalert2.min.js"></script>
    <script type="text/javascript" src="MUD-Visualizer/scripts/ui.js"></script>
    <script type="text/javascript" src="MUD-Visualizer/scripts/utils.js"></script>
    <script type="text/javascript" src="MUD-Visualizer/scripts/helpers.js"></script>
    <script type="text/javascript" src="MUD-Visualizer/scripts/mud.js"></script>
    <script type="text/javascript" src="MUD-Visualizer/scripts/default_devices.js"></script>
   <script type="text/javascript">
     var incoming_mudfile='<?php echo $mudfile;?>';
   </script>
   <script type="text/javascript" src="MUD-Visualizer/renderer.js"></script>
  </body>
</html>
