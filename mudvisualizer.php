<!DOCTYPE html>
<?php
  session_start();

// cache for 300 seconds
  header("Cache-Control: s-maxage=300, public, max-age=300");
  $pinfo=json_decode(base64_decode($_SESSION['pb64']));
  $mudfile=preg_replace("/\n/", '\n',base64_decode($pinfo->{'Mudfile'}));
?>
<!--
	Prism by TEMPLATED	templated.co @templatedco	Released for free under the Creative Commons Attribution 3.0 license (templated.co/license)-->
<html>
  <head>
    <meta http-equiv="content-type" content="text/html; charset=utf-8">
    <title>Visualize a MUD-enabled Network</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <!--[if lte IE 9]><link rel="stylesheet" href="assets/css/ie9.css" /><![endif]-->
    <!-- <script type="text/javascript" src="aux.js" defer="defer"></script> -->
    <link rel="stylesheet" href="assets/css/main.css">


    <meta charset="utf-8">
    <link rel='stylesheet' href='css/mainWindow.css' type='text/css' media='all'/>
    <link rel='stylesheet' href='css/tooltip.css' type='text/css' media='all'/>
    <link rel='stylesheet' href='css/introjs.css'>
    <link rel="shortcut icon" href="favicon.ico" type="image/x-icon"/>
    <title>MUD-Visualizer</title>
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
    <section id="vizholder" class="wrapper style2" style="padding: 0 !important">
    <input type="file" id="openfile-input" style="display:none;" multiple>
    <div class="icon-bar" id="lefticonbar">
        <div style="text-align: center; margin-top: 5px;">
            <button id="openfile-button" class="icon-button" data-intro="Open one or more MUD files" data-step="1"
                    tooltip="Open Mud File(s)" flow="right" >
                <img align="middle" src="img/menu_icons/openfile.png" width="35" height="35" vspace="5"></button>

            <button id="openurl-button" class="icon-button" data-intro="Open a MUD file by URL" data-step="2"
                    tooltip="Open Mud File(s)" flow="right" onclick="openurl()">
                <img align="middle" src="img/menu_icons/openurl.png" width="35" height="35" vspace="5"></button>

            <button class="icon-button" data-intro="Resets the drawing to initial position" data-step="3"
                    tooltip="Refresh the Drawing" flow="right">
                <img align="middle" src="img/menu_icons/refresh.png" width="35" height="35" vspace="5" onclick="drawer()"></button>

            <button id="SelectMmdFiles" data-intro=" Opens the menu for deselecting/selecting the visualized MUD-files" data-step="4"
                    class="icon-button" tooltip="Select/Deselect Mud Files" flow="right">
                <img align="middle" src="img/menu_icons/select.png" width="35" height="35" vspace="5"></button>

            <button id="button_incoming" data-intro="Click on this to change the traffic direction to (incoming)" data-step="5" class="icon-button"
                    tooltip="Show Incmoing Traffic" flow="right">
                <img align="middle" src="img/menu_icons/incoming.png" width="35" height="35" vspace="5" onclick="set_incoming()"></button>

            <button id="button_outgoing" data-intro="With this icon selected, the outgoing traffic will be visualized" data-step="6"
                    class="icon-button" tooltip="Show Outgoing Traffic" flow="right">
                <img align="middle" src="img/menu_icons/outgoing.png" width="35" height="35" vspace="5" onclick="set_outgoing()"></button>

            <button id="helper" class="icon-button" href="javascript:void(0);" tooltip="Tour of the MUD-Visualize" flow="right"
                data-intro="See this introductory tour again" data-step="7">
                <img align="middle" src="img/menu_icons/help.png" width="35" height="35" vspace="6" onclick="tour()"></button>
        </div>
    </div>

    <div class="svg_board" id="svgplaceholder">
        <svg class="svg" style="position: relative !important"></svg>

        <!-- Footer -->
        <footer id="footer">
          <div class="copyright"> Except as follows, this page is open source.<br>
            © Untitled. All rights reserved. Images: <a href="http://unsplash.com">Unsplash</a>.
            Design: <a href="http://templated.co">TEMPLATED</a>. </div>
        </footer>
    </div>

    <!-- div for selecting and deselcting the mud files to preview -->
    <div id="mudSelectionDiv" class="select-deselect-muds">
        <div id="fileNotLoaded" style="text-align: center" class="select-deselect-muds__text">No Mud-file loaded
            <br>
            <img align="middle" src="img/other_icons/file_not_loaded.svg" width="100" height="100" vspace="30">
        </div>
    </div>


    </section>

    <!-- Scripts -->
    <!-- <script src="assets/js/jquery.min.js"></script>
    <script src="assets/js/skel.min.js"></script>
    <script src="assets/js/util.js"></script> -->
    <!--[if lte IE 8]><script src="assets/js/ie/respond.min.js"></script><![endif]-->
    <!-- <script src="assets/js/main.js"></script> -->

   <script type="text/javascript">
     var incoming_mudfile='<?php echo $mudfile;?>';
   </script>



    <!-- Visualizer imports start (copy paste from mud-visualizer/mainWindow.html)-->
    <script type="text/javascript" src="scripts/d3.v4.min.js"></script>
    <script type="text/javascript" src="scripts/jquery.min.js" onload="window.$ = window.jQuery = module.exports;"></script>
    <script src="https://code.jquery.com/ui/1.12.1/jquery-ui.js"></script>
    <script type="text/javascript" src="scripts/psl.min.js"></script>
    <script type="text/javascript" src="scripts/sweetalert2.min.js"></script>
    <script type="text/javascript" src="scripts/ui.js"></script>
    <script type="text/javascript" src="scripts/intro.js"></script>
    <script type="text/javascript" src="scripts/utils.js"></script>
    <script type="text/javascript" src="scripts/helpers.js"></script>
    <script type="text/javascript" src="scripts/mud.js"></script>
    <script type="text/javascript" src="scripts/default_devices.js"></script>
    <script type="text/javascript" src="renderer.js"></script>
    <!-- Visualizer imports end-->



  </body>
</html>
