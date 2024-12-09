<?php
  session_start();

/* Copyright (c) 2016-2024, Cisco Systems
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this
  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

/*
 * Take a few inputs and generate a MUD file.
 *
 * All components are optional.
 * We will build two access lists: inbound and outbound.
 * There are two directions in which communications can be initiated: to device
 * and from device.  We allow the specified port outbound as a destination port
 * and inbound as a source port when the device initiates.  We allow the specified
 * port inbound as a destination port and outbound as a source port when others
 * initiate.  
 */

use chillerlan\QRCode\{QRCode, QROptions};
require __DIR__ . '/vendor/autoload.php';
date_default_timezone_set("GMT");
$aclhead= <<< ACL_HEAD
"ietf-access-control-list:acls" : {
  "acl" : 
  
ACL_HEAD;
  
$downloadtext=<<< DOWNLOAD
<form method="POST" action="download.php">
  <input type="submit" value="Download MUD file" formaction="download.php" class="button special">
  <input type="submit" value="Visualize" formaction="mudvisualizer.php" class="button special">
   
DOWNLOAD;
  
$actxt0=<<< ACTXT0

  "ietf-mud:mud" : {
    "mud-version" : 1,
ACTXT0;
        

$actxt1=<<<  ACTXT1

    "from-device-policy" : {
        "access-lists" : {
            "access-list" : [

ACTXT1;

$actxt1a=<<< ACTXT1A
            ] 
        }
    },

ACTXT1A;

$actxt1b=<<< ACTXT1B
    "to-device-policy" : {
      "access-lists" : {
            "access-list" : [
ACTXT1B;
                

$actxt2=<<< ACTXT2
                   ]
                 }
        }
},
ACTXT2;


define("IS_LOCAL",1);
define("IS_MFG", 2);
define("IS_CONTROLLER", 3);
define("IS_CLOUD", 4);
define("IS_MY_CONTROLLER", 5);
define("IS_MYMFG", 6);

  

/* Rather than try to pretty print the json throughout, I have 
 * borrowed some code from Kendall Hopkins and George Garchagudashvili
 * from stackoverflow at the following URL:
 *  http://stackoverflow.com/questions/6054033/pretty-printing-json-with-php
 *
 * Yes, this means that [null] looks a little weird.
 */



function prettyPrint( $json )
{
  $result = '';
  $level = 0;
  $in_quotes = false;
  $in_escape = false;
  $ends_line_level = NULL;
  $json_length = strlen( $json );

  for( $i = 0; $i < $json_length; $i++ ) {
    $char = $json[$i];
    $new_line_level = NULL;
    $post = "";
    
    if( $ends_line_level !== NULL ) {
      $new_line_level = $ends_line_level;
      $ends_line_level = NULL;
    }
    
    if ( $in_escape ) {
      $in_escape = false;
    }
    else if( $char === '"' ) {
      $in_quotes = !$in_quotes;
    }
    else if( ! $in_quotes ) {
      switch( $char ) {
      case '}': case ']':
	$level--;
	$ends_line_level = NULL;
	$new_line_level = $level;
	break;

      case '{': case '[':
	$level++;
	
      case ',':
	$ends_line_level = $level;
	break;

      case ':':
	$post = " ";
	break;
	
      case " ": case "\t": case "\n": case "\r":
	$char = "";
	$ends_line_level = $new_line_level;
	$new_line_level = NULL;
	break;
      }
    }
    else if ( $char === '\\' ) {
      $in_escape = true;
    }
    
    if( $new_line_level !== NULL ) {
      $result .= "\n".str_repeat( "  ", $new_line_level );
    }
    $result .= $char.$post;
  }

  return $result;
  
}



// add a line to an acl.  

$gotin = 0;
$gotout = 0;
$fail=0;	/* set if someone is screwing with us */

function errorexit($errstr)  {
    
  print "<!DOCTYPE html>\n<html>\n<body>\n";

  print "<h1>Error</h1>";
  print "<p>";
  print $errstr;
  print "</p><p>Please click back and correct.</p>";
  print "</body></html>";
  exit;
}
  
function mkportrange($rname,$port, $dirinit) {
    if ( $port == 'any' ) {
        return "";
    }
    $frag='';
    
    if ( $dirinit == "thing" || $dirinit == "remote" ) {
        $frag = ',';
    }
    
    $frag = $frag . '"' . $rname . '"  :  ' . 
    "{\n" . '"operator" : "eq" ' . ",\n" .
    ' "port" : ' . $port . "\n }";
    return $frag;
}
  

function addace($acename, $pdirect, $target, $proto, $lport, $port, $type,$dirinit) {
  

  $openacl='';

  $ace="   {\n   " . '"name" :' . '"' . $acename . '"' . ",\n" .
    '   "matches" : {';

  $clfrag = '';
  $l4frag = '';

  if ( strlen($target) > 120 ) {
    errorexit("string too long: " . $target);
  }

  switch ($type) {
    case IS_LOCAL:
      $ace = $ace . '  "ietf-mud:mud" : { "local-networks" : [ null ] }';
      break;
    case IS_MY_CONTROLLER:
      $ace = $ace . '  "ietf-mud:mud" : { "my-controller" : [ null ] }';
      break;
    case IS_CONTROLLER:
      // uri validator courtesy of...
      // https://www.sitepoint.com/community/t/url-validation-with-preg-match/3255/2
      if ( ! preg_match('/^(http|https):\\/\\/[a-zA-Z0-9_]+([\\-\\.]{1}[a-zA-Z_0-9]+)*\\.[_a-zA-Z]{2,5}'.'((:[0-9]{1,5})?\\/.*)?$/i',$target) &&
	   ! preg_match ("^urn:[a-zA-Z0-9][a-zA-Z0-9-]{0,31}:[a-zA-Z0-9()+,\-.:=@;\$_!*'%/?#]+$^", $target)) {
	errorexit("Not a valid URL: " . $target);
      }
      $ace = $ace . '      "ietf-mud:mud": { "controller" : "' . $target . '" }';
      break;
    case IS_CLOUD:
      if ( ! preg_match('/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,3}$/',$target)) {
	errorexit("Not a domain name: " . $target);
      }
    
      if ( $pdirect == "to-device" ) {
          $clfrag = '"ietf-acldns:src-dnsname": "';
      } else {
          $clfrag = '"ietf-acldns:dst-dnsname": "';
      }
    $clfrag = $clfrag . $target . '"'; /* this becomes an l3 component */
    
      break;
    case IS_MFG:
        if ( ! preg_match('/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,3}$/',$target)) {
            errorexit("Not a domain name: " . $target);
        }
        $ace = $ace . '      "ietf-mud:mud" : { "manufacturer" : "' . $target . '" }';
        break;
    case IS_MYMFG:
        $ace = $ace . '     "ietf-mud:mud" : { "same-manufacturer" : [ null ]}';
        break;
    
  }
  
    /* in both cases we left off the comma because we don't know if there
     * is another line, so... */

  if ( $proto == 'any' ) { /* just close off the cloud bit (if necessary) */
      if ( $type == IS_CLOUD ) {
          $l3frag = '"ipv4" : { ' . $clfrag . '}';
          $ace = $ace . $l3frag;

      }
  } else { // tcp or udp

      // create an l3frag and add protocol info.
      $l3frag = '"ipv4" : { ';
      if ( $type == IS_CLOUD ) {
          $l3frag = $l3frag . $clfrag . ",";
          $addcomma='';
      } else {
          $l3frag = ',' . $l3frag;
      }
      
      if ( $proto == "tcp" ) {
          $l3frag = $l3frag . '"protocol" : 6 }'; 
      } else {
          $l3frag = $l3frag . '"protocol" : 17 }';
      }
      $ace = $ace . $l3frag;
      $l4frag="";
      
      $endfrag = '}';
      if ( $proto == 'tcp' ) {
          $l4frag = $l4frag . ', "tcp" : {';
          if ( $dirinit == 'thing' ) {
              $l4frag= $l4frag . '"ietf-mud:direction-initiated" : "from-device"';
          } else {
              if ( $dirinit == "remote" ) {
              $l4frag= $l4frag . '"ietf-mud:direction-initiated" : "to-device"';
              }
          }
      } else {
          $l4frag = $l4frag . ', "udp" : {';
      }
      
      $pfrag='';
      $pex1='';
      $pex2='';
      
      if ( $pdirect == "to-device"  ) {
          $pex1= mkportrange("source-port",$port, $dirinit);
          $pex2= mkportrange("destination-port",$lport,$dirinit) ;
      } else {
          $pex1=mkportrange("destination-port",$port, $dirinit);
          $pex2=mkportrange("source-port",$lport,$dirinit);
      }

      if ( $pex1 != '' ) {
          $pfrag = $pex1;
      }

      if ( $pex2 != '' ) {
          if ( $pex1 != '' ) {
              $pfrag=$pfrag . ",";
          }
          $pfrag = $pfrag . $pex2;
      }
      
          

      if ( strlen($pfrag) > 0 || $dirinit == 'thing' ||
          $dirinit == 'remote' ) {
          $ace = $ace . $l4frag . $pfrag . $endfrag;
      }
      
  
  }
  
  
  

    /* now close off matches, add action to the ACE and return it. */
    
    $ace = $ace . "\n }, " . '"actions" : {' . "\n " .
      '"forwarding" : "accept"' . "\n  }\n   }\n";
    return($ace);
}
               
  function checkportrange($p) {

      if ( $p != 'any' ) {
          if ( (! is_numeric($p)) || ( $p < 0 || $p > 65535 )) {
              errorexit('Invalid port range: use "any" or 0 - 65536');
          }
      }
}
  

function buildacegroup(&$target, &$proto, &$portl, &$portarray,
                       &$dirinit,  $namehead,$type) 
{
  global $inbound, $outbound, $gotin, $gotout;


  // loop through all entries in array
  // we can rely on proto as being set to SOME value...

  for ($i = 0; isset($proto[$i]); $i++)
    {
      // for each line build two ACEs, one for the inbound ACL and
      // one for the outbound ACL.
      
      if ( $target[$i] == '' ) { // there may be no there there, especially on 0.
          continue;
      }
      
      if ( $i > 0 || $gotin > 0 ) {
          $outbound = $outbound . "  ,\n";
          $inbound = $inbound . "  ,\n";
      } else {
      	  $gotin = 1;
      }

      if ( $proto[$i] == 'any' ) {
          $port = FALSE;
      } else {
          if ( $proto[$i] == 'udp' || $proto[$i] == 'tcp') {
              $port = $portarray[$i];
      
              checkportrange($port);
              checkportrange($portl[$i]);
          }
          else {
              errorexit("unsupported protocol");
          }
      }
      if ( $proto[$i] != 'tcp' && $dirinit[$i] != 'either' ) {
          errorexit("direction initiated requires TCP");
      }
      
      
      $s1= $namehead  . $i . "-frdev" ;
      $s2= $namehead . $i . "-todev";
      
      /* a little kludge here.  if we are dealing with local networks
       * then $target is = FALSE.
       */

      if ( $type == IS_LOCAL ) {
          $t2 = 'local';
      } else {
          $t2= $target[$i];
      }
      
      $outbound = $outbound . addace($s1,"from-device", 
                     $t2, $proto[$i],$portl[$i],
				     $port, $type,$dirinit[$i]);
      
      $inbound = $inbound . addace($s2,"to-device",
                   $t2, $proto[$i], $portl[$i],
				   $port, $type,$dirinit[$i]);
    }
}


  
$inbound="";
$outbound="";
    
$choice=$_POST['ipchoice'];
/* $doegress=$_POST['bibox']; */
$doegress="Yes";

// Not necessary to generate actual ACLs, but we need to know at this
// point in the code.

if ( isset($_POST['clbox']) || isset($_POST['entbox']) ||
     isset($_POST['myctlbox']) || isset($_POST['locbox']) ||
     isset($_POST['manbox']) || isset($_POST['mymanbox'])) {
     $gotacls=1;
     } else {
     $gotacls=0;
}

if ( $gotacls ) {

   if ( $choice != 'ipv4' && $choice != 'ipv6' && $choice != 'both' ) {
     errorexit("No IP version chosen");
   }
  
  // We start by processing cloud communications

  if ( isset($_POST['clbox'] ) ) {
     // build based on cloud outbound

     if (isset($_POST['clport']))  { // distinctly possible user didn't enter ports
     	$clport= $_POST['clport'];
      } else {
        $clport= FALSE;
     }
  
     buildacegroup($_POST['clnames'],$_POST['clproto'],$_POST['clportl'],$clport,
      $_POST['clinit'], "cl",IS_CLOUD);
  }



// Next controller (enterprise)

  if ( isset($_POST['entbox'] )) {
    // build based on enterprise outbound
  
    if (isset($_POST['entproto']))  {
      // distinctly possible user didn't enter ports   
      $entport= $_POST['entport'];
    
    } else {
      $entport= FALSE;
    }
  
    buildacegroup($_POST['entnames'],$_POST['entproto'],$_POST['entportl'],$entport,
        $_POST['entinit'], "ent",IS_CONTROLLER);

  }

  // my-controller 

  if (isset($_POST['myctlport']))  {
     // distinctly possible user didn't enter ports   
    $myctlport= $_POST['myctlport'];
    
  } else {
    $myctlport= FALSE;
  }
  if ( isset($_POST['myctlbox']) ) {
    // build my-controller
      
      buildacegroup($_POST['myctlnames'],$_POST['myctlproto'],$_POST['myctlportl'],
      $myctlport, $_POST['myctlinit'], "myctl",IS_MY_CONTROLLER);
  }

  // local services

  if ( isset($_POST['locbox'])) {
    // build local outbound services.
    
    buildacegroup($_POST['locnames'],$_POST['locproto'],$_POST['locportl'],
       $_POST['locport'], $_POST['locinit'], "loc",IS_LOCAL);
  }

  // manufacturer

  if ( isset($_POST['manbox'])) {
    // build local inbound services.
    buildacegroup($_POST['mannames'],$_POST['manproto'],$_POST['manportl'],
       $_POST['manport'], $_POST['maninit'], "man",IS_MFG);
  }

  // my-manufacturer
  if ( isset($_POST['mymanbox'])) {
    // build local inbound services.
    buildacegroup($_POST['mymannames'],$_POST['mymanproto'],$_POST['mymanportl'],
     $_POST['mymanport'], $_POST['mymaninit'], "myman",IS_MYMFG);

  }
}


if ( $fail ) {
  exit;
}


  $d=new Datetime('NOW');
  $time=$d->format(DATE_RFC3339);

  $masa='';
  if ( isset($_POST['anbox']) ) {
    if ( $_POST['anbox'] == 'Yes' && preg_match('/^(http|https):\\/\\/[a-z0-9_]+([\\-\\.]{1}[a-z_0-9]+)*\\.[_a-z]{2,5}'.'((:[0-9]{1,5})?\\/.*)?$/i',$_POST['masa']) ) {
      $masa = '"masa-server" : "' . $_POST['masa'] . '",' . "\n";
      }
  }
  
  $sysDesc=htmlspecialchars($_POST['sysDescr'],ENT_QUOTES);
  $doc_url=htmlspecialchars($_POST['doc_url'],ENT_QUOTES);
  $model_name=htmlspecialchars($_POST['model_name'],ENT_QUOTES);
  $mudurl= "https://" . htmlspecialchars($_POST['mudhost'],ENT_QUOTES) .
  '/' . $model_name . ".json";
  $mudsig= "https://" . htmlspecialchars($_POST['mudhost'],ENT_QUOTES) .
  '/' . $model_name . ".p7s";
  $sbom_add='';
  if ( $_POST['sbom'] == 'cloud' ) {
    $sbom_add = '"sboms" : [ { "version-info" : "' . $_POST['sbomswver'] . '",' .
                '"sbom-url" :  "' . htmlspecialchars($_POST['sbomcloudurl'])
                 . '" } ]';
  } else if ( $_POST['sbom'] == 'local' ) {
    $schema =htmlspecialchars($_POST['sbschema'],ENT_QUOTES);
    $sbom_add = '"sbom-local-well-known" : "' . $schema . '"' ;
  } else if ( $_POST['sbom'] == 'tel' ) {
    $sbom_add =	'"contact-info" : "tel:+' . htmlspecialchars($_POST['sbomcc']) .
    	        htmlspecialchars($_POST['sbomnr']) . '"';
  } else if ( $_POST['sbom'] == 'infourl' ) {
    $sbom_add =	'"contact-info" : "' . htmlspecialchars($_POST['infourl']) . '"';
  } else if ( $_POST['sbom' ] == 'c2' ) {
    $schema =htmlspecialchars($_POST['sbschema'],ENT_QUOTES);
    $sbom_add = '"local-well-known" : "openc2"' ;
  }

  $vuln_add='';
  if ( $_POST['vulntype'] == "url" ) {
    if ( $sbom_add != '' ) {
       $vuln_add = ', ';
    }
    $vuln_add = $vuln_add . '"vuln-url" : [ "' . htmlspecialchars($_POST['vulninfo']) . '" ]';
  }
  $exts = '"ol"';
  if ( $sbom_add != '' || $vuln_add != '' ) {
    $exts = $exts . ' , ' . '"transparency"' ;
    $transparency = '"mudtx:transparency" : { ' . $sbom_add . $vuln_add . '},';
  }

  $exts = '"extensions": [ ' . $exts . '],';
  if( isset($_POST['man_name']) && strlen(htmlspecialchars($_POST['man_name'],ENT_QUOTES)) > 0) {
    $man_name = htmlspecialchars($_POST['man_name'],ENT_QUOTES);
    $mfg_info = '"mfg-name": "' . $man_name . '",' . "\n";
  } else {
    $mfg_info = '';
  }
  if ( isset($_POST['pubsame'])) {
    $d = new DateTime('NOW');
    $year = $d->format('Y');
    $publisher = "Copyright (c) " . $man_name . " " . $year . ". All Rights Reserved";
  } else {
    $publisher = htmlspecialchars($_POST['pub_name']);
  }
  $olstring = '"ol" : { "owners" : [ "' . $publisher . '" ],' .
  	    '"spdx-tag" : "0BSD" },';
  $supportInfo = $actxt0 . $exts . $olstring . $transparency .
  	       '"mud-url" : "' . $mudurl . '",
  	       "mud-signature" : "' . $mudsig . '",
  	       "last-update" : "' . $time . '",' . "\n" .
	       '"cache-validity" : 48,' .
	       '"is-supported": true,' . "\n" .
	       $masa . '"systeminfo": "' . $sysDesc . '",' . "\n" .
	       $mfg_info .
	       '"documentation": "' . $doc_url . '",' . "\n" .
	       '"model-name": "' . $model_name . '"';
  if ( $gotacls ) {
    $supportInfo = $supportInfo . ',' . "\n";
  } else {
    $supportinfo = $supportInfo . "\n";
  }

  $devput = "{\n". $supportInfo . "\n";

if ( ! $gotacls ) {
  $output = $devput . '} }';

} else {
  $mudname="mud-" . rand(10000,99999) . "-";
  $v4in = $mudname . "v4to";
  $v4out = $mudname . "v4fr";
  $v6in  = $mudname . "v6to";
  $v6out = $mudname . "v6fr";

  $pre4in='';
  $pre4out='';
  $pre6in='';
  $pre6out='';
  $output='';
  $ipv4outbound = '';

  
  if ( $choice == "ipv4" || $choice == "both" ) {
      $pre4in = '{ "name" : "' . $v4in . '" ' . "\n" . ' }' . "\n";
      $pre4out =  '{ "name" : "' . $v4out . '" ' . "\n" .  ' }' . "\n";
      if ( $doegress == 'Yes' ) {
         $ipv4inbound = '[ { "name" : "' . $v4in . '",' . "\n" .
             '"type" : "ipv4-acl-type",' .
             "\n" . '"aces" : {' . '"ace" : [';
         $ipv4inbound= $ipv4inbound . $inbound . " ]}},\n";
	 } else {
	    $ipv4inbound='';
	    $ipv4outbound = '[';
	    $pre4in='';
	    }
      $ipv4outbound = $ipv4outbound . ' { "name" : "' . $v4out . '",' . "\n" .
          '"type" : "ipv4-acl-type",'  .
          "\n" . '"aces" : {'  . '"ace" : [';
      $ipv4outbound= $ipv4outbound . $outbound . " ]}}\n";
      $output = $output . $ipv4inbound . $ipv4outbound;
  
    }

  if ( $choice == "ipv6" || $choice == "both" ) {
      $pre6in = '{ "name" : "' . $v6in . '"' . "\n" . '}';
      $pre6out =  '{ "name" : "' . $v6out . '"' . "\n" . '}';
      if ( $choice == "ipv6" ) {
          $addsquiggle = "[ ";
      } else {
          $addsquiggle = "";
      }
      if ( $doegress == 'Yes' ) {
         $ipv6inbound = $ipv6inbound . '{ "name" : "' . $v6in . '",' . "\n" .
         '"type" : "ipv6-acl-type",' . "\n" .
         '"aces" : {' . '"ace" : [';
         $ipv6inbound= $ipv6inbound . str_replace("ipv4","ipv6",$inbound) . " ]}},\n";
	 } else {
	    $pre6in='';
	    $ipv6inbound = '';
	 }
      $ipv6outbound = ' { "name" : "' . $v6out . '",' . "\n" .
      '"type" : "ipv6-acl-type",' .
      "\n" . '"aces" : {' . '"ace" : [';
      $ipv6outbound= $ipv6outbound . str_replace("ipv4","ipv6",$outbound) . "]}}\n";

      if ( $choice == 'both' ) {
          $output = $output . ","; 
      }
      $output = $output . $addsquiggle . $ipv6inbound . $ipv6outbound;
  }
  

  $devput = $devput . $actxt1 . $pre4out;

  $comma="";
  
  if ( $choice == 'both' ) {
      $comma=", ";
  }
  if ( $choice == 'ipv6' || $choice == "both" ) {

      $devput = $devput . $comma . $pre6out;
  }
      
  if ( $doegress == 'No' ) {
     $actxt1b = '';
     $pre4in = '';
     $actxt1a ='';
       $pre6in='';
  }

  $devput = $devput  . $actxt1a . $actxt1b . $pre4in;
  
  if ( $doegress == 'No' ) {
     $comma = '';
  }
  if ( $choice == 'ipv6' || $choice == "both" ) {
      $devput = $devput . $comma . $pre6in;
  }
  
  $devput = $devput . $actxt2;
  
  $output = $devput . $aclhead . $output . "]}}";
}
  $b64in = $output;
  $output= prettyPrint($output);

/* and now we sign with a demo signature. store mudfile into file, and then
 * call cms_sign.  Read in the resultant file, and attach it to a button.
 */

  $mudtmpfile = tempnam(sys_get_temp_dir(),"mud");
  $ziptmpfile = $mudtmpfile . ".zip";
  $signcert="/etc/ssl/certs/mudsigner.crt";
  $intcert="/etc/ssl/certs/mudi2.crt";
  $signkey="/etc/ssl/private/mudsigner.key";
  $mudfp=fopen($mudtmpfile, "w") or die("Unable to open file!");
  fwrite($mudfp, $output) or die ("Unable to write file!");
  fclose($mudfp);
  $sigtmpfile = tempnam(sys_get_temp_dir(),"sig");

  //  openssl_cms_sign($mudtmpfile,$sigtmp,$sigtmpfile,
  //   openssl_x509_read($signcert),$signkey,
  // NULL, CMS_DETACHED|CMS_BINARY, OPENSSL_ENCODING_DER);
  $pinfo = ( "Manufacturer" => $man_name, "Model" => $model_name,
             "CountryCode" => "US",
             "MudUrl" => $mudurl, "SerialNumber" => "S12345",
             "Mudfile" => $output, "EmailAddress" => "mudfiles@" . 
             htmlspecialchars($_POST['mudhost'],ENT_QUOTES)
  );
  $pb64 = base64_encode(json_encode($pinfo));
  //  $cmd="/usr/bin/openssl cms -sign -binary -signer " . $signcert .
  //       " -in " . $mudtmpfile . " -inkey " . $signkey . 
  //       " -outform DER -certfile " . $intcert . " -out " . $sigtmpfile;
  //  exec($cmd);
  //  $sigfp=fopen($sigtmpfile,"rb") or die("Cannot read signature");
  
  //  $signature = fread($sigfp,32000);
  //  fclose($sigfp);
  //  $z=new zipArchive();
  //  $z->open($ziptmpfile,ZIPARCHIVE::CREATE);
  //  $z->addFromString($model_name . ".json", $output);
  //  $z->addFromString($model_name . ".p7s", $signature);
  //  $z->close();
  //  $zfp = $sigfp=fopen($ziptmpfile,"rb") or die("Cannot read signature");
  //  $zcontent= base64_encode(fread($zfp,64000));
  //  fclose($zfp);
  //  unlink($mudtmpfile);
  //  unlink($sigtmpfile);
  //  unlink($ziptmpfile);    
  session_unset();
  //  $_SESSION['zipfile'] = $zcontent;
  $_SESSION['model'] = $model_name;
  //  $_SESSION['mudfile'] = $output;
  $_SESSION['pb64' ] = $pb64
  print "<!DOCTYPE html>\n<html>\n";
  print  "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n";
  print  "<link rel=\"stylesheet\" href=\"assets/css/main.css\">\n";
  print  "<script type=\"text/javascript\" src=\"aux.js\" defer=\"defer\"></script> ";
 
  print "<body>\n";
  print "<section id=\"banner_makemud\">\n";
  print "<h1>Your MUD file is ready!</h1>";
  print "<p>Congratulations!  You've just created a MUD file.  Simply ";
  print "download the file after reviewing it below.  Next you can\n";
  print "visualize the results.  You can also sign the file and place it in the location that its corresponding ";
  print "MUD URL will find.  You can find instructions on how to sign your " ;
  print "MUD file <a href=\"https://www.mudmaker.org/signing.html\">here.</a>";
  print "If you download the MUD file, it comes as a ZIP file with an example";
  print "signature for testing purposes.  You can validate that signature using ";
  print "<a href=\"mudmakerCA.crt\">this demonstration CA root.</a>";
  print "<br>";

  print $downloadtext;
  print "<button type=\"button\" class=\"button special\" onclick=\"j2pp('" . base64_encode($b64in) . "')\">ACL Text</button>";
  print "</form>";
  print "</section>";
  print "<div id=\"mudresults\">";
  print "<hr>\n";
  print "<div style=\"float: right\"><figure>";
  $qrc= (new QRcode)->render($mudurl);
  printf('<img src="%s" alt="QR code"/>',$qrc);
  print "<figcaption style=\"text-align: center\">Your MUDURL<br></figcaption>";
  print "</figure></div>";
  print "<pre style=\"padding: 1em 1em 1em 1em; font-weight: bold;\">" . htmlentities($output) . "</pre>";
  print "<hr></div>\n";
  print "</body>\n</html>";

?>
