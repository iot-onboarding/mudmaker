# Welcome to MudMaker

This package generates and visualizes Manufacturer Usage Description (MUD) files.

MUD intended to assist IoT device manufacturers in explaining what network resources they need.  This tool is realized on [mudmaker.org](https://mudmaker.org)

For more information about MUD, see [RFC8520](https://tools.ietf.org/html/rfc8520).

Please feel free to post issues and PRs.

This package also requires the python mudpp package, also available
from this project.

## Requirements

This tool has been tested with PHP 8.3, php-zip, as well as composer with chillerlan/php-qrcode, using Apache 2.
For pretty printing of access lists, mudpp must be installed and exposed at /mudrest/mudpp.

### mud-visualizer submodule

To configure the mud-visualizer submodule properly, follow these steps: 

``` bash
$ git clone --recursive https://github.com/iot-onboarding/mudmaker
$ cd mudmaker
$ chmod +x create_symlinks.sh
$ ./create_symlinks.sh
```

To update the visualizer:

``` bash
$ cd mudmaker/mud-visualizer
$ git pull origin master
```
