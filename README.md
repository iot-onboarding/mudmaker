# Welcome to MudMaker

This package generates and visualizes Manufacturer Usage Description (MUD) files.

MUD intended to assist IoT device manufacturers in explaining what network resources they need.  This tool is realized on [mudmaker.org](https://mudmaker.org)

For more information about MUD, see [RFC8520](https://tools.ietf.org/html/rfc8520).

Please feel free to post issues and PRs.

This package also requires the python mudpp package, also available
from this project.

## Requirements

This version of MUD Maker is based on Python3, JavaScript and Go.  Signing
is supported with the [mudcerts](https://github.com/iot-onboarding/mudcerts) package.
At this time, the GitHub PR integration is not publicly available.

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

## ToDo

The following items are on the ToDo List:

* Better integration with visualizer.
* Ability to edit MUD file and have it properly represented in the builder
* Uploading of PCAP files
* Interactive building of MUD files with those PCAP files (a'la mudgee)


