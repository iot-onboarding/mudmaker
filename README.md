# Welcome to MudMaker

This package generates and visualizes Manufacturer Usage Description (MUD) files.

MUD intended to assist IoT device manufacturers in explaining what network resources they need.  This tool is realized on [mudmaker.org](https://mudmaker.org)

For more information about MUD, see [RFC8520](https://tools.ietf.org/html/rfc8520).

MudMaker also supports two extensions from
[draft-lear-iotops-mudextras](https://datatracker.ietf.org/doc/draft-lear-iotops-mudextras/):

- `directed-broadcasts` — declares whether the device sends and/or
  receives directed broadcasts (see the *Multicast & Directed Broadcast*
  section of the form).
- `multicast-across-segments` — a marker that signals the device's
  multicast traffic may need to traverse network segments. Multicast
  destination addresses themselves are still listed as ordinary ACL
  entries (via the *Host or network address* category).

Please feel free to post issues and PRs.

This package also requires the python mudpp package, also available
from this project.

## Requirements

This version of MUD Maker is based on Python3, JavaScript and Go.  Signing
is supported with the [mudcerts](https://github.com/iot-onboarding/mudcerts) package.
At this time, the GitHub PR integration is not publicly available.

