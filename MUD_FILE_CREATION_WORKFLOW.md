# MUD File Creation Workflow

This package provides a browser-based workflow for creating, viewing, visualizing, saving, signing, and optionally publishing Manufacturer Usage Description (MUD) files.

1. Open `mudmaker.html`.
   The page opens on the Create tab and initializes a working MUD object in browser session storage. The initial object includes defaults such as MUD version, cache validity, and support status.

2. Enter the device identity.
   In the Create tab, the user provides the manufacturer domain, device model, manufacturer name, short device description, documentation URL, email address, country, IP mode, and publisher name.

   The tool builds the MUD URL from the manufacturer host and model:

   ```text
   https://{manufacturer-host}/{model}.json
   ```

   It also creates a matching MUD signature URL using the same base path with a `.p7s` suffix.

3. Add optional transparency metadata.
   The user can describe how to obtain a software bill of materials, including a cloud URL, a well-known URL on the device, telephone contact, or an informational URL. The user can also provide a vulnerability advisory URL.

4. Describe required network access.
   Under "What systems does this device need to talk to?", the user selects the categories of systems the device needs to reach or be reached by. Supported categories include named Internet hosts, this device's controller, local networks, controller classes, same-manufacturer devices, and devices identified by manufacturer domain.

   For each entry, the user can choose `Any`, `TCP`, or `UDP`, provide local and remote ports where applicable, and for TCP rules specify whether the device, the remote side, or either side initiates the connection.

5. Let the builder update the MUD JSON.
   As fields change, the JavaScript updates the in-memory MUD object and stores the working state in browser `sessionStorage`. The generated policy includes the relevant MUD fields, ACLs, ACEs, protocol matches, port matches, and to-device/from-device policy references.

6. View the generated MUD file.
   The user can open the View MUD File tab to inspect the current JSON representation of the MUD file.

7. Visualize the network behavior.
   The user can open the Visualize Network tab to render the generated MUD file through the visualizer iframe.

8. Save or continue work.
   In the Publish/Save/Continue Work tab, the user can save the current MUD file as a local JSON file. Later, the user can upload that saved JSON file through Continue Earlier Work to reload the MUD fields and continue editing.

9. Sign the completed MUD file.
   The user can click Sign to send the generated MUD file to the `/mudzip` endpoint. The response is downloaded as a ZIP file containing a sample signed MUD file and certificates. Signing requires the manufacturer name, model, country, email address, and MUD URL to be set.

10. Optionally publish to GitHub.
    The user can optionally upload a PCAP file and click Publish. The publish flow authenticates with GitHub, creates or reuses the user's `mudfiles` fork, creates a branch, commits the generated MUD file, and opens a pull request against `iot-onboarding/mudfiles`.

    GitHub publishing is optional. The UI notes that users do not need GitHub to create or store MUD files, and the README states that the GitHub pull request integration is not publicly available at this time.
