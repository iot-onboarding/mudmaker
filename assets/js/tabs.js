/**
 * Copyright 2017-2025 Eliot Lear
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

function b64_encode(str) {
	return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g,
        function toSolidBytes(match, p1) {
            return String.fromCharCode('0x' + p1);
		}
	))
}

function checklistValue(id) {
	let v = document.getElementById(id);
	let value = v && v.value != null ? v.value.trim() : '';

	return {
		valid: !!(v && v.validity.valid && value != ''),
		value: value
	};
}

function countryChecklistValue() {
	let country = document.getElementById("country");
	let option;

	if (!country || country.value == "0" || country.value == "") {
		return { valid: false, value: "" };
	}
	option = country.options[country.selectedIndex];
	return {
		valid: true,
		value: option ? option.textContent.trim() : country.value
	};
}

function mudUrlChecklistValue() {
	let mud = document.mudFile && document.mudFile["ietf-mud:mud"];
	let value = mud && mud["mud-url"] ? mud["mud-url"] : "";

	return {
		valid: value != "",
		value: value
	};
}

function appendChecklistItem(list, label, result) {
	let dom = window.MudSafeDom;
	let item = dom.element("li");

	if (result.valid) {
		dom.append(
			item,
			dom.statusText("\u2713", { style: { color: "green" } }),
			" ",
			label,
			": ",
			result.value
		);
	} else {
		dom.append(
			item,
			dom.statusText("\u2717", { style: { color: "red" } }),
			" ",
			label,
			": not set"
		);
	}
	dom.append(list, item);
	return result.valid;
}

function refreshSignRequirements() {
	let dom = window.MudSafeDom;
	let sign = dom.clear("sign-mandatories");
	let list;

	if (!sign) {
		return;
	}
	list = dom.element("ul", { style: { listStyleType: "none", marginBottom: "0" } });
	appendChecklistItem(list, "Manufacturer Name", checklistValue("mfg-name"));
	appendChecklistItem(list, "Device Model", checklistValue("model_name"));
	appendChecklistItem(list, "Country", countryChecklistValue());
	appendChecklistItem(list, "EMail Address", checklistValue("email_addr"));
	appendChecklistItem(list, "MUD URL", mudUrlChecklistValue());
	dom.append(
		sign,
		dom.element("p", { style: { margin: "0.75em 0 0.25em" } }, "Sign requires:"),
		list
	);
}

function refreshmans(){
	let dom = window.MudSafeDom;
	let mans = dom.clear("mandatories");
	let gtg = true;
	let list = dom.element("ul", { style: { listStyleType: "none" } });
	let displaytab = {
		"mudhost" : "Manufacturer Domain",
		"mfg-name" : "Manufacturer Name",
		"model_name" : "Device Model",
		"systeminfo" : "Device Description",
		"documentation" : "Documentation URL",
		"email_addr" : "EMail Address"
	};
	Object.keys(displaytab).forEach(
		(k) => {
			if (!appendChecklistItem(list, displaytab[k], checklistValue(k))) {
				gtg = false;
			}
		});
	dom.append(mans, list);
	refreshSignRequirements();
	let but = document.getElementById("pubbutton");
	if ( gtg ==  false ) {
		but.disabled = true;
	} else {
		but.disabled = false;
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
	} else if (tabName == "publish") {
		refreshmans();
		// Phase 3: whether we already have credentials is a purely
		// local question -- if the browser holds a session bearer in
		// sessionStorage, oAuthP1/oAuthP2 will use it; otherwise a
		// fresh OAuth dance runs.  No server round-trip needed here
		// (kills T-02, the /gottoken presence oracle).
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
