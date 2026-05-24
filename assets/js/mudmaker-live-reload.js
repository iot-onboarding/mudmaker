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

(function(global) {
	"use strict";

	var reloadNavigation = false;

	function isReloadNavigation() {
		var entries;
		if (global.performance && typeof global.performance.getEntriesByType === "function") {
			entries = global.performance.getEntriesByType("navigation");
			if (entries && entries.length) {
				return entries[0].type === "reload";
			}
		}
		if (global.performance && global.performance.navigation) {
			return global.performance.navigation.type === global.performance.navigation.TYPE_RELOAD;
		}
		return false;
	}

	function resetRestoredFormState() {
		var form = global.document && global.document.getElementById("mudform");
		var details;

		if (form) {
			form.reset();
		}
		if (!global.document || typeof global.document.getElementsByTagName !== "function") {
			return;
		}
		details = global.document.getElementsByTagName("details");
		Array.prototype.forEach.call(details, function(detail) {
			detail.open = false;
		});
	}

	reloadNavigation = isReloadNavigation();
	if (!reloadNavigation) {
		return;
	}
	try {
		global.sessionStorage.removeItem("mudfile");
		global.sessionStorage.removeItem("pcap");
		global.sessionStorage.removeItem("gottoken");
	} catch (e) {
		return;
	}
	if (global.document && global.document.readyState === "loading") {
		global.document.addEventListener("DOMContentLoaded", resetRestoredFormState);
	} else {
		resetRestoredFormState();
	}
})(window);
