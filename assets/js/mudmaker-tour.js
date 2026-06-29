// Copyright 2017-2026 Eliot Lear
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0
//
// Lightweight, dependency-free guided tour for mudmaker.html.
//
// Exposes window.MudMakerTour = { start, stop, isActive }.  The first
// visit (no matching cookie) triggers start() automatically once the
// DOM is ready; subsequent visits only start it when the user clicks
// the Tour button.  Escape, clicking the backdrop, or "Skip" cleanly
// dismiss the tour and restore prior UI state.
//
// The "seen" state is recorded in a long-lived first-party cookie
// whose value is the current TOUR_TOKEN.  Bumping TOUR_TOKEN (for
// example when the tour content changes meaningfully) forces every
// returning visitor to see the new tour exactly once.
(function (global) {
	"use strict";

	// Long, unique token written to the cookie when the tour is
	// dismissed.  Change this string to force re-display for every
	// returning visitor.
	var TOUR_TOKEN =
		"mm-tour-v1-9f4c2a1e3b7d4f8e8a6c5b2d1e7f3a9c-7b8e2d1a";
	var COOKIE_NAME = "mudmaker_tour_seen";
	// ~5 years in seconds; cookie is renewed each time the tour ends.
	var COOKIE_MAX_AGE = 60 * 60 * 24 * 365 * 5;

	function readCookie(name) {
		var raw = (typeof document !== "undefined" && document.cookie)
			? document.cookie : "";
		var parts = raw ? raw.split(";") : [];
		for (var i = 0; i < parts.length; i++) {
			var kv = parts[i].split("=");
			var key = (kv.shift() || "").trim();
			if (key === name) {
				try { return decodeURIComponent(kv.join("=")); }
				catch (e) { return kv.join("="); }
			}
		}
		return null;
	}

	function writeSeenCookie() {
		try {
			var secure = (location.protocol === "https:")
				? "; Secure" : "";
			document.cookie = COOKIE_NAME + "=" +
				encodeURIComponent(TOUR_TOKEN) +
				"; Max-Age=" + COOKIE_MAX_AGE +
				"; Path=/; SameSite=Lax" + secure;
		} catch (e) { /* cookies disabled; ignore */ }
	}

	function hasSeenCurrentTour() {
		return readCookie(COOKIE_NAME) === TOUR_TOKEN;
	}

	// Each step targets one or more existing DOM elements via selector.
	// `tab` (optional) switches the named tab before the step is shown.
	// `openDetails` (optional) is a list of <details> selectors to open
	// for the step's duration; they are restored to their previous
	// state when the tour ends.
	var STEPS = [
		{
			id: "welcome",
			selector: "#banner",
			title: "Welcome to MUD Maker",
			body: "A quick tour of the main features. Press Esc " +
				"any time to exit.",
			placement: "bottom"
		},
		{
			id: "tabs",
			selector: ".tab",
			title: "Three workflows",
			body: "Create your MUD file here, View the generated " +
				"JSON, or Sign and Publish it.",
			placement: "bottom"
		},
		{
			id: "privacy",
			selector: "#privacy-note",
			title: "Your data stays here",
			body: "Nothing you type is saved unless you choose to " +
				"publish to GitHub.",
			placement: "bottom"
		},
		{
			id: "url",
			selector: "#mud-url-builder",
			title: "Build your MUD URL",
			body: "Combine a hostname and a model name to form the " +
				"MUD URL your device will advertise.",
			placement: "bottom"
		},
		{
			id: "basics",
			selector: "#basic-info",
			title: "Basic information",
			body: "Describe the device: manufacturer, summary, " +
				"documentation URL, and a contact email.",
			placement: "bottom"
		},
		{
			id: "sbom",
			selector: "#sbom",
			title: "Software Bill of Materials",
			body: "Optionally point to an SBOM and a vulnerability " +
				"information source.",
			placement: "bottom"
		},
		{
			id: "acls",
			selector: "#acl-section",
			title: "Allowed traffic",
			body: "Declare what your device may talk to. Expand a " +
				"category to add entries.",
			placement: "bottom"
		},
		{
			id: "visualizer",
			selector: "#mud-live-visualizer",
			title: "Live visualizer",
			body: "Your MUD file is drawn here as you build it. " +
				"On a wide screen it sits beside the form.",
			placement: "left"
		},
		{
			id: "dropzone",
			selectors: ["#mud-live-save", "#mud-live-toggle",
				"#mud-live-visualizer"],
			title: "Save, load, maximize",
			body: "Use the disk icon to save your work. Drop a MUD " +
				".json or .pcap onto the visualizer to load it " +
				"(Shift-drop replaces, plain drop merges). The " +
				"square icon expands the visualizer.",
			placement: "left"
		},
		{
			id: "publish",
			selector: "#pubbutton",
			title: "Sign and publish",
			body: "When you are ready, sign locally or submit your " +
				"MUD file to the IoT Onboarding GitHub for review.",
			placement: "top",
			tab: "publish"
		}
	];

	// Active tour state.  null when no tour is running.
	var state = null;

	function $(selector) {
		return document.querySelector(selector);
	}

	function currentTabId() {
		var active = document.querySelector(".tabcontent[style*=\"block\"]");
		return active ? active.id : null;
	}

	function switchTab(tabId) {
		if (!tabId) { return; }
		if (currentTabId() === tabId) { return; }
		// tabs.js exposes openTab(event, name) but tolerates a null
		// event when called programmatically by other modules.
		var btn = Array.prototype.find.call(
			document.querySelectorAll(".tablinks"),
			function (b) {
				return (b.getAttribute("onclick") || "").indexOf(
					"'" + tabId + "'") !== -1;
			});
		if (btn && typeof global.openTab === "function") {
			global.openTab({ currentTarget: btn }, tabId);
		}
	}

	function openDetailsList(selectors) {
		var opened = [];
		(selectors || []).forEach(function (sel) {
			var el = $(sel);
			if (el && el.tagName === "DETAILS" && !el.open) {
				el.open = true;
				opened.push(el);
			}
		});
		return opened;
	}

	function restoreDetails(list) {
		(list || []).forEach(function (el) { el.open = false; });
	}

	function targetsForStep(step) {
		var sels = step.selectors || [step.selector];
		return sels.map($).filter(Boolean);
	}

	function unionRect(els) {
		var rect = null;
		els.forEach(function (el) {
			var r = el.getBoundingClientRect();
			if (!rect) {
				rect = { top: r.top, left: r.left,
					right: r.right, bottom: r.bottom };
			} else {
				rect.top = Math.min(rect.top, r.top);
				rect.left = Math.min(rect.left, r.left);
				rect.right = Math.max(rect.right, r.right);
				rect.bottom = Math.max(rect.bottom, r.bottom);
			}
		});
		return rect;
	}

	function buildOverlay() {
		var root = document.createElement("div");
		root.className = "mud-tour-root";
		root.setAttribute("data-mud-tour", "1");

		var svgNS = "http://www.w3.org/2000/svg";
		var svg = document.createElementNS(svgNS, "svg");
		svg.setAttribute("class", "mud-tour-overlay");
		svg.setAttribute("aria-hidden", "true");
		var mask = document.createElementNS(svgNS, "mask");
		mask.setAttribute("id", "mud-tour-mask");
		var full = document.createElementNS(svgNS, "rect");
		full.setAttribute("x", "0"); full.setAttribute("y", "0");
		full.setAttribute("width", "100%");
		full.setAttribute("height", "100%");
		full.setAttribute("fill", "white");
		var hole = document.createElementNS(svgNS, "rect");
		hole.setAttribute("id", "mud-tour-hole");
		hole.setAttribute("rx", "10"); hole.setAttribute("ry", "10");
		hole.setAttribute("fill", "black");
		mask.appendChild(full);
		mask.appendChild(hole);
		var defs = document.createElementNS(svgNS, "defs");
		defs.appendChild(mask);
		svg.appendChild(defs);
		var dim = document.createElementNS(svgNS, "rect");
		dim.setAttribute("x", "0"); dim.setAttribute("y", "0");
		dim.setAttribute("width", "100%");
		dim.setAttribute("height", "100%");
		dim.setAttribute("fill", "rgba(30, 22, 50, 0.65)");
		dim.setAttribute("mask", "url(#mud-tour-mask)");
		svg.appendChild(dim);
		root.appendChild(svg);

		// Click on the backdrop (anywhere on the SVG) closes the tour.
		svg.addEventListener("click", stop);

		var popover = document.createElement("div");
		popover.className = "mud-tour-popover";
		popover.setAttribute("role", "dialog");
		popover.setAttribute("aria-modal", "true");
		popover.setAttribute("aria-labelledby", "mud-tour-title");
		popover.setAttribute("aria-describedby", "mud-tour-body");
		popover.tabIndex = -1;

		var head = document.createElement("div");
		head.className = "mud-tour-head";
		var title = document.createElement("h3");
		title.id = "mud-tour-title";
		title.className = "mud-tour-title";
		var close = document.createElement("button");
		close.type = "button";
		close.className = "mud-tour-close";
		close.setAttribute("aria-label", "Close tour");
		close.textContent = "\u00d7";
		close.addEventListener("click", stop);
		head.appendChild(title);
		head.appendChild(close);

		var body = document.createElement("p");
		body.id = "mud-tour-body";
		body.className = "mud-tour-body";

		var foot = document.createElement("div");
		foot.className = "mud-tour-foot";
		var progress = document.createElement("span");
		progress.className = "mud-tour-progress";
		var skip = document.createElement("button");
		skip.type = "button";
		skip.className = "mud-tour-skip";
		skip.textContent = "Skip tour";
		skip.addEventListener("click", stop);
		var nav = document.createElement("div");
		nav.className = "mud-tour-nav";
		var back = document.createElement("button");
		back.type = "button";
		back.className = "mud-tour-back";
		back.textContent = "Back";
		back.addEventListener("click", prev);
		var next = document.createElement("button");
		next.type = "button";
		next.className = "mud-tour-next";
		next.textContent = "Next";
		next.addEventListener("click", advance);
		nav.appendChild(back);
		nav.appendChild(next);
		foot.appendChild(progress);
		foot.appendChild(skip);
		foot.appendChild(nav);

		popover.appendChild(head);
		popover.appendChild(body);
		popover.appendChild(foot);
		root.appendChild(popover);

		document.body.appendChild(root);

		return {
			root: root, svg: svg, hole: hole, popover: popover,
			title: title, body: body, progress: progress,
			back: back, next: next, skip: skip, close: close
		};
	}

	function teardownOverlay() {
		if (state && state.ui && state.ui.root && state.ui.root.parentNode) {
			state.ui.root.parentNode.removeChild(state.ui.root);
		}
	}

	function positionHole(rect) {
		var pad = 8;
		var hole = state.ui.hole;
		var x = Math.max(0, rect.left - pad);
		var y = Math.max(0, rect.top - pad);
		var w = (rect.right - rect.left) + (pad * 2);
		var h = (rect.bottom - rect.top) + (pad * 2);
		hole.setAttribute("x", x);
		hole.setAttribute("y", y);
		hole.setAttribute("width", w);
		hole.setAttribute("height", h);
	}

	function positionPopover(rect, placement) {
		var pop = state.ui.popover;
		// Force a layout so offsetWidth/Height reflect content.
		pop.style.visibility = "hidden";
		pop.style.display = "block";
		var pw = pop.offsetWidth;
		var ph = pop.offsetHeight;
		var vw = window.innerWidth;
		var vh = window.innerHeight;
		var margin = 16;
		var x, y;

		switch (placement) {
		case "top":
			x = rect.left + ((rect.right - rect.left) / 2) - (pw / 2);
			y = rect.top - ph - margin;
			break;
		case "left":
			x = rect.left - pw - margin;
			y = rect.top + ((rect.bottom - rect.top) / 2) - (ph / 2);
			break;
		case "right":
			x = rect.right + margin;
			y = rect.top + ((rect.bottom - rect.top) / 2) - (ph / 2);
			break;
		case "bottom":
		default:
			x = rect.left + ((rect.right - rect.left) / 2) - (pw / 2);
			y = rect.bottom + margin;
		}

		// Clamp into the viewport so the popover is always reachable.
		if (x + pw + margin > vw) { x = vw - pw - margin; }
		if (x < margin) { x = margin; }
		if (y + ph + margin > vh) { y = vh - ph - margin; }
		if (y < margin) { y = margin; }

		pop.style.left = x + "px";
		pop.style.top = y + "px";
		// Expose placement so CSS can orient the balloon tail toward
		// the highlighted element.
		pop.setAttribute("data-placement", placement);
		pop.style.visibility = "";
	}

	function show(index) {
		if (!state) { return; }
		if (index < 0 || index >= STEPS.length) { stop(); return; }
		state.index = index;

		var step = STEPS[index];

		// Restore <details> opened by the previous step before opening
		// any new ones, so each step has a clean baseline.
		restoreDetails(state.openedDetails);
		state.openedDetails = [];

		if (step.tab) {
			switchTab(step.tab);
		}
		state.openedDetails = openDetailsList(step.openDetails);

		// Wait one frame so the DOM reflects tab and details changes
		// before measuring bounding rectangles.
		requestAnimationFrame(function () {
			var targets = targetsForStep(step);
			if (!targets.length) {
				// If the target is missing (e.g. element hidden in a
				// version of the page), skip the step rather than
				// silently break the tour.
				advance();
				return;
			}
			targets[0].scrollIntoView({
				block: "center",
				behavior: "auto"
			});
			// After the scroll, measure on the next frame so bounding
			// rects reflect the final positions.
			requestAnimationFrame(function () {
				var rect = unionRect(targets);
				positionHole(rect);
				positionPopover(rect, step.placement || "bottom");
				state.ui.title.textContent = step.title;
				state.ui.body.textContent = step.body;
				state.ui.progress.textContent =
					"Step " + (index + 1) + " of " + STEPS.length;
				var isLast = (index === STEPS.length - 1);
				state.ui.next.textContent = isLast ? "Done" : "Next";
				state.ui.back.disabled = (index === 0);
				state.ui.popover.focus();
			});
		});
	}

	function advance() {
		if (!state) { return; }
		if (state.index >= STEPS.length - 1) {
			stop();
			return;
		}
		show(state.index + 1);
	}

	function prev() {
		if (!state) { return; }
		if (state.index <= 0) { return; }
		show(state.index - 1);
	}

	function onKey(e) {
		if (!state) { return; }
		if (e.key === "Escape") {
			e.preventDefault();
			stop();
		} else if (e.key === "ArrowRight") {
			e.preventDefault();
			advance();
		} else if (e.key === "ArrowLeft") {
			e.preventDefault();
			prev();
		} else if (e.key === "Enter") {
			// Only intercept Enter when focus is inside the popover so
			// the rest of the page (forms, etc.) is unaffected.
			if (state.ui.popover.contains(document.activeElement)) {
				e.preventDefault();
				advance();
			}
		}
	}

	function onResize() {
		if (!state) { return; }
		// Re-render the current step to recompute positions.
		show(state.index);
	}

	function start() {
		if (state) { return; }
		var reducedMotion = false;
		try {
			reducedMotion = window.matchMedia(
				"(prefers-reduced-motion: reduce)").matches;
		} catch (e) { /* ignore */ }

		state = {
			index: 0,
			prevFocus: document.activeElement,
			prevTab: currentTabId(),
			openedDetails: [],
			reducedMotion: reducedMotion,
			ui: null
		};
		state.ui = buildOverlay();
		document.addEventListener("keydown", onKey, true);
		window.addEventListener("resize", onResize);
		show(0);
	}

	function stop() {
		if (!state) { return; }
		document.removeEventListener("keydown", onKey, true);
		window.removeEventListener("resize", onResize);
		restoreDetails(state.openedDetails);
		if (state.prevTab && currentTabId() !== state.prevTab) {
			switchTab(state.prevTab);
		}
		teardownOverlay();
		try {
			if (state.prevFocus && state.prevFocus.focus) {
				state.prevFocus.focus();
			}
		} catch (e) { /* ignore */ }
		writeSeenCookie();
		state = null;
	}

	function isActive() { return !!state; }

	function maybeAutoStart() {
		// Escape hatch for browser tests and embedding contexts that
		// never want the auto-open to fire.  Set before this script
		// runs (e.g. via Playwright's add_init_script).
		if (global.MUDMAKER_NO_TOUR) { return; }
		if (hasSeenCurrentTour()) { return; }
		// Defer slightly so the form, visualizer, and other deferred
		// scripts have finished their first paint before we measure.
		setTimeout(start, 250);
	}

	global.MudMakerTour = {
		start: start,
		stop: stop,
		isActive: isActive
	};

	if (document.readyState === "loading") {
		document.addEventListener("DOMContentLoaded", maybeAutoStart);
	} else {
		maybeAutoStart();
	}
}(window));
