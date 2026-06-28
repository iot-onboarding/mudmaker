/*
 * mudmaker-dragdrop.js
 *
 * Makes the live-visualizer aside (#mud-live-visualizer) a drop target
 * for MUD .json files and pcap captures.  Behavior parity:
 *   - dropping a single .json reuses MudMakerVisualizer.loadSavedWork,
 *     i.e. it loads the file exactly as "Continue Earlier Work" does;
 *   - dropping one or more .pcap / .pcapng files reuses the pcap picker
 *     plus generateMudFromPcap() — i.e. it loads the files exactly as
 *     selecting them through #pcapfile and clicking the "Generate MUD
 *     from PCAP" button would.
 *
 * UX rule:
 *   * default drop merges incrementally into the live MUD (so users can
 *     keep dragging captures in as they arrive);
 *   * holding Shift at drop time forces the historical replace
 *     behavior (overwrites whatever is in the editor).
 *
 * Mixed JSON+PCAP drops and drops containing multiple JSON files are
 * rejected with a status message.  Status is reported into the
 * existing #pcap-result element so the user sees feedback in the place
 * they already expect.
 *
 * Document-level dragover/drop preventDefault stops the browser from
 * navigating away if the user misses the drop zone.
 */
(function (global) {
	'use strict';

	function looksLikeJson(file) {
		var n = (file && file.name) ? file.name.toLowerCase() : '';
		var t = (file && file.type) ? file.type.toLowerCase() : '';
		if (n.endsWith('.json')) { return true; }
		if (t === 'application/json' || t === 'text/json') { return true; }
		return false;
	}

	function looksLikePcap(file) {
		var n = (file && file.name) ? file.name.toLowerCase() : '';
		var t = (file && file.type) ? file.type.toLowerCase() : '';
		if (n.endsWith('.pcap') || n.endsWith('.pcapng')
				|| n.endsWith('.cap')) { return true; }
		if (t === 'application/vnd.tcpdump.pcap'
				|| t === 'application/x-pcap'
				|| t === 'application/x-pcapng') { return true; }
		return false;
	}

	function classify(files) {
		var jsons = [];
		var pcaps = [];
		var other = [];
		for (var i = 0; i < files.length; i++) {
			var f = files[i];
			if (looksLikeJson(f)) { jsons.push(f); }
			else if (looksLikePcap(f)) { pcaps.push(f); }
			else { other.push(f); }
		}
		return { jsons: jsons, pcaps: pcaps, other: other };
	}

	function report(msg, isError) {
		var div = document.getElementById('pcap-result');
		if (!div) {
			if (isError && global.console) { global.console.warn(msg); }
			return;
		}
		while (div.firstChild) { div.removeChild(div.firstChild); }
		div.appendChild(document.createTextNode(msg));
		div.style.color = isError ? '#b00020' : '';
	}

	function hasExistingAces() {
		var mf = document.mudFile;
		if (!mf || typeof mf !== 'object') { return false; }
		var lists = mf['ietf-access-control-list:acls'];
		if (!lists || !Array.isArray(lists.acl)) { return false; }
		return lists.acl.some(function (a) {
			return a && a.aces && Array.isArray(a.aces.ace)
				&& a.aces.ace.length > 0;
		});
	}

	function handleJsonDrop(file) {
		if (!global.MudMakerVisualizer
				|| typeof global.MudMakerVisualizer.loadSavedWork
					!== 'function') {
			report('Visualizer not ready — cannot load MUD file.', true);
			return;
		}
		try {
			global.MudMakerVisualizer.loadSavedWork({ files: [file] });
			report('Loaded MUD file ' + file.name + '.');
		} catch (e) {
			report('Failed to load ' + file.name + ': ' + e, true);
		}
	}

	function handlePcapDrop(files, shiftKey) {
		var picker = document.getElementById('pcapfile');
		if (!picker) {
			report('PCAP picker not present — cannot import captures.', true);
			return;
		}
		if (typeof global.generateMudFromPcap !== 'function') {
			report('generateMudFromPcap is unavailable.', true);
			return;
		}
		// Shift-Drop = "treat this as starting over": wipe the
		// editor state to the same baseline as the Reset button so
		// no stale form metadata (mfg, model, sysinfo, docs,
		// mud-url) round-trips through /pcap2mud and reappears in
		// the regenerated MUD.  #pcapfile and #pcapmac live outside
		// #mudform, so the about-to-be-staged files survive the
		// form.reset() that resetSite() performs.
		if (shiftKey && typeof global.resetSite === 'function') {
			try {
				global.resetSite();
			} catch (e) {
				report('Could not reset editor before replace: ' + e,
					true);
				return;
			}
		}
		try {
			picker.value = null;
			var dt = new DataTransfer();
			files.forEach(function (f) { dt.items.add(f); });
			picker.files = dt.files;
			// omud.js listens for ``change`` to stash pcaps into
			// sessionStorage for the OAuth round-trip; assigning
			// .files programmatically does not fire it, so do so.
			picker.dispatchEvent(new Event('change', { bubbles: true }));
		} catch (e) {
			report('Could not stage dropped pcaps: ' + e, true);
			return;
		}
		var mode = shiftKey
			? 'replace'
			: (hasExistingAces() ? 'merge' : 'replace');
		try {
			global.generateMudFromPcap({ mode: mode });
		} catch (e) {
			report('Failed to start MUD generation: ' + e, true);
		}
	}

	function onDrop(event) {
		event.preventDefault();
		var aside = event.currentTarget;
		if (aside && aside.classList) { aside.classList.remove('dragover'); }
		var dt = event.dataTransfer;
		if (!dt || !dt.files || dt.files.length === 0) {
			report('No files were dropped.', true);
			return;
		}
		var sorted = classify(dt.files);
		if (sorted.other.length) {
			report('Unsupported file type(s) dropped: '
				+ sorted.other.map(function (f) { return f.name; })
					.join(', ')
				+ '. Drop a MUD .json or one or more .pcap files.', true);
			return;
		}
		if (sorted.jsons.length && sorted.pcaps.length) {
			report('Drop either a MUD .json or pcap captures, not both.',
				true);
			return;
		}
		if (sorted.jsons.length > 1) {
			report('Drop a single MUD .json file (got '
				+ sorted.jsons.length + ').', true);
			return;
		}
		if (sorted.jsons.length === 1) {
			handleJsonDrop(sorted.jsons[0]);
			return;
		}
		handlePcapDrop(sorted.pcaps, !!event.shiftKey);
	}

	function init() {
		var aside = document.getElementById('mud-live-visualizer');
		if (!aside) { return; }

		// Stop the browser from navigating away on near-miss drops.
		['dragover', 'drop'].forEach(function (evt) {
			global.addEventListener(evt, function (e) {
				if (!aside.contains(e.target)) {
					e.preventDefault();
				}
			}, false);
		});

		aside.addEventListener('dragenter', function (e) {
			e.preventDefault();
			aside.classList.add('dragover');
		}, false);
		aside.addEventListener('dragover', function (e) {
			e.preventDefault();
			// Allow Shift to be advertised as a copy/replace gesture.
			if (e.dataTransfer) {
				e.dataTransfer.dropEffect = 'copy';
			}
			aside.classList.add('dragover');
		}, false);
		aside.addEventListener('dragleave', function (e) {
			// Only clear when leaving the aside itself, not bubbling
			// children, otherwise the overlay flickers.
			if (e.target === aside) {
				aside.classList.remove('dragover');
			}
		}, false);
		aside.addEventListener('drop', onDrop, false);
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', init, false);
	} else {
		init();
	}
})(typeof window !== 'undefined' ? window : this);
