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

	var SVG_NS = "http://www.w3.org/2000/svg";
	var state = {
		initialized: false,
		timer: null,
		activeEdge: null
	};

	function byId(id) {
		return document.getElementById(id);
	}

	function asArray(value) {
		return Array.isArray(value) ? value : [];
	}

	function createSvg(tagName, attrs) {
		var node = document.createElementNS(SVG_NS, tagName);
		setAttrs(node, attrs);
		return node;
	}

	function setAttrs(node, attrs) {
		if (!attrs) {
			return node;
		}
		Object.keys(attrs).forEach(function(name) {
			var value = attrs[name];
			if (value == null) {
				return;
			}
			if (name === "text") {
				node.textContent = String(value);
			} else {
				node.setAttribute(name, String(value));
			}
		});
		return node;
	}

	function clearNode(node) {
		while (node && node.firstChild) {
			node.removeChild(node.firstChild);
		}
		return node;
	}

	function currentMudFile() {
		var stored;
		if (typeof document.mudFile !== "undefined" && document.mudFile != null) {
			return document.mudFile;
		}
		try {
			stored = window.sessionStorage.getItem("mudfile");
			return stored ? JSON.parse(stored) : null;
		} catch (e) {
			return null;
		}
	}

	function policyListNames(policy) {
		var lists;
		if (!policy || !policy["access-lists"]) {
			return [];
		}
		lists = policy["access-lists"]["access-list"];
		return asArray(lists).map(function(entry) {
			return entry && entry.name;
		}).filter(Boolean);
	}

	function buildPolicyMap(mud) {
		var map = {};
		policyListNames(mud["to-device-policy"]).forEach(function(name) {
			map[name] = "to-device";
		});
		policyListNames(mud["from-device-policy"]).forEach(function(name) {
			map[name] = "from-device";
		});
		return map;
	}

	function aclDirection(acl, policyMap) {
		if (acl && acl.name && policyMap[acl.name]) {
			return policyMap[acl.name];
		}
		if (acl && /^to/i.test(acl.name || "")) {
			return "to-device";
		}
		if (acl && /^(fr|from)/i.test(acl.name || "")) {
			return "from-device";
		}
		return "from-device";
	}

	function aclFamily(acl, matches) {
		if (matches && matches.ipv6) {
			return "IPv6";
		}
		if (matches && matches.ipv4) {
			return "IPv4";
		}
		if (acl && /ipv6/i.test(acl.type || acl.name || "")) {
			return "IPv6";
		}
		if (acl && /ipv4/i.test(acl.type || acl.name || "")) {
			return "IPv4";
		}
		return "IP";
	}

	function firstIpMatch(matches) {
		if (!matches) {
			return {};
		}
		return matches.ipv4 || matches.ipv6 || {};
	}

	function protocolName(ipMatch) {
		var protocol = ipMatch && ipMatch.protocol;
		if (protocol === 6 || protocol === "6" || protocol === "tcp") {
			return "tcp";
		}
		if (protocol === 17 || protocol === "17" || protocol === "udp") {
			return "udp";
		}
		if (protocol) {
			return "ip-" + protocol;
		}
		return "any";
	}

	function portValue(match) {
		if (!match || typeof match.port === "undefined") {
			return "any";
		}
		return String(match.port);
	}

	function transport(matches, proto, direction) {
		var details = {
			localPort: "any",
			remotePort: "any",
			initiated: "either"
		};
		var protoMatch;

		if (proto !== "tcp" && proto !== "udp") {
			return details;
		}
		protoMatch = matches[proto] || {};
		if (direction === "to-device") {
			details.localPort = portValue(protoMatch["destination-port"]);
			details.remotePort = portValue(protoMatch["source-port"]);
		} else {
			details.localPort = portValue(protoMatch["source-port"]);
			details.remotePort = portValue(protoMatch["destination-port"]);
		}
		if (proto === "tcp" && protoMatch["ietf-mud:direction-initiated"]) {
			details.initiated = protoMatch["ietf-mud:direction-initiated"];
		}
		return details;
	}

	function mudMatchValue(value) {
		if (Array.isArray(value)) {
			return value.length && value[0] != null ? String(value[0]) : "";
		}
		if (value == null) {
			return "";
		}
		return String(value);
	}

	function endpointFromMudMatch(mudMatch) {
		var labels = {
			"my-controller": "My Controller",
			"local-networks": "Local Networks",
			"controller": "Controller Class",
			"same-manufacturer": "Same Manufacturer",
			"manufacturer": "Manufacturer"
		};
		var keys = Object.keys(mudMatch || {});
		var key;
		var value;
		var label;

		if (!keys.length) {
			return null;
		}
		key = keys[0];
		value = mudMatchValue(mudMatch[key]);
		label = value || labels[key] || key;
		if ((key === "controller" || key === "manufacturer") && value) {
			label = value;
		}
		return {
			id: "mud:" + key + ":" + label,
			label: label,
			kind: key,
			zone: "enterprise"
		};
	}

	function endpointFromDns(ipMatch, direction) {
		var name = "";
		var fromNetwork = false;
		if (direction === "to-device") {
			name = ipMatch["ietf-acldns:src-dnsname"] || "";
			if (!name) {
				name = ipMatch["source-ipv4-network"] ||
					ipMatch["source-ipv6-network"] || "";
				if (name) { fromNetwork = true; }
			}
		} else {
			name = ipMatch["ietf-acldns:dst-dnsname"] || "";
			if (!name) {
				name = ipMatch["destination-ipv4-network"] ||
					ipMatch["destination-ipv6-network"] || "";
				if (name) { fromNetwork = true; }
			}
		}
		if (!name) {
			name = ipMatch["ietf-acldns:src-dnsname"] || ipMatch["ietf-acldns:dst-dnsname"] || "";
			if (!name) {
				name = ipMatch["source-ipv4-network"] ||
					ipMatch["destination-ipv4-network"] ||
					ipMatch["source-ipv6-network"] ||
					ipMatch["destination-ipv6-network"] || "Network";
				if (name && name !== "Network") { fromNetwork = true; }
			}
		}
		return {
			id: "endpoint:" + name,
			label: name,
			kind: fromNetwork ? "ipnet" : "internet-host",
			zone: "internet"
		};
	}

	function endpointFromAce(ace, direction) {
		var matches = ace.matches || {};
		if (matches["ietf-mud:mud"]) {
			return endpointFromMudMatch(matches["ietf-mud:mud"]);
		}
		return endpointFromDns(firstIpMatch(matches), direction);
	}

	function aceBaseName(name) {
		return String(name || "ace").replace(/^(to|fr)/i, "");
	}

	function addFamily(edge, family) {
		if (edge.families.indexOf(family) === -1) {
			edge.families.push(family);
		}
	}

	function edgeKey(endpoint, proto, details) {
		return [
			endpoint.id,
			proto,
			details.localPort,
			details.remotePort,
			details.initiated
		].join("|");
	}

	function displayEndpoints(endpoints) {
		var totals = {};
		var seen = {};

		endpoints.forEach(function(endpoint) {
			totals[endpoint.label] = (totals[endpoint.label] || 0) + 1;
		});
		endpoints.forEach(function(endpoint) {
			if (totals[endpoint.label] < 2) {
				return;
			}
			seen[endpoint.label] = (seen[endpoint.label] || 0) + 1;
			endpoint.label = endpoint.label + " " + seen[endpoint.label];
		});
		return endpoints;
	}

	function buildModel(mudFile) {
		var mud = mudFile && mudFile["ietf-mud:mud"] ? mudFile["ietf-mud:mud"] : {};
		var aclContainer = mudFile && mudFile["ietf-access-control-list:acls"];
		var policyMap = buildPolicyMap(mud);
		var endpoints = {};
		var edges = {};
		var edgeList;

		asArray(aclContainer && aclContainer.acl).forEach(function(acl) {
			var direction = aclDirection(acl, policyMap);
			asArray(acl.aces && acl.aces.ace).forEach(function(ace) {
				var matches = ace.matches || {};
				var ipMatch = firstIpMatch(matches);
				var family = aclFamily(acl, matches);
				var endpoint = endpointFromAce(ace, direction);
				var proto = protocolName(ipMatch);
				var details = transport(matches, proto, direction);
				var key;

				if (!endpoint) {
					return;
				}
				endpoints[endpoint.id] = endpoint;
				key = edgeKey(endpoint, proto, details);
				if (!edges[key]) {
					edges[key] = {
						endpointId: endpoint.id,
						proto: proto,
						localPort: details.localPort,
						remotePort: details.remotePort,
						initiated: details.initiated,
						directions: {},
						families: [],
						aces: []
					};
				}
				edges[key].directions[direction] = true;
				addFamily(edges[key], family);
				edges[key].aces.push(aceBaseName(ace.name));
			});
		});

		edgeList = Object.keys(edges).map(function(key) {
			var edge = edges[key];
			if (edge.directions["from-device"] && edge.directions["to-device"]) {
				edge.direction = "bidirectional";
			} else if (edge.directions["to-device"]) {
				edge.direction = "to-device";
			} else {
				edge.direction = "from-device";
			}
			edge.families.sort();
			return edge;
		});

		var endpointList = Object.keys(endpoints).map(function(key) {
			return endpoints[key];
		}).sort(function(a, b) {
			return a.label.localeCompare(b.label);
		});

		displayEndpoints(endpointList);

		return {
			deviceLabel: mud.systeminfo || mud["mud-url"] || "This Device",
			endpoints: endpointList,
			edges: edgeList.sort(function(a, b) {
				var left = endpoints[a.endpointId].label + a.proto + a.direction;
				var right = endpoints[b.endpointId].label + b.proto + b.direction;
				return left.localeCompare(right);
			})
		};
	}

	function isInternetEndpoint(endpoint) {
		return endpoint && endpoint.zone === "internet";
	}

	function installDefs(svg) {
		var defs = createSvg("defs");
		svg.appendChild(defs);
	}

	function textNode(tagName, attrs, text) {
		var node = createSvg(tagName, attrs);
		node.textContent = text;
		return node;
	}

	function shorten(text, maxLength) {
		text = String(text || "");
		if (text.length <= maxLength) {
			return text;
		}
		return text.slice(0, maxLength - 3) + "...";
	}

	function pointToward(from, to, distance) {
		var dx = to.x - from.x;
		var dy = to.y - from.y;
		var len = Math.sqrt(dx * dx + dy * dy) || 1;

		return {
			x: from.x + dx / len * distance,
			y: from.y + dy / len * distance
		};
	}

	function pathBetween(from, to, offset, fromMargin, toMargin) {
		var start = pointToward(from, to, fromMargin || 0);
		var end = pointToward(to, from, toMargin || 0);
		var mx = (start.x + end.x) / 2;
		var my = (start.y + end.y) / 2;
		var dx = end.x - start.x;
		var dy = end.y - start.y;
		var len = Math.sqrt(dx * dx + dy * dy) || 1;
		var cx = mx + (-dy / len) * offset;
		var cy = my + (dx / len) * offset;
		return "M " + start.x + " " + start.y + " Q " + cx + " " + cy + " " + end.x + " " + end.y;
	}

	function labelWidth(label) {
		return Math.max(60, Math.min(240, String(label || "").length * 8 + 18));
	}

	function uniqueValues(values) {
		var seen = {};
		return asArray(values).filter(function(value) {
			if (seen[value]) {
				return false;
			}
			seen[value] = true;
			return true;
		});
	}

	function protocolLabel(proto) {
		if (!proto || proto === "any") {
			return "Any protocol";
		}
		return String(proto).toUpperCase();
	}

	function initiatedLabel(initiated) {
		if (initiated === "from-device") {
			return "thing";
		}
		if (initiated === "to-device") {
			return "remote endpoint";
		}
		return "either endpoint";
	}

	function edgeAccessRow(edge, index) {
		var aces = uniqueValues(edge.aces);

		return {
			number: index,
			protocol: protocolLabel(edge.proto),
			family: edge.families.length ? edge.families.join(", ") : "Any",
			devicePort: edge.proto === "tcp" || edge.proto === "udp" ? edge.localPort : "any",
			endpointPort: edge.proto === "tcp" || edge.proto === "udp" ? edge.remotePort : "any",
			initiatedBy: edge.proto === "tcp" ? initiatedLabel(edge.initiated) : "n/a",
			ace: aces.length ? aces.join(", ") : ""
		};
	}

	function accessTooltip(model, endpoint, edges) {
		return {
			title: edges.length === 1 ? "Allowed access" : "Allowed accesses",
			between: model.deviceLabel + " and " + endpoint.label,
			rows: edges.map(function(edge, index) {
				return edgeAccessRow(edge, index + 1);
			})
		};
	}

	function accessTooltipText(tooltip) {
		var lines = [
			tooltip.title,
			"Between: " + tooltip.between
		];

		tooltip.rows.forEach(function(row) {
			lines.push([
				row.number + ".",
				row.protocol,
				row.family,
				"device port " + row.devicePort,
				"endpoint port " + row.endpointPort,
				"initiated by " + row.initiatedBy,
				"ACE " + row.ace
			].join("; "));
		});
		return lines.join("; ");
	}

	function groupEdgesByEndpoint(edges) {
		var grouped = {};

		edges.forEach(function(edge) {
			if (!grouped[edge.endpointId]) {
				grouped[edge.endpointId] = [];
			}
			grouped[edge.endpointId].push(edge);
		});
		return grouped;
	}

	function drawEdge(svg, from, to, edge, offset, fromMargin, toMargin, tooltip) {
		var d = pathBetween(from, to, offset, fromMargin, toMargin);
		var path = createSvg("path", {
			d: d,
			class: "mud-live-edge"
		});
		var hitPath = createSvg("path", {
			d: d,
			class: "mud-live-edge-hit",
			tabindex: "0",
			focusable: "true",
			"data-mud-live-tooltip": "true",
			"data-mud-live-tooltip-title": tooltip.title,
			"data-mud-live-tooltip-between": tooltip.between,
			"data-mud-live-tooltip-rows": JSON.stringify(tooltip.rows),
			"aria-label": tooltip ? accessTooltipText(tooltip) : "Allowed access"
		});

		hitPath._mudLiveVisibleEdge = path;
		svg.appendChild(path);
		svg.appendChild(hitPath);
	}

	function iconKind(kind) {
		if (kind === "device" || kind === "same-manufacturer" || kind === "manufacturer") {
			return "iot";
		}
		if (kind === "my-controller" || kind === "controller") {
			return "computer";
		}
		if (kind === "internet-host" || kind === "ipnet") {
			return "cloud";
		}
		return "enterprise";
	}

	function iconColorClass(kind) {
		if (kind === "device") {
			return "mud-live-icon mud-live-icon-device";
		}
		if (kind === "internet-host") {
			return "mud-live-icon mud-live-icon-internet";
		}
		return "mud-live-icon mud-live-icon-enterprise";
	}

	function nodeRadius(kind) {
		return kind === "device" ? 48 : 34;
	}

	function edgeMargin(kind) {
		return nodeRadius(kind) + 10;
	}

	function drawIoTIcon(group, position, radius) {
		var width = radius * 0.62;
		var height = radius * 0.9;
		var x = position.x - width / 2;
		var y = position.y - height / 2;

		group.appendChild(createSvg("rect", {
			x: x,
			y: y,
			width: width,
			height: height,
			rx: 5,
			class: "mud-live-node-icon"
		}));
		group.appendChild(createSvg("line", {
			x1: position.x,
			y1: y,
			x2: position.x,
			y2: y - radius * 0.23,
			class: "mud-live-node-icon"
		}));
		group.appendChild(createSvg("circle", {
			cx: position.x,
			cy: y - radius * 0.28,
			r: 2.5,
			class: "mud-live-node-icon-fill"
		}));
		group.appendChild(createSvg("circle", {
			cx: position.x,
			cy: position.y - radius * 0.12,
			r: radius * 0.12,
			class: "mud-live-node-icon"
		}));
		group.appendChild(createSvg("line", {
			x1: x + width * 0.22,
			y1: y + height * 0.75,
			x2: x + width * 0.78,
			y2: y + height * 0.75,
			class: "mud-live-node-icon"
		}));
	}

	function drawComputerIcon(group, position, radius) {
		var width = radius * 1.05;
		var height = radius * 0.65;
		var x = position.x - width / 2;
		var y = position.y - height / 2 - radius * 0.08;

		group.appendChild(createSvg("rect", {
			x: x,
			y: y,
			width: width,
			height: height,
			rx: 4,
			class: "mud-live-node-icon"
		}));
		group.appendChild(createSvg("line", {
			x1: position.x,
			y1: y + height,
			x2: position.x,
			y2: y + height + radius * 0.22,
			class: "mud-live-node-icon"
		}));
		group.appendChild(createSvg("line", {
			x1: position.x - radius * 0.32,
			y1: y + height + radius * 0.22,
			x2: position.x + radius * 0.32,
			y2: y + height + radius * 0.22,
			class: "mud-live-node-icon"
		}));
	}

	function drawCloudIcon(group, position, radius) {
		var scale = radius / 34;
		var x = position.x;
		var y = position.y;
		var d = [
			"M", x - 23 * scale, y + 8 * scale,
			"C", x - 30 * scale, y + 8 * scale, x - 34 * scale, y + 3 * scale, x - 34 * scale, y - 3 * scale,
			"C", x - 34 * scale, y - 9 * scale, x - 29 * scale, y - 14 * scale, x - 22 * scale, y - 14 * scale,
			"C", x - 18 * scale, y - 25 * scale, x - 4 * scale, y - 29 * scale, x + 5 * scale, y - 20 * scale,
			"C", x + 13 * scale, y - 23 * scale, x + 24 * scale, y - 17 * scale, x + 24 * scale, y - 7 * scale,
			"C", x + 31 * scale, y - 6 * scale, x + 35 * scale, y - 1 * scale, x + 35 * scale, y + 5 * scale,
			"C", x + 35 * scale, y + 12 * scale, x + 30 * scale, y + 16 * scale, x + 22 * scale, y + 16 * scale,
			"L", x - 23 * scale, y + 16 * scale,
			"C", x - 28 * scale, y + 16 * scale, x - 32 * scale, y + 13 * scale, x - 34 * scale, y + 8 * scale
		].join(" ");

		group.appendChild(createSvg("path", {
			d: d,
			class: "mud-live-node-icon"
		}));
	}

	function drawEnterpriseIcon(group, position, radius) {
		var size = radius * 0.78;
		var x = position.x - size / 2;
		var y = position.y - size / 2;

		group.appendChild(createSvg("rect", {
			x: x,
			y: y,
			width: size,
			height: size,
			rx: 4,
			class: "mud-live-node-icon"
		}));
		group.appendChild(createSvg("line", {
			x1: x + size * 0.25,
			y1: y + size * 0.35,
			x2: x + size * 0.75,
			y2: y + size * 0.35,
			class: "mud-live-node-icon"
		}));
		group.appendChild(createSvg("line", {
			x1: x + size * 0.25,
			y1: y + size * 0.62,
			x2: x + size * 0.75,
			y2: y + size * 0.62,
			class: "mud-live-node-icon"
		}));
	}

	function drawNodeIcon(group, position, kind, radius) {
		var glyph = iconKind(kind);
		var iconGroup = createSvg("g", {
			class: iconColorClass(kind)
		});

		if (glyph === "iot") {
			drawIoTIcon(iconGroup, position, radius);
		} else if (glyph === "computer") {
			drawComputerIcon(iconGroup, position, radius);
		} else if (glyph === "cloud") {
			drawCloudIcon(iconGroup, position, radius);
		} else {
			drawEnterpriseIcon(iconGroup, position, radius);
		}
		group.appendChild(iconGroup);
	}

	function drawNode(svg, position, label, subtitle, kind) {
		var group = createSvg("g");
		var isDevice = kind === "device";
		var radius = nodeRadius(kind);

		drawNodeIcon(group, position, kind, radius);
		var labelText = shorten(label, isDevice ? 30 : 24);
		var labelY = position.y + radius + 24;
		var subtitleText = subtitle ? shorten(subtitle, 22) : "";
		var subtitleY = position.y + radius + 43;

		group.appendChild(createSvg("rect", {
			x: position.x - labelWidth(labelText) / 2,
			y: labelY - 16,
			width: labelWidth(labelText),
			height: 22,
			rx: 4,
			class: "mud-live-node-label-bg"
		}));
		group.appendChild(textNode("text", {
			x: position.x,
			y: labelY,
			class: "mud-live-node-label"
		}, labelText));
		if (subtitleText) {
			group.appendChild(createSvg("rect", {
				x: position.x - labelWidth(subtitleText) / 2,
				y: subtitleY - 14,
				width: labelWidth(subtitleText),
				height: 20,
				rx: 4,
				class: "mud-live-node-label-bg"
			}));
			group.appendChild(textNode("text", {
				x: position.x,
				y: subtitleY,
				class: "mud-live-node-subtitle"
			}, subtitleText));
		}
		svg.appendChild(group);
	}

	function endpointPositions(endpoints) {
		var positions = {};
		var enterpriseEndpoints = endpoints.filter(function(endpoint) {
			return !isInternetEndpoint(endpoint);
		});
		var internetEndpoints = endpoints.filter(isInternetEndpoint);
		var enterpriseSlots = [300, 170, 430, 115, 485, 225, 375];
		var enterpriseRows = [130, 470, 90, 510];

		enterpriseEndpoints.forEach(function(endpoint, index) {
			var y;
			var column;
			if (internetEndpoints.length) {
				y = enterpriseRows[index % enterpriseRows.length];
				column = Math.floor(index / enterpriseRows.length);
				positions[endpoint.id] = {
					x: 380 + (column * 70),
					y: y
				};
				return;
			}
			y = enterpriseSlots[index % enterpriseSlots.length];
			column = Math.floor(index / enterpriseSlots.length);
			positions[endpoint.id] = {
				x: 420 + (column * 58),
				y: y
			};
		});
		internetEndpoints.forEach(function(endpoint, index) {
			var count = internetEndpoints.length;
			var y = count === 1 ? 300 : 145 + (index * 310 / Math.max(1, count - 1));
			positions[endpoint.id] = {
				x: 750,
				y: y
			};
		});
		return positions;
	}

	function drawEmpty(svg, model) {
		var device = { x: 180, y: 300 };
		drawNode(svg, device, model.deviceLabel, "", "device");
		var tipText = createSvg("text", {
			x: 335,
			y: 410,
			class: "mud-live-empty-title"
		});
		tipText.appendChild(createSvg("tspan", {
			x: 335,
			dy: "0",
			text: "Tip: drop a MUD .json or .pcap here."
		}));
		tipText.appendChild(createSvg("tspan", {
			x: 335,
			dy: "1.2em",
			text: "Shift-drop replaces, plain drop merges."
		}));
		svg.appendChild(tipText);
		svg.appendChild(textNode("text", {
			x: 450,
			y: 614,
			class: "mud-live-empty-copy"
		}, "Open a traffic category and add an entry to update this view."));
	}

	function drawEnterpriseBorder(svg) {
		svg.appendChild(createSvg("rect", {
			x: 55,
			y: 78,
			width: 560,
			height: 444,
			rx: 10,
			class: "mud-live-enterprise-border"
		}));
		svg.appendChild(textNode("text", {
			x: 75,
			y: 108,
			class: "mud-live-border-label"
		}, "Enterprise"));
		svg.appendChild(textNode("text", {
			x: 860,
			y: 304,
			class: "mud-live-border-label mud-live-internet-label"
		}, "Internet"));
	}

	function drawLegend(svg) {
		var x = 62;
		var y = 555;
		svg.appendChild(createSvg("rect", {
			x: x - 12,
			y: y - 26,
			width: 790,
			height: 66,
			rx: 8,
			class: "mud-live-legend-bg"
		}));
		svg.appendChild(textNode("text", {
			x: x,
			y: y - 4,
			class: "mud-live-legend-title"
		}, "Key"));
		drawNodeIcon(svg, { x: x + 55, y: y - 8 }, "device", 16);
		svg.appendChild(textNode("text", {
			x: x + 82,
			y: y - 3,
			class: "mud-live-legend-text"
		}, "IoT device"));
		drawNodeIcon(svg, { x: x + 205, y: y - 8 }, "controller", 16);
		svg.appendChild(textNode("text", {
			x: x + 232,
			y: y - 3,
			class: "mud-live-legend-text"
		}, "enterprise controller"));
		drawNodeIcon(svg, { x: x + 430, y: y - 8 }, "internet-host", 16);
		svg.appendChild(textNode("text", {
			x: x + 457,
			y: y - 3,
			class: "mud-live-legend-text"
		}, "internet host"));
		drawNodeIcon(svg, { x: x + 590, y: y - 8 }, "local-networks", 16);
		svg.appendChild(textNode("text", {
			x: x + 617,
			y: y - 3,
			class: "mud-live-legend-text"
		}, "other enterprise access"));
	}

	function drawModel(svg, model) {
		var device = { x: 180, y: 300 };
		var positions = endpointPositions(model.endpoints);
		var endpointById = {};
		var edgesByEndpoint = groupEdgesByEndpoint(model.edges);

		drawEnterpriseBorder(svg);
		drawLegend(svg);
		if (!model.edges.length) {
			drawEmpty(svg, model);
			return;
		}

		model.endpoints.forEach(function(endpoint) {
			endpointById[endpoint.id] = endpoint;
		});
		Object.keys(edgesByEndpoint).forEach(function(endpointId) {
			var endpoint = positions[endpointId];
			var endpointModel = endpointById[endpointId] || {};
			var tooltip = accessTooltip(model, endpointModel, edgesByEndpoint[endpointId]);

			drawEdge(svg, device, endpoint, edgesByEndpoint[endpointId][0], 0, edgeMargin("device"), edgeMargin(endpointModel.kind), tooltip);
		});

		model.endpoints.forEach(function(endpoint) {
			var related = model.edges.filter(function(edge) {
				return edge.endpointId === endpoint.id;
			});
			drawNode(svg, positions[endpoint.id], endpoint.label, related.length + " flow" + (related.length === 1 ? "" : "s"), endpoint.kind);
		});
		drawNode(svg, device, model.deviceLabel, "", "device");
	}

	function renderDetails(model) {
		var summary = byId("mud-live-summary");
		var details = byId("mud-live-details");
		var edgeCounts = {};

		if (summary) {
			summary.textContent = model.endpoints.length + " endpoint" +
				(model.endpoints.length === 1 ? "" : "s") + ", " +
				model.edges.length + " flow" + (model.edges.length === 1 ? "" : "s");
		}
		if (!details) {
			return;
		}
		clearNode(details);
		model.edges.forEach(function(edge) {
			edgeCounts[edge.endpointId] = (edgeCounts[edge.endpointId] || 0) + 1;
		});
		if (!model.endpoints.length) {
			return;
		}
		model.endpoints.forEach(function(endpoint) {
			var row = document.createElement("div");
			var name = document.createElement("span");
			var meta = document.createElement("span");
			var count = edgeCounts[endpoint.id] || 0;

			row.className = "maker-live-detail-row";
			name.className = "maker-live-detail-name";
			meta.className = "maker-live-detail-meta";
			name.textContent = endpoint.label;
			meta.textContent = count + " flow" + (count === 1 ? "" : "s");
			row.appendChild(name);
			row.appendChild(meta);
			details.appendChild(row);
		});
	}

	function render(mudFile) {
		var svg = byId("mud-live-svg");
		var model;

		if (!svg) {
			return null;
		}
		model = buildModel(mudFile || {});
		clearActiveEdge();
		clearNode(svg);
		svg.appendChild(textNode("title", { id: "mud-live-title" }, "MUD access list visualization"));
		svg.appendChild(textNode("desc", { id: "mud-live-desc" }, "Live visualization of access-list entries added to the MUD file."));
		installDefs(svg);
		drawModel(svg, model);
		renderDetails(model);
		return model;
	}

	function callGlobal(name) {
		if (typeof global[name] !== "function") {
			return undefined;
		}
		return global[name].apply(global, Array.prototype.slice.call(arguments, 1));
	}

	function logLoadProblem(message, error) {
		if (global.console && typeof global.console.warn === "function") {
			global.console.warn(message, error || "");
		} else if (global.console && typeof global.console.error === "function") {
			global.console.error(message, error || "");
		}
	}

	function reportLoadError(message, error) {
		logLoadProblem(message, error);
		if (typeof global.alert === "function") {
			global.alert(message);
		}
	}

	function initializeLoadedMudFile(mudFile) {
		document.mudFile = mudFile;
		if (!state.initialized) {
			init();
		}
		try {
			callGlobal("normalizeMUDFile", document.mudFile);
		} catch (e) {
			logLoadProblem("The saved MUD file was loaded, but it could not be normalized.", e);
		}
		try {
			callGlobal("reloadFields");
		} catch (e) {
			logLoadProblem("The saved MUD file was loaded, but some form fields could not be restored.", e);
		}
		try {
			callGlobal("refreshmans");
		} catch (e) {
			logLoadProblem("The saved MUD file was loaded, but the publish checklist could not be refreshed.", e);
		}
		try {
			if (typeof global.saveMUD === "function") {
				global.saveMUD();
			} else {
				window.sessionStorage.setItem("mudfile", JSON.stringify(document.mudFile));
			}
		} catch (e) {
			logLoadProblem("The saved MUD file was loaded, but it could not be saved in this browser session.", e);
		}
		return render(document.mudFile);
	}

	function loadSavedWork(input) {
		var file = input && input.files && input.files[0];
		var reader;

		if (!file) {
			return false;
		}
		reader = new FileReader();
		reader.onload = function() {
			var mudFile;

			try {
				mudFile = JSON.parse(reader.result);
			} catch (e) {
				reportLoadError("Unable to load saved work: the selected file is not valid JSON.", e);
				return;
			}
			initializeLoadedMudFile(mudFile);
		};
		reader.onerror = function() {
			reportLoadError("Unable to read the selected saved work file.", reader.error);
		};
		reader.readAsText(file);
		return false;
	}

	function scheduleRender() {
		if (state.timer) {
			window.clearTimeout(state.timer);
		}
		state.timer = window.setTimeout(function() {
			state.timer = null;
			render(currentMudFile());
		}, 40);
	}

	function wrapGlobalFunction(name) {
		var original = global[name];
		var wrapped;
		if (typeof original !== "function" || original._mudLiveWrapped) {
			return;
		}
		wrapped = function() {
			var result = original.apply(this, arguments);
			scheduleRender();
			return result;
		};
		wrapped._mudLiveWrapped = true;
		wrapped._mudLiveOriginal = original;
		global[name] = wrapped;
	}

	function tooltipElement() {
		var tooltip = byId("mud-live-tooltip");

		if (tooltip) {
			return tooltip;
		}
		tooltip = document.createElement("div");
		tooltip.id = "mud-live-tooltip";
		tooltip.className = "mud-live-tooltip";
		tooltip.setAttribute("aria-hidden", "true");
		document.body.appendChild(tooltip);
		return tooltip;
	}

	function edgeTooltipTarget(node) {
		var className;

		while (node && node !== document) {
			className = node.getAttribute && node.getAttribute("class");
			if (className && className.indexOf("mud-live-edge-hit") !== -1 &&
				node.getAttribute("data-mud-live-tooltip")) {
				return node;
			}
			node = node.parentNode;
		}
		return null;
	}

	function clearActiveEdge() {
		if (!state.activeEdge) {
			return;
		}
		state.activeEdge.setAttribute("class", "mud-live-edge");
		state.activeEdge = null;
	}

	function setActiveEdge(target) {
		clearActiveEdge();
		if (!target || !target._mudLiveVisibleEdge) {
			return;
		}
		state.activeEdge = target._mudLiveVisibleEdge;
		state.activeEdge.setAttribute("class", "mud-live-edge mud-live-edge-active");
	}

	function positionTooltip(event, target) {
		var tooltip = tooltipElement();
		var rect = target && target.getBoundingClientRect ? target.getBoundingClientRect() : null;
		var x = event && typeof event.clientX === "number" ? event.clientX :
			(rect ? rect.left + rect.width / 2 : 0);
		var y = event && typeof event.clientY === "number" ? event.clientY :
			(rect ? rect.top + rect.height / 2 : 0);
		var left = x + 14;
		var top = y + 14;
		var tooltipRect = tooltip.getBoundingClientRect();
		var viewportWidth = global.innerWidth ||
			(document.documentElement && document.documentElement.clientWidth) || 0;
		var viewportHeight = global.innerHeight ||
			(document.documentElement && document.documentElement.clientHeight) || 0;

		if (viewportWidth && left + tooltipRect.width + 12 > viewportWidth) {
			left = Math.max(8, x - tooltipRect.width - 14);
		}
		if (viewportHeight && top + tooltipRect.height + 12 > viewportHeight) {
			top = Math.max(8, y - tooltipRect.height - 14);
		}
		tooltip.style.left = left + "px";
		tooltip.style.top = top + "px";
	}

	function tooltipRows(target) {
		try {
			return JSON.parse(target.getAttribute("data-mud-live-tooltip-rows") || "[]");
		} catch (e) {
			return [];
		}
	}

	function appendTooltipCell(row, tagName, text) {
		var cell = document.createElement(tagName);

		cell.textContent = text;
		row.appendChild(cell);
		return cell;
	}

	function renderTooltipTable(tooltip, target) {
		var title = document.createElement("div");
		var between = document.createElement("div");
		var table = document.createElement("table");
		var thead = document.createElement("thead");
		var tbody = document.createElement("tbody");
		var headRow = document.createElement("tr");
		var headers = [ "#", "Protocol", "Family", "Thing Port", "Remote Port", "Initiated by", "ACE" ];

		clearNode(tooltip);
		title.className = "mud-live-tooltip-title";
		title.textContent = target.getAttribute("data-mud-live-tooltip-title") || "Allowed access";
		between.className = "mud-live-tooltip-between";
		between.textContent = target.getAttribute("data-mud-live-tooltip-between") || "";
		headers.forEach(function(header) {
			appendTooltipCell(headRow, "th", header);
		});
		thead.appendChild(headRow);
		tooltipRows(target).forEach(function(access) {
			var row = document.createElement("tr");

			appendTooltipCell(row, "td", access.number);
			appendTooltipCell(row, "td", access.protocol);
			appendTooltipCell(row, "td", access.family);
			appendTooltipCell(row, "td", access.devicePort);
			appendTooltipCell(row, "td", access.endpointPort);
			appendTooltipCell(row, "td", access.initiatedBy);
			appendTooltipCell(row, "td", access.ace);
			tbody.appendChild(row);
		});
		table.appendChild(thead);
		table.appendChild(tbody);
		tooltip.appendChild(title);
		tooltip.appendChild(between);
		tooltip.appendChild(table);
	}

	function showEdgeTooltip(event, target) {
		var tooltip = tooltipElement();

		setActiveEdge(target);
		renderTooltipTable(tooltip, target);
		tooltip.style.display = "block";
		tooltip.setAttribute("aria-hidden", "false");
		positionTooltip(event, target);
	}

	function hideEdgeTooltip() {
		var tooltip = byId("mud-live-tooltip");

		if (!tooltip) {
			clearActiveEdge();
			return;
		}
		tooltip.style.display = "none";
		tooltip.setAttribute("aria-hidden", "true");
		clearActiveEdge();
	}

	function hasAncestor(node, selector) {
		while (node && node !== document) {
			if (node.matches && node.matches(selector)) {
				return true;
			}
			node = node.parentNode;
		}
		return false;
	}

	function wireEvents() {
		document.addEventListener("change", function(event) {
			if (hasAncestor(event.target, "#mudform")) {
				scheduleRender();
			}
		});
		document.addEventListener("click", function(event) {
			if (hasAncestor(event.target, ".addable") || hasAncestor(event.target, ".tab")) {
				window.setTimeout(scheduleRender, 0);
			}
		});
		window.addEventListener("storage", function(event) {
			if (event.key === "mudfile") {
				scheduleRender();
			}
		});
		document.addEventListener("mouseover", function(event) {
			var target = edgeTooltipTarget(event.target);

			if (target) {
				showEdgeTooltip(event, target);
			}
		});
		document.addEventListener("mousemove", function(event) {
			var target = edgeTooltipTarget(event.target);

			if (target) {
				positionTooltip(event, target);
			}
		});
		document.addEventListener("mouseout", function(event) {
			if (edgeTooltipTarget(event.target)) {
				hideEdgeTooltip();
			}
		});
		document.addEventListener("focusin", function(event) {
			var target = edgeTooltipTarget(event.target);

			if (target) {
				showEdgeTooltip(event, target);
			}
		});
		document.addEventListener("focusout", function(event) {
			if (edgeTooltipTarget(event.target)) {
				hideEdgeTooltip();
			}
		});
	}

	function installHooks() {
		wrapGlobalFunction("saveMUD");
		wrapGlobalFunction("resetSite");
		wrapGlobalFunction("removeAces");
		wrapGlobalFunction("updateAces");
	}

	function init() {
		if (state.initialized || !byId("mud-live-svg")) {
			return;
		}
		state.initialized = true;
		installHooks();
		wireEvents();
		render(currentMudFile());
	}

	global.MudMakerVisualizer = {
		buildModel: buildModel,
		currentMudFile: currentMudFile,
		init: init,
		initializeLoadedMudFile: initializeLoadedMudFile,
		loadSavedWork: loadSavedWork,
		render: render,
		scheduleRender: scheduleRender
	};

	if (document.readyState === "loading") {
		document.addEventListener("DOMContentLoaded", init);
	} else {
		init();
	}
})(window);
