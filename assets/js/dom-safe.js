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

    function nodeFor(target) {
        if (typeof target === "string") {
            return document.getElementById(target);
        }
        return target;
    }

    function asTextNode(value) {
        return document.createTextNode(value == null ? "" : String(value));
    }

    function clear(target) {
        var node = nodeFor(target);
        if (!node) {
            return null;
        }
        while (node.firstChild) {
            node.removeChild(node.firstChild);
        }
        return node;
    }

    function append(parent) {
        var node = nodeFor(parent);
        if (!node) {
            return null;
        }
        Array.prototype.slice.call(arguments, 1).forEach(function(child) {
            if (child == null) {
                return;
            }
            node.appendChild(child.nodeType ? child : asTextNode(child));
        });
        return node;
    }

    function applyAttrs(node, attrs) {
        if (!attrs) {
            return node;
        }
        Object.keys(attrs).forEach(function(key) {
            var value = attrs[key];
            if (value == null || value === false) {
                return;
            }
            if (/^on/i.test(key)) {
                throw new Error("Event handler attributes are not allowed");
            }
            if (key === "className") {
                node.className = String(value);
            } else if (key === "text") {
                node.appendChild(asTextNode(value));
            } else if (key === "style" && typeof value === "object") {
                Object.keys(value).forEach(function(styleName) {
                    node.style[styleName] = value[styleName];
                });
            } else {
                node.setAttribute(key, value === true ? key : String(value));
            }
        });
        return node;
    }

    function element(tagName, attrs) {
        var node = document.createElement(tagName);
        applyAttrs(node, attrs);
        append.apply(null, [node].concat(Array.prototype.slice.call(arguments, 2)));
        return node;
    }

    function isSafeHref(href) {
        var url;
        if (typeof href !== "string" || href === "") {
            return false;
        }
        if (href.charAt(0) === "#") {
            return true;
        }
        try {
            url = new URL(href, window.location.href);
        } catch (e) {
            return false;
        }
        return ["http:", "https:", "mailto:"].indexOf(url.protocol) !== -1;
    }

    function link(href, label, attrs) {
        var node = element("a", attrs, label);
        if (!isSafeHref(href)) {
            throw new Error("Unsafe link target");
        }
        node.setAttribute("href", href);
        if (node.getAttribute("target") === "_blank" && !node.getAttribute("rel")) {
            node.setAttribute("rel", "noopener noreferrer");
        }
        return node;
    }

    function statusText(text, attrs) {
        return element("span", attrs, text);
    }

    function listItem(label, value, attrs) {
        var item = element("li", attrs);
        append(item, label, ": ", value);
        return item;
    }

    global.MudSafeDom = {
        append: append,
        clear: clear,
        element: element,
        link: link,
        listItem: listItem,
        statusText: statusText,
        text: asTextNode
    };
})(window);
