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


function sbomselect(one,another) {
    var onview = document.getElementById(one);
    var offview = document.getElementById(another);

    if ( document.getElementById(one).checked ) {
	onview = document.getElementById(one);
	offview = document.getElementById(another);
    } else {
	offview = document.getElementById(one);
	onview = document.getElementById(another);
    }
    onview.style.display = "inline";
    offview.style.display = "none";
}

