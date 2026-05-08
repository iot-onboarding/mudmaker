# JavaScript Security Remediation Plan

## Scope

This plan addresses the JavaScript and JavaScript-adjacent vulnerabilities found in the local checkout, including first-party browser code, inline JavaScript, and referenced client-side dependencies.

## Plan


3. Fix OAuth status rendering in `assets/js/omud.js`.
   Replace `innerHTML` concatenation for `user`, `branch_name`, and backend error text with safe DOM construction. Build the GitHub repository link with `document.createElement("a")` and a validated URL.

4. Fix PHP-to-JavaScript escaping in `mudvisualizer.php`.
   Emit `incoming_mudfile` with `json_encode($mudfile, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT)` instead of interpolating data into a quoted JavaScript string.

5. Completed: Tighten request construction.
   Used `URL` and `URLSearchParams` for the GitHub OAuth URL in `assets/js/omud.js`. Used `URL` and `URLSearchParams` for the `mudurl` query parameter in `assets/js/tabs.js`.

6. Reduce GitHub OAuth scope.
   Change the OAuth request from `repo` to `public_repo` if private repository access is not required. Longer term, consider a GitHub App with fine-grained repository permissions.


9. Audit missing visualizer JavaScript.
   The referenced `scripts/*.js` files are not present in this checkout. Once available, review them for URL loading, HTML rendering, file parsing, D3 tooltip and label rendering, and dynamic script or style injection.

## Verification Checklist

- Test form fields with `<img src=x onerror=alert(1)>`.
- Test form fields with quotes, apostrophes, and `</script>`.
- Test `mud-url` values containing `&extra=1` and other query delimiters.
- Load a malicious saved work file and open the Publish tab.
- Exercise the OAuth publish flow through PR creation.
- Create, save, reload, visualize, and sign a MUD file.
- Verify TCP and UDP ACEs round-trip correctly through save and reload.
- Confirm visualizer pages still load after the jQuery UI update.
