# JavaScript Security Remediation Plan

## Scope

This plan addresses the JavaScript and JavaScript-adjacent vulnerabilities found in the local checkout, including first-party browser code, inline JavaScript, and referenced client-side dependencies.

## Plan


3. Completed: Fix OAuth status rendering in `assets/js/omud.js`.
   Replaced `innerHTML` concatenation for `user`, `branch_name`, and backend error text with safe DOM construction. Built the GitHub repository link through `MudSafeDom.link()` with a validated URL.

4. Fix PHP-to-JavaScript escaping in `mudvisualizer.php`.
   Emit `incoming_mudfile` with `json_encode($mudfile, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT)` instead of interpolating data into a quoted JavaScript string.

5. Completed: Tighten request construction.
   Used `URL` and `URLSearchParams` for the GitHub OAuth URL in `assets/js/omud.js`. Used `URL` and `URLSearchParams` for the `mudurl` query parameter in `assets/js/tabs.js`.

6. Reduce GitHub OAuth scope.
   The current OAuth authorization URL in `assets/js/omud.js` requests the broad `repo` scope, which grants access to private repositories as well as public repositories. The publish flow only appears to need public repository access: create or reuse the user's public `mudfiles` fork, create a branch, commit the generated MUD file, and open a pull request against `iot-onboarding/mudfiles`. Reduce the scope only after confirming that no supported workflow publishes to a private repository.

   Required work:
   - Confirm the product requirement: publishing through this UI is limited to public GitHub repositories and does not need private repository reads, writes, hooks, collaborators, invitations, projects, or organization-private resources.
   - Inventory the backend `/gitShovel` calls used by the browser flow: `/oAuthv2`, `/dorepo`, `/branch`, and `/therest`. For each endpoint, document the GitHub REST API operations it performs and verify those operations work with `public_repo`.
   - Update `assets/js/omud.js` so the OAuth request uses `public_repo` instead of `repo`.
   - Check the OAuth callback/token exchange path in the backend. It should not request or upgrade to `repo`, and it should reject or warn if GitHub returns a token without the required public repository permissions.
   - Handle existing authorizations that already granted `repo`: revoke stored tokens, clear any server-side token cache/session state, and require users to authorize again so future publish attempts use the reduced permission set.
   - Update user-facing copy near the Publish flow if it currently implies access broader than public repository publishing.
   - Add a regression check that inspects the generated GitHub authorization URL and fails if `scope=repo` is reintroduced.
   - Exercise the full publish path with a fresh GitHub authorization: authenticate, create or locate the fork, create the branch, commit the file, open the pull request, and confirm the OAuth token has `public_repo` but not `repo`.

   Longer term, replace the OAuth App with a GitHub App installed only on the target public repository or user fork, with narrowly configured contents and pull request permissions.


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
