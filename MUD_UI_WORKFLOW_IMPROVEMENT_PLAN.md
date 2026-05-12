# MUD UI and Workflow Improvement Plan

This plan organizes the proposed user interface and workflow improvements into staged work. The goal is to make MUD file creation easier to understand, safer to complete, and clearer to review before export, signing, or publication.

## Goals

- Guide users through MUD file creation in a predictable order.
- Reduce ambiguity around required fields, generated URLs, network rules, saving, signing, and publishing.
- Make validation visible before users reach the final export or publish step.
- Preserve the current MUD generation behavior while improving the interface around it.
- Keep GitHub publishing optional and clearly scoped.

## Phase 1: Workflow Structure

Replace the current broad tab model with a guided builder flow:

1. Device Info
2. Network Access
3. Review JSON
4. Visualize
5. Export, Sign, or Publish

Required work:

- Rename the current tabs to match user intent instead of implementation detail.
- Keep the existing `mudmaker.html` entry point.
- Preserve session-backed draft state while users move between steps.
- Add a persistent progress indicator showing which steps are complete, incomplete, or blocked.
- Add a persistent validation summary panel that lists required fields and blocking errors.

Acceptance criteria:

- A new user can determine the next required action without opening every tab.
- Required metadata status is visible before the publish/export step.
- Existing draft state still survives navigation between steps.

## Phase 2: Device Information Improvements

Make the first step focused on device identity and core metadata.

Required work:

- Group required identity fields together: manufacturer domain, model, manufacturer name, device description, documentation URL, and email address.
- Show the generated MUD URL in a read-only field as soon as manufacturer domain and model are valid.
- Show the generated signature URL in a read-only field near the MUD URL.
- Move country selection closer to signing, or clearly mark that it is only required for signed demo packages.
- Rename publisher field copy so users understand how it maps into the generated MUD metadata.
- Replace normal validation alerts with inline field-level validation messages.

Acceptance criteria:

- Invalid URLs, missing required fields, and invalid email addresses are shown next to the relevant field.
- The user can see the exact generated MUD URL before viewing, saving, signing, or publishing.
- Country is no longer presented as required for ordinary draft creation unless signing is selected.

## Phase 3: Network Rule Builder

Improve the rule creation experience while keeping the generated ACL and ACE structure compatible with the current implementation.

Required work:

- Replace implicit rule creation from opening `<details>` sections with explicit controls:
  - Add Rule
  - Save Rule
  - Delete Rule
- Keep supported rule categories:
  - named Internet hosts
  - this device's controller
  - local networks
  - controller classes
  - same-manufacturer devices
  - devices by manufacturer domain
- Keep protocol choices as `Any`, `TCP`, and `UDP`.
- For TCP, keep the connection initiator control, but label it as `Connection Initiated By`.
- Add a rule summary table that translates generated rules into readable text.
- Add warnings for broad rules, especially `Any` protocol, `Any` ports, and wide local-network access.

Acceptance criteria:

- Opening and closing a rule category does not create or delete policy by itself.
- Each saved rule appears in a readable summary.
- Deleting a rule removes the corresponding ACEs from the generated MUD object.
- Existing IPv4, IPv6, and dual-stack behavior still works.

## Phase 4: Review and Validation

Add a dedicated review step before export, signing, or publishing.

Required work:

- Show a structured review page with:
  - generated MUD URL
  - generated signature URL
  - manufacturer name
  - model
  - documentation URL
  - email address
  - IP family
  - SBOM metadata status
  - vulnerability advisory status
  - number of ACLs and ACEs
  - warnings for broad network rules
- Add a JSON validity check for the generated MUD structure.
- Keep the raw JSON view, but add copy and download controls.
- Show a useful empty state if no network rules have been added.

Acceptance criteria:

- Users can review the complete generated output before exporting or publishing.
- JSON output can be copied or downloaded from the review step.
- The review step clearly distinguishes errors from warnings.

## Phase 5: Visualization

Improve the visualization step without changing the visualizer engine.

Required work:

- Keep the existing visualizer iframe integration.
- Add an empty state when there are no network rules to visualize.
- Refresh the visualization only when the MUD file has changed.
- Add clear visual status when the iframe is loading or fails to load.

Acceptance criteria:

- Visualization does not appear blank without explanation.
- The visualizer refreshes after relevant MUD changes.
- Failures are visible to the user instead of silently leaving the area empty.

## Phase 6: Draft Import and Export

Separate draft management from GitHub publishing.

Required work:

- Rename `Save` to `Download Draft`.
- Rename `Continue Earlier Work` to `Import Draft`.
- Make draft import available near the start of the workflow as well as in the final step.
- Add an autosave status indicator, such as `Saved locally at HH:MM`.
- Validate imported draft files before loading them into the form.
- Warn before resetting the session and clearing all fields.

Acceptance criteria:

- Users can import an existing draft before starting a new one.
- Draft export still downloads a JSON file named from the model.
- Invalid draft files produce a visible error and do not corrupt the current session.
- Reset requires confirmation.

## Phase 7: Signing Flow

Clarify that signing produces a demo signed package and has additional requirements.

Required work:

- Rename `Sign` to `Download Signed Demo Package`.
- Show signing prerequisites before enabling the action:
  - manufacturer name
  - model
  - country
  - email address
  - MUD URL
- Replace signing alerts with inline validation.
- Show a loading state while `/mudzip` is processing.
- Show an error state if signing fails.

Acceptance criteria:

- Signing is disabled until all signing prerequisites are met.
- Users understand that signing downloads a ZIP package.
- Signing failures are visible and actionable.

## Phase 8: GitHub Publishing Flow

Make GitHub publishing explicit, optional, and permission-aware.

Required work:

- Rename `Publish` to `Create GitHub Pull Request`.
- Hide or clearly disable GitHub publishing when the deployment does not support it.
- Before OAuth, show the exact publish sequence:
  - authenticate with GitHub
  - create or reuse the user's `mudfiles` fork
  - create a branch
  - commit the generated MUD file
  - open a pull request against `iot-onboarding/mudfiles`
- Explain that GitHub is optional and not required to create or store MUD files.
- Explain the OAuth permission scope before redirecting to GitHub.
- Align this work with the separate JavaScript security remediation item that reduces OAuth from `repo` to `public_repo`.
- Show progress for each backend `/gitShovel` step.
- Handle failure states with clear messages and retry guidance.

Acceptance criteria:

- Users know what GitHub access is requested before authenticating.
- Public deployments do not present unavailable publishing as a normal working action.
- The publish flow clearly reports which step failed if a backend call fails.

## Phase 9: Accessibility and Layout Cleanup

Improve usability and maintainability of the page structure.

Required work:

- Replace table-based layout in the action area with semantic sections and form groups.
- Add accessible tab or stepper semantics.
- Ensure keyboard navigation works across the full builder.
- Ensure validation state is not communicated by color alone.
- Add labels and descriptions for complex concepts such as controller classes, same-manufacturer access, local networks, SBOM, and vulnerability advisory metadata.
- Replace the long country dropdown with a searchable control or defer it until signing.
- Ensure buttons and actions have descriptive names.

Acceptance criteria:

- The builder is usable with keyboard navigation.
- Required field status and validation errors are readable by assistive technology.
- Complex MUD concepts have concise explanatory text near the control that uses them.

## Phase 10: Regression Coverage

Add focused tests around the most important workflow behavior.

Required work:

- Add tests or browser checks for:
  - generated MUD URL and signature URL
  - required field validation
  - draft export
  - draft import
  - rule creation
  - rule deletion
  - JSON review output
  - visualization refresh trigger
  - signing prerequisites
  - GitHub authorization URL scope
- Add a regression check that fails if GitHub OAuth requests `scope=repo`.
- Add sample draft files for import/reload testing.

Acceptance criteria:

- The main user path can be verified without manual inspection of every field.
- OAuth scope regression is covered.
- Rule edits are verified against the generated MUD JSON, not only against the UI.

## Suggested Implementation Order

1. Rename actions and add inline validation around existing fields.
2. Add the generated MUD URL and signature URL preview.
3. Add the persistent validation summary.
4. Split draft import/export, signing, and GitHub publishing into clearer final-step sections.
5. Refactor the network rule builder to use explicit add/save/delete actions.
6. Add the readable rule summary table.
7. Add the review step with JSON validation and copy/download controls.
8. Improve visualization empty/loading/error states.
9. Clean up accessibility and layout.
10. Add regression coverage for the completed workflow.

## Risks and Notes

- The network rule builder is the highest-risk UI change because it directly maps form state to ACL and ACE generation.
- Draft import must remain backward compatible with existing saved work files.
- GitHub publishing should be treated as optional because the README states that the pull request integration is not publicly available at this time.
- Signing depends on the `/mudzip` backend and the `mudcerts` package, so UI changes should handle backend unavailability cleanly.
- The first implementation pass should preserve the existing MUD JSON schema and focus on workflow clarity rather than changing generated policy semantics.
