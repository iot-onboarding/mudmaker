# Remaining Basic Information Form Fixes

## Summary

Finish the remaining Basic Information correctness issues in `mudmaker-live.html` and associated JavaScript. Preserve the generated MUD schema, use `model_name` as the device model for signing/publishing metadata, and keep `systeminfo` as the device description.

## Key Changes

1. Rename labels for clarity: `EMail` to `Contact email`, `Country for demo CA` to `Demo certificate country`, `A short description for this device` to `Device description`, and the MUD URL fieldset legend to concise MUD URL wording.
2. In signing logic, use `model_name` as `Model`, validate all required signing fields, and `return` immediately after the alert when validation fails.
3. In Publish validation, require host, model, manufacturer, description, documentation, contact email, and publisher name. Keep country required only for Sign.
4. Add failure handling around `/gitShovel/gottoken` so opening Publish from non-server contexts does not produce an unhandled promise error.

## Public Interfaces

1. The `/mudzip` request payload remains the same shape, but `Model` will now be populated from `#model_name` instead of `systeminfo`.
2. Generated MUD JSON keys remain unchanged: `mfg-name`, `systeminfo`, `documentation`, `mud-url`, `mud-signature`, and `ol.owners`.
3. No new persisted MUD fields are introduced.

## Test Plan

1. Run Playwright desktop and mobile smoke checks against `mudmaker-live.html` as a regression check.
2. Confirm the revised labels render in the Basic Information and MUD URL sections.
3. Fill required fields, open Publish, and confirm the checklist includes publisher and excludes country.
4. Confirm Sign with missing required fields alerts and does not issue `/mudzip`.
5. Confirm Sign with valid fields sends `Model` from `model_name`.
6. Confirm opening Publish from `file://` or without backend access does not create an unhandled promise error.

## Assumptions

1. Scope is targeted to the MUD URL and Basic Information form areas, not a full restyle of tabs, Publish table, or visualizer.
2. `model_name` is the authoritative device model for signing and publication metadata.
3. Country remains a demo certificate/signing field, not a GitHub Publish requirement.
