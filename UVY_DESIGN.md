# UVY Design adoption

## Guidance and scope

Reviewed against the [current guidance](https://github.com/UnitVectorY-Labs/uvy-design/tree/64017af64fd58e4cf3a2a0e6ed66f6f5d9c0d09a) at `64017af64fd58e4cf3a2a0e6ed66f6f5d9c0d09a`. The guidance is no longer a versioned asset package; the following identifies the historical source of the locally maintained assets.

- Release: [UVY Design v0.1.0](https://github.com/UnitVectorY-Labs/uvy-design/tree/12f8e3d964785d78628346516351fe4dac583cef)
- Source commit: `12f8e3d964785d78628346516351fe4dac583cef`
- Guide: [approved style guide](https://github.com/UnitVectorY-Labs/uvy-design/blob/12f8e3d964785d78628346516351fe4dac583cef/docs/style-guide.md)
- Local runtime: shared token/controller/treatment files under `assets/uvy-design/`, copied into generated `html/uvy-design/`. No new framework or HTMX is introduced.
- Inline icon source: the release's official Tabler outline SVGs, pinned upstream commit `ed177a085b652fe04ec4f37ced867c94621e7840`; templates are defined in `templates/icons.html`. Both upstream MIT notices are retained alongside the vendored assets.

The adapter at the end of `assets/style.css` maps the existing navbar, home cards, lists, metadata, detail/compare tabs, permission filters, suggestions, comparisons and footer to the shared color/type/spacing rules. Layouts, destinations, tab workflows, comparison computation and include/exclude storage remain intact. Standard density is used for panels; dense technical/list values remain readable at 14px. Existing include/exclude and shared/unique semantic colors retain their meaning independently of branding.

The top-right theme control uses the shared head script, defaults to the system and saves a host-only `uvy-theme` cookie for explicit choices. There is no System selector or localStorage theme owner. Without JavaScript, CSS follows the system and the inactive button stays hidden. Source/license footer links identify this project, without an organization masthead. Native labels/focus and deprecated text replace placeholder-only names and emoji indicators without removing their meaning.

## Vendored checksums

| Path | SHA-256 |
| --- | --- |
| `assets/uvy-design/LICENSE` | `00320f7ebea7d48c92ddabd067541e3a8d3c033deafb50ada6bf7a3a56f640dc` |
| `assets/uvy-design/TABLER-ICONS-LICENSE` | `b740a1d46122672da62833e97f7e7c8a13fa85cbc7445b584b297cc00dde93db` |
| `assets/uvy-design/uvy-elements.css` | `b2f92292dd9317bb770be1a4c745c9a00b81b6cef39cbcac54d2fe192135b092` |
| `assets/uvy-design/uvy-theme.js` | `b105c0ddec8c19b6a380a33ffa5f9f558ca49baa477921a1dee9596d77bc61ed` |
| `assets/uvy-design/uvy-tokens.css` | `0e97baaece886e0015c4238eaf7dbed9ea68f330c0f50729311c43b4a5a98533` |

## Updating

Review a new upstream design commit and file hashes; copy canonical assets verbatim, retaining notices. Keep application-specific rules in the adapter and update this record. Rebuild, run the main workflows and compare the complete major-page screenshot matrix. Do not fetch mutable assets from the design repository or any CDN at runtime.

## Validation and evidence

- Generate using `WEBSITE=https://gcp-iam-catalog.unitvectorylabs.com go run . -generate`.
- `go test ./...`, `go vet ./...`, and `go build .`.
- Browser coverage: home; filtered role/permission lists; role/permission details; role/permission comparisons; empty, include/exclude and no-match searches; filtering, comparison set/count parity, saved state, copying, explicit/OS theme, narrow layouts and local-only requests.
- Evidence compares the same full committed IAM snapshot before and after, with baseline source SHA and data hashes recorded. OS-dark baseline is faithfully light because the existing site has no dark theme.
- Screenshots belong to a dedicated design-repository evidence branch and are embedded in the PR, not committed to this application. They do not constitute complete screen-reader/WCAG certification. Existing autocomplete and detail/compare navigation workflows remain; this change does not redesign them.
