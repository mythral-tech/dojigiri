# Dojigiri Licensing

Dojigiri is licensed under the **GNU Affero General Public License v3.0** (AGPL-3.0-only).

## Your Rights

- **Use** Dojigiri for any purpose -- personal, commercial, internal, educational
- **Modify** the source code to suit your needs
- **Distribute** copies of Dojigiri, modified or unmodified
- **Run** Dojigiri as part of a service, including SaaS and CI/CD pipelines

## Your Obligations

- **Share modifications.** If you distribute a modified version of Dojigiri, you must make the modified source code available under the AGPL v3.
- **Network use counts as distribution.** If you run a modified version of Dojigiri as a network service (e.g., a SaaS scanning platform), users of that service must be able to obtain the corresponding source code. This is what distinguishes AGPL from GPL.
- **Preserve license notices.** Keep the LICENSE file and copyright notices intact in all copies and derivative works.
- **State changes.** If you modify the source, note what you changed and when.

## What This Means in Practice

| Use Case | AGPL Requirement |
|----------|-----------------|
| Scan your own code (any org size) | None -- internal use is unrestricted |
| Use in CI/CD pipeline | None -- running the tool doesn't trigger disclosure |
| Fork and modify for internal use | None -- no distribution, no obligation |
| Distribute a modified version | Must share your modifications under AGPL v3 |
| Offer as a hosted/SaaS service | Must provide source of your modified version to users |
| Embed in a proprietary product | Not permitted under AGPL -- see dual licensing below |

## Commercial Dual Licensing

Organizations that cannot comply with the AGPL v3 -- for example, those embedding Dojigiri in proprietary products or offering it as a white-label service -- can obtain a commercial license from Mythral Technologies Inc.

Commercial licensing inquiries: [github.com/mythral-tech/dojigiri/issues](https://github.com/mythral-tech/dojigiri/issues)

## Why AGPL v3?

AGPL v3 keeps Dojigiri fully open-source while ensuring that improvements to the tool benefit the community. The "network use" clause prevents SaaS providers from wrapping Dojigiri without contributing back. Companies that need different terms can use the commercial dual-license.

## Full License Text

See [LICENSE](LICENSE).
