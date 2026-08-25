# Chrome Web Store Publishing Guide

This guide covers publishing and updating **Enterprise Authentication & NetLog Inspector** in the Chrome Web Store.

## Current Package Information

- Extension name: `Enterprise Authentication & NetLog Inspector`
- Version: `5.1.1`
- Package directory: `dist/`
- Upload archive: `enterprise-auth-netlog-inspector-chrome-v5.1.1.zip`
- Privacy policy: `PRIVACY.md`
- Public privacy-policy URL: <https://ksudhir.github.io/oracle-sso-devtools/privacy/>

Manifest summary:

> Investigate browser authentication failures with live capture, offline analysis, and correlated diagnostic evidence.

## 1. Prepare the Google Developer Account

1. Sign in to the [Chrome Web Store Developer Dashboard](https://chrome.google.com/webstore/devconsole/).
2. Register as a Chrome Web Store developer and pay Google's one-time registration fee if it has not already been paid.
3. Complete the publisher profile and verify the publisher email address.
4. Enable 2-Step Verification on the Google account. Google requires it for publishing and updating extensions.
5. Enable developer-dashboard email notifications for review completion, publication, warnings, and user reviews.

## 2. Test the Extension Locally

1. Run `npm run build` to regenerate `dist/` from the root source files.
2. Run `npm test` to verify JavaScript, flow analysis, and distribution integrity.
3. Open `chrome://extensions` in Chrome.
4. Enable **Developer mode**.
5. Click **Load unpacked**.
6. Select this project's `dist` directory.
7. Open a normal browser tab and then open DevTools.
8. Confirm that the **Auth & NetLog Inspector** panel appears.
9. Test live capture, Start/Stop capture, filters, HAR import/export, Flow Analysis with OAM/WNA details and ECID/RID, SAML decoding, cookies, Kerberos / X.509, OAuth Token, and OIDC Details.
10. Import `demo-data/chromium-netlog-auth-demo.json` and confirm that **NetLog Analysis** shows categorized findings, source timelines, raw parameters, authentication tracing, Kerberos/NTLM classification, and contextual actions.
11. Exercise **Trace TLS connection** plus at least one DNS, proxy, socket, HTTP, HTTP/2, or QUIC investigation when corresponding sample evidence is available.
12. Check DevTools and `chrome://extensions` for errors.

Test a live authentication flow, the supplied HAR-import workflow, and the supplied Chromium NetLog workflow before every release.

## 3. Review the Manifest

Before packaging, update and verify the canonical root `manifest.json`, then run `npm run build`. The generated `dist/manifest.json` must have:

- `name` is correct.
- `description` is no more than 132 characters.
- `version` is greater than every version previously uploaded to the Web Store.
- `manifest_version` is `3`.
- Icons exist at 16, 48, and 128 pixels.
- Only necessary permissions are declared.
- The manifest is valid JSON and contains no comments.

The current compliance release is version `5.1.1`. For later releases, increase the version in both `package.json` and the root `manifest.json`, for example, to `5.1.2` or `5.2`, then regenerate `dist/`. Chrome rejects an uploaded package if its version is not higher than the previously uploaded version.

## 4. Create a Clean ZIP Archive

The manifest must be at the root of the ZIP, not inside a `dist` folder. From the project directory, run:

```bash
npm test
npm run package:chrome
```

Check the package:

```bash
unzip -l enterprise-auth-netlog-inspector-chrome-v5.1.1.zip
unzip -p enterprise-auth-netlog-inspector-chrome-v5.1.1.zip manifest.json
```

Do not include `.git`, `.DS_Store`, private keys, HAR files, test data, screenshots, or store-promotion assets in the extension ZIP.

## 5. Create or Open the Store Item

1. Open the Chrome Web Store Developer Dashboard.
2. For the first release, click **New item**.
3. Upload `enterprise-auth-netlog-inspector-chrome-v5.1.1.zip`.
4. For an existing item, open it, select **Package**, and click **Upload new package**.

Keep using the same Web Store item for future production releases. Creating another item for the same extension can be treated as repetitive content.

## 6. Complete the Store Listing

Use the following title:

> Enterprise Authentication & NetLog Inspector

Use the package summary:

> Investigate browser authentication failures with live capture, offline analysis, and correlated diagnostic evidence.

Use the complete approved copy in `STORE_LISTING.md` for the full description, screenshot captions, single-purpose statement, permission justification, remote-code declaration, and YouTube metadata.

Add the full store description, category, language, support contact, and project website or GitHub repository.

Use these public links in the Store listing:

- Homepage URL: <https://ksudhir.github.io/oracle-sso-devtools/>
- Support URL: <https://github.com/ksudhir/oracle-sso-devtools/issues>
- Getting Started: <https://ksudhir.github.io/oracle-sso-devtools/getting-started/>
- Documentation: <https://ksudhir.github.io/oracle-sso-devtools/docs/>

Upload the prepared assets:

- Store icon: `icons/icon128.png`
- Screenshots: up to five JPEG or 24-bit PNG images, each 1280x800 or 640x400, without alpha
- Small promo tile: `store-assets/chrome/promo/small-promo-tile-440x280.png`
- Marquee promo tile: `store-assets/chrome/promo/marquee-promo-tile-1400x560.png`

Run `npm run package:store:chrome` to create a browser-specific review ZIP containing only the Chrome screenshots and promo tiles. This is separate from the extension package uploaded in the **Package** section.

Recommended committed screenshots:

- `store-assets/chrome/screenshots/01-complete-sso-traffic.png`
- `store-assets/chrome/screenshots/02-saml-federation-analysis.png`
- `store-assets/chrome/screenshots/03-oidc-flow-analysis.png`
- `store-assets/chrome/screenshots/04-wna-ntlm-x509-auth.png`
- `store-assets/chrome/screenshots/05-netlog-kerberos-analysis.jpg`

The first screenshot demonstrates the standalone **Offline Viewer** opened from the extension toolbar with an imported synthetic HAR. It must visibly include the Offline Viewer label, imported filename, theme selector, and request analysis without DevTools chrome.

Use the fifth screenshot in every release that includes NetLog functionality. Its caption should explicitly mention:

- Chromium NetLog analysis
- Negotiate challenge and retry tracing
- Kerberos versus NTLM client-token classification
- Final HTTP outcome
- Recommended next check

Paste only the text under **Full Store Description** in `STORE_LISTING.md`. Keep the description task-oriented and written in natural prose. Do not append the YouTube tags, screenshot captions, protocol inventories, endpoint lists, cookie lists, or other keyword collections to the Store description.

Make sure screenshots contain no real customer names, hostnames, tokens, cookies, email addresses, certificate data, or other confidential information.

## 7. Complete Privacy Practices

Use this single-purpose statement:

> This extension provides local inspection and troubleshooting of browser-visible enterprise authentication, SSO, federation, authorization, and Chromium NetLog evidence through a Chrome DevTools panel and file-based Offline Viewer.

Permission justification:

> No additional extension permissions are requested. The devtools_page entry registers the live inspector in Chrome DevTools. While DevTools is open, request and response evidence is read only from the active inspected tab through Chrome DevTools APIs. The toolbar action opens a packaged local Offline Viewer and processes only files the user explicitly selects; it does not gain access to website data.

Remote-code declaration:

> No. All JavaScript, HTML, CSS, images, and processing logic are packaged inside the extension. The extension does not download or execute remote code.

Privacy-policy URL:

> https://ksudhir.github.io/oracle-sso-devtools/privacy/

Answer every data-use question according to the extension's actual behavior. The panel can process browsing activity, URLs, request and response headers, cookies, authentication information, imported HAR content, Inspector JSON exports, and Chromium NetLog files. NetLog can contain URLs, hostnames, headers, cookies, authentication tokens, proxy details, certificate information, and other sensitive network evidence. Google requires disclosure of handled user data even when it is processed only locally and is not transmitted to the developer or a third party.

The dashboard declarations, store description, privacy policy, and extension behavior must agree. Do not claim that the extension handles no data merely because processing occurs locally.

## 8. Configure Distribution

Choose the appropriate visibility:

- **Public**: listed and available to everyone.
- **Unlisted**: installable by anyone with the direct Web Store URL but not normally discoverable through search.
- **Private**: available only to specified trusted testers.

Select the countries or regions where the extension should be available. Declare whether the extension contains in-app purchases. This project currently does not include paid features or in-app purchases.

Public, unlisted, and private items are all subject to Chrome Web Store policy review.

## 9. Add Test Instructions

Explain to the reviewer how to find and test the extension:

> 1. Install the extension.
> 2. Open any browser tab and launch Chrome DevTools.
> 3. Select the Auth & NetLog Inspector panel. It may appear under the DevTools overflow menu if the window is narrow.
> 4. Browse an authentication flow, use Import File to load a sanitized HAR or panel JSON export, or import `demo-data/chromium-netlog-auth-demo.json`.
> 5. Use Traffic Inspector for Request, Response, Cookies, Kerberos / X.509, SAML XML, SAML Details, OAuth Token, and OIDC Details. Switch to Flow Analysis for correlated attempts and recommended actions.
> 6. Switch to NetLog Analysis. Review the summary counters and categorized Auth, DNS, Proxy, TLS, Sockets, HTTP, HTTP/2, and QUIC findings, then select a source to inspect its event timeline and raw parameters.
> 7. Open the authentication finding and select Trace exchange. Review the server challenge, browser response, Kerberos/NTLM/undetermined classification, retries, final HTTP outcome, and recommended next check. Reusable token values are not displayed.
> 8. Open a TLS finding and select Trace TLS connection. Review endpoint setup, handshake and certificate evidence, protocol negotiation, connection reuse or fallback, and the final outcome.
> 9. Open a DNS, proxy, socket, HTTP, HTTP/2, or QUIC finding and use its contextual Investigate action to see linked sources, related events, and category-specific next actions.
> 10. The extension processes inspected and imported traffic locally and does not require an account or external service.

Provide only sanitized test data. Never upload a HAR or NetLog containing real credentials, session cookies, bearer tokens, authentication tokens, SAML assertions, personal data, certificate material, proxy details, or internal hostnames.

## 10. Submit for Review

1. Resolve all validation errors shown in the dashboard.
2. Recheck the Package, Store listing, Privacy practices, Distribution, and Test instructions tabs.
3. Click **Submit for review**.
4. Choose whether Google should publish automatically after approval.

Publishing choices:

- **Publish automatically**: Google publishes the item after approval; no manual publication step is required.
- **Deferred publishing**: after approval, the item becomes ready to publish. You must click **Publish** within 30 days or the submission returns to draft and must be reviewed again.

## 11. While the Item Is Under Review

- Monitor the dashboard status and publisher email.
- A pending item is not publicly available until approved and published.
- If a mistake is discovered, open the three-dot menu on the Store listing page and select **Cancel review**.
- Canceling returns the submission to draft so it can be corrected and resubmitted. Google currently limits publishers to six review cancellations per day.
- If Google rejects the item, read the Status tab and email carefully, correct the identified issue, and submit again.

## 12. After Approval and Publication

1. If deferred publishing was selected, click **Publish** within 30 days.
2. Open the public Web Store listing and verify the title, description, screenshots, privacy link, and support information.
3. Install the Web Store version in a clean Chrome profile.
4. Open DevTools and verify that the Auth & NetLog Inspector panel loads.
5. Test capture, filtering, HAR import, Flow Analysis, SAML decoding, cookie tables, Kerberos / X.509, OAuth Token, and OIDC Details correlation.
6. Import the sanitized NetLog demo and verify categorized findings, Trace exchange, Trace TLS connection, contextual finding actions, source timelines, and raw event parameters.
7. Save and share the public listing URL.
8. Monitor reviews, support email, crash reports, policy notices, and publisher notifications.

## 13. Publish a Future Update

For every update:

1. Make and test the code changes in the source files.
2. Increase `version` in `package.json` and the root `manifest.json`.
3. Run `npm run build` to regenerate `dist/`; never edit generated files directly.
4. Run `npm test`, then test the unpacked `dist/` build in Chrome.
5. Create a new versioned ZIP archive.
6. Open the existing Web Store item.
7. Select **Package** and **Upload new package**.
8. Update the listing, privacy disclosures, screenshots, test instructions, or distribution details if behavior changed.
9. Submit the update for review.
10. Verify the published update after rollout.

Uploading an update does not immediately replace the currently published version. Existing and new users continue receiving the current published version until the update is approved and published.

## Release Checklist

- [ ] All features tested from unpacked `dist/`
- [ ] No extension errors or DevTools console errors
- [ ] Manifest name and summary checked
- [ ] Manifest version increased when required
- [ ] `npm run check:dist` confirms generated files are current and clean
- [ ] ZIP has `manifest.json` at its root
- [ ] ZIP contains no `.DS_Store`, secrets, HAR files, or private keys
- [ ] Screenshots and promo images contain no confidential data
- [ ] Store description is copied only from the Full Store Description section
- [ ] No suggested tags, protocol inventory, endpoint list, or cookie list was pasted into the description
- [ ] Repeated product and protocol terms remain below Google's keyword-spam threshold
- [ ] Fifth screenshot clearly demonstrates NetLog authentication tracing
- [ ] Store listing is accurate
- [ ] Single-purpose statement is accurate
- [ ] Data-use disclosures match local processing behavior
- [ ] Privacy-policy URL is public and accessible
- [ ] Permission justification is accurate
- [ ] Remote-code declaration is accurate
- [ ] Distribution and regions selected
- [ ] Reviewer instructions added
- [ ] Automatic or deferred publishing choice confirmed
- [ ] Web Store installation tested after publication
- [ ] NetLog categorized findings and raw source timeline tested
- [ ] NetLog Trace exchange and Kerberos/NTLM classification tested
- [ ] NetLog Trace TLS connection tested
- [ ] Contextual DNS, proxy, socket, HTTP, HTTP/2, or QUIC investigation tested
- [ ] HAR/JSON/NetLog import tested after publication

## Official References

- [Chrome Web Store documentation](https://developer.chrome.com/docs/webstore/)
- [Prepare an extension](https://developer.chrome.com/docs/webstore/prepare/)
- [Publish an extension](https://developer.chrome.com/docs/webstore/publish/)
- [Complete the store listing](https://developer.chrome.com/docs/webstore/cws-dashboard-listing/)
- [Privacy and user-data requirements](https://developer.chrome.com/docs/webstore/program-policies/user-data-faq/)
- [Configure distribution](https://developer.chrome.com/docs/webstore/cws-dashboard-distribution/)
- [Check review status](https://developer.chrome.com/docs/webstore/check-review/)
- [Cancel a pending review](https://developer.chrome.com/docs/webstore/cancel-review/)
- [Update a published extension](https://developer.chrome.com/docs/webstore/update/)
