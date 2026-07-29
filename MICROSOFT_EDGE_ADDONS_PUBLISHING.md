# Publish To Microsoft Edge Add-ons

## 1. Prepare And Test

1. Install Microsoft Edge.
2. Run `npm test`.
3. Run `npm run package:edge`.
4. Open `edge://extensions`.
5. Enable **Developer mode**.
6. Select **Load unpacked** and choose the repository's `dist-edge` directory.
7. Navigate to an ordinary HTTP(S) page before opening DevTools. Browser-protected pages do not expose extension DevTools panels.
8. Open Microsoft Edge DevTools and select **Auth Flow Inspector** from the Activity Bar or **More tools**.
9. Test live capture, HAR import, Inspector JSON import, NetLog import, filters, Flow Analysis, and both assessment exports.
10. Confirm the About tab identifies the Microsoft Edge package and uses `edge://net-export`.

## 2. Create The Partner Center Submission

1. Sign in to [Partner Center](https://partner.microsoft.com/dashboard/microsoftedge/overview).
2. Reserve the product name **Enterprise Authentication Flow Inspector**.
3. Create a new extension submission.
4. Upload `enterprise-auth-flow-inspector-edge-v3.0.0.zip`.
5. Complete the properties and store listing with `EDGE_STORE_LISTING.md`.
6. Provide the public privacy-policy URL:
   `https://ksudhir.github.io/oracle-sso-devtools/privacy/`
7. Upload the Edge-branded screenshots and promotional tiles from `store-assets/edge/`.
8. Add no more than the seven search terms listed in `EDGE_STORE_LISTING.md`.
9. Submit the extension for certification.

## 3. Reviewer Notes

Use notes similar to:

> This is a Manifest V3 DevTools extension with no requested host permissions. To see the panel, install the extension, navigate to an ordinary HTTPS page, open Microsoft Edge DevTools, and select Auth Flow Inspector from the Activity Bar or More tools. For offline review, choose Import File and select a HAR, Inspector JSON export, or Chromium NetLog JSON dump. All processing is local and the extension executes no remote code.

Attach a sanitized sample only when the reviewer requests one. Never upload customer authentication traces.

## 4. After Approval

1. Verify the public Microsoft Edge Add-ons listing.
2. Add its public URL to `edge/browser-config.js`, the project website, README, and store documentation.
3. Run `npm run build:edge`, `npm test`, and `npm run package:edge` again.
4. Publish the documentation update.
5. Test installation and automatic updates from the public listing.

## Release Checklist

- [ ] Manifest and package versions match.
- [ ] `dist` and `dist-edge` pass synchronization checks.
- [ ] The ZIP contains `manifest.json` at its root.
- [ ] No `.DS_Store`, source maps, test data, private files, or stale archives are present.
- [ ] Edge About content and NetLog instructions are correct.
- [ ] Screenshots are 1280x800 and have no alpha channel.
- [ ] Promotional tiles are 440x280 and 1400x560 with no alpha channel.
- [ ] Description, privacy statement, permission justification, and remote-code declaration are current.
- [ ] A real Microsoft Edge sideload test has passed.

## Official References

- [Port a Chrome extension to Microsoft Edge](https://learn.microsoft.com/en-us/microsoft-edge/extensions-chromium/developer-guide/port-chrome-extension)
- [Publish a Microsoft Edge extension](https://learn.microsoft.com/en-us/microsoft-edge/extensions/publish/publish-extension)
- [Extend Microsoft Edge DevTools](https://learn.microsoft.com/en-us/microsoft-edge/extensions/developer-guide/devtools-extension)
- [Capture a Chromium NetLog](https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/app-integration/use-netlog-capture-network-traffic)
