# Store Assets

Store publication artwork is separated by browser:

- `chrome/` contains only Google Chrome Web Store screenshots, promo tiles, and review manifests.
- `edge/` contains only Microsoft Edge Add-ons screenshots, promo tiles, and review manifests.
- `source-screenshots/` contains supplemental or legacy source images and must not be uploaded as a store screenshot set.
- `video/` contains the shared promotional video source and output.

Create isolated review bundles with:

```sh
npm run package:store:chrome
npm run package:store:edge
```

The installable extension ZIPs created by `npm run package:chrome` and `npm run package:edge` do not contain store screenshots or promotional artwork.

`npm test` verifies that each browser publication set contains exactly five screenshots and two promo tiles, that every manifest path resolves, and that key Chrome and Edge screenshots are not identical.

The first screenshot in each browser set is the standalone Offline Viewer with synthetic imported HAR evidence. The remaining screenshots retain SAML, OIDC, WNA/X.509, and NetLog analysis coverage.
