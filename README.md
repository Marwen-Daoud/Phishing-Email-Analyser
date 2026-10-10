# Phishing Email Analyser

A privacy-first, browser-only tool that checks a pasted or uploaded email for common phishing and social-engineering warning signs, then explains every point of its score.

**Live demo:** _add your GitHub Pages link here_
**Screenshot:** _add a screenshot here (save it as `screenshot.png` and link it)_

> Educational triage tool. It looks for warning signs and cannot prove an email is safe or malicious. A low score does not mean safe.

## Features
- Risk score from 0 to 100 with a classification: Low Risk (0-29), Suspicious (30-59), High Risk (60-100)
- Every detected indicator is listed with its points, a plain-English reason and the matching evidence
- The email is shown with the suspicious text highlighted in place
- Paste text or upload a saved `.eml` file
- Optional header checks: Reply-To mismatch, display-name spoofing, SPF, DKIM and DMARC failures
- Copy report button, with links defanged (`hxxps://example[.]com`) so they are safe to share
- Six fictional demo emails (obvious, sophisticated, Microsoft 365, parcel, invoice/BEC, legitimate)
- Works on desktop and mobile, no installation or build step

## Privacy
All analysis runs locally in your browser. There is no backend, database, account system, analytics, tracking or external API call. A Content Security Policy in `index.html` makes the browser refuse connections to other sites, so the privacy design is technically enforced and not only promised.

## How scoring works
Every rule in `analyser.js` (see `RULES`) has a fixed point value. The points of all triggered rules are added, with a +10 bonus when pressure language appears together with a request for credentials, codes or money. The total is capped at 100. There is no hidden weighting, and you can edit any value.

## Run it
Download the files and open `index.html`. To run the tests (needs Node.js): `node tests/test.js`

## Hosting
Any static host works. For GitHub Pages: push these files, then Settings > Pages > deploy from the `main` branch.

## Limitations
- Keyword and pattern based, so expect false positives (legitimate emails that say "sign in") and false negatives (well-written attacks).
- Does not follow links, scan attachments or check domain reputation, by design, to stay offline and safe.
- `.eml` support is basic: it does not decode base64 bodies or attachments.

## Ideas for the future
Adjustable rule weights, Received-header path analysis, lookalike-domain detection, MITRE ATT&CK mapping (T1566).

## Licence
MIT. Built with AI assistance and reviewed by the author.
