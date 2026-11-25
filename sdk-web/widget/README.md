# @v18/widget

The V18 private age check that visitors see. One script, no framework, drawn in a Shadow DOM so
your page's styles don't change it.

The 2-line embed (use the exact `integrity` value from the release's `SRI.txt`):

```html
<script src="https://cdn.v18.example/v18-1.0.0.min.js" integrity="sha384-..." crossorigin="anonymous" data-v18-server="https://api.v18.example"></script>
<button data-v18-min-age="18">Verify age</button>
```

Your server needs two routes: `POST /v18/challenge` and `POST /v18/verify`, using `@v18/verify`
(Node) or `v18_verify` (Python). Ways to check: the V18 phone app (QR code), V18 for Windows, and
a phone wallet ID through the browser where both the browser and the V18 server support it.

From JavaScript: `V18.verify({ minAge: 18, onSuccess(ticket) { ... } })`.
The bundle is `dist/v18.min.js`. The full guide is `docs/web/INTEGRATION.md`.
Licence: UNLICENSED (no licence chosen yet, see LICENSE).
