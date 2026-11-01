# NorthCause brand, browser tab, and sharing

NorthCause uses the finalized NorthCause mark and wordmark across the site header, customer portal, browser tab, and footer. The shared footer follows the Narmadya parent-company treatment while keeping the NorthCause product identity visible.

## Footer information

The footer presents the NorthCause logo, Narmadya Innovations copyright line, headquarters line, support email, product navigation, parent-company attribution, and a WhatsApp share action. The contact email is `hello@narmadaya.com`; the parent-company site is [narmadya.com](https://narmadya.com/). Location copy is `Jabalpur, MP, India · Singapore`.

## Browser tab and social cards

The browser tab uses the existing `/static/favicon.svg` and the NorthCause page title. Apple touch icons use `/static/apple-touch-icon.png`. Public pages include Open Graph and Twitter card metadata with a large 1200 × 630 NorthCause share image at `/static/northcause-share.png`; its editable vector source is `/static/northcause-share.svg`.

`NORTHCAUSE_PUBLIC_URL` sets the canonical public origin used for canonical links, Open Graph URLs, the social image URL, and the WhatsApp share link. It defaults to `https://northcause.com`. For an isolated local preview, set it to the local app origin, for example `http://127.0.0.1:8888`. Keep the production value set to `https://northcause.com` in the deployment environment so social platforms receive an absolute, public URL.

The footer's **Share on WhatsApp** link opens WhatsApp's share composer with a short NorthCause description and the homepage URL encoded as a single query parameter. The visitor still chooses the recipient and sends the message. This does not connect to WhatsApp APIs or expose customer/workspace data.

## Social-preview checks

After publishing, inspect the rendered page source and confirm that `og:title`, `og:description`, `og:url`, `og:image`, and `twitter:card` point to the expected NorthCause values and that the image URL returns the 1200 × 630 PNG. Social apps cache preview cards, so an older preview may continue to appear until that platform refreshes its cache.
