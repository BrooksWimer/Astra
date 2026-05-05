# Epic: mobile-wifi-scanner

_Read [`../PROJECT_CONTEXT.md`](../PROJECT_CONTEXT.md) and [`../PROJECT_ROADMAP.md`](../PROJECT_ROADMAP.md) before starting a slice._

## Goal

Make the Astra mobile app the **acquisition surface** for ordinary home users. First-time use must produce a meaningful list of labeled devices within Apple's local-network entitlement constraints, with no setup beyond granting permission. When the user installs the desktop agent later, the mobile experience gets richer via the hosted backend without the user re-doing anything.

## In scope

- Expo / React Native app behavior (`mobile/`).
- Mobile UX for device discovery, labels, and insights.
- Phone-side mDNS / Bonjour discovery and the limited active probing iOS permits.
- Phone-to-agent flow: when the user has the desktop agent installed, mobile gets the desktop's deeper labels.
- Hosted-backend sync from the client side: pulling labels learned elsewhere, surfacing them on the device the user is on now.
- iPhone-only feasibility research and the boundary between "mobile-only useful" and "you need the desktop agent."

## Out of scope

- Desktop Go scanner internals — belong in [`laptop-wifi-scanner`](laptop-wifi-scanner.md). Mobile work that depends on scanner output schema is fine; mobile work that changes how the scanner produces labels is not.
- Authenticated router-admin ingestion — belongs in [`router-admin-ingestion`](router-admin-ingestion.md). The mobile app may surface router-admin results once that epic ships; the credential entry and extraction are not done here.
- Server-side hosted-backend implementation — that's a `server/`-side workstream (no separate epic yet; falls under whichever lane originates the work).
- Network-admin / IT-pro features (topology diagrams, SNMP). Astra is for ordinary home users.

## Planning guidance

- **First impression is the product.** A first-time user who taps scan and sees a useful list of labeled devices in under 30 seconds is the design target. Onboarding flows that ask permissions, explain features, or wait for backend sync break that bar.
- **Don't expose scanner internals.** Strategy names, mDNS query types, OUI lookups are scanner research, not user-facing copy. The mobile UX shows labels and confidence; what produced the label is metadata, not visible.
- **Hybrid scanning trajectory.** The long-term goal is Bonjour / mDNS + limited probing + backend-supplied labels. Don't paint the product into "iOS only does Bonjour" copy; the boundary moves over time as M5 progresses.
- **Empty / loading / error states matter.** Local-network permission denied, no devices found, sync failure — every state needs a deliberate UX rather than "the list is just empty."
- **Coordinate the label schema with `laptop-wifi-scanner`.** When the schema changes, both surfaces and the hosted backend update together. The operator should not see "v2.1.3" on desktop and "v2.0.x" on mobile.

## Success criteria for M2 (first-impression) and M5 (hybrid)

(See [`../PROJECT_ROADMAP.md`](../PROJECT_ROADMAP.md).)

- **M2:** First-time mobile user opens the app, taps scan, sees a meaningful list with labels — no operator coaching, no docs, no setup beyond local-network permission. If desktop is installed, richer labels follow via backend sync.
- **M5:** Mobile-only labels are noticeably better than mDNS alone could produce, and the iOS feasibility boundary is documented and surfaced in the UX.
