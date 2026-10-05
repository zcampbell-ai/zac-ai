"""Caz AI presentation foundation.

Pure presentation for server-rendered pages: one reusable inline stylesheet and
the fixed owner sign-in document. Nothing here authorizes actions, reports
source connections, or produces conversational content; the source-backed
packet and gateway remain authoritative. Decorative layers are CSS-only, carry
no text, and never sit above content or controls.
"""

from __future__ import annotations

__all__ = ["CAZ_STYLE", "render_sign_in"]


CAZ_STYLE = """
/* ---- Tokens ---- */
:root {
  color-scheme: dark;
  --caz-ink: #0a0e13;
  --caz-text: #ecefe9;
  --caz-muted: #a7b2ad;
  --caz-surface: #f7f3ec;
  --caz-surface-sunk: #efe9de;
  --caz-card-ink: #171b20;
  --caz-card-muted: #4d5551;
  --caz-accent: #9fd8c0;
  --caz-accent-deep: #1d6a54;
  --caz-hairline: rgba(23, 27, 32, 0.12);
  --caz-radius: clamp(18px, 0.9rem + 1vw, 28px);
  --caz-gutter: clamp(1rem, 0.6rem + 2.4vw, 2.5rem);
  --caz-ease: cubic-bezier(0.2, 0.7, 0.2, 1);
  --caz-sans: ui-sans-serif, -apple-system, BlinkMacSystemFont, 'Segoe UI Variable Text', 'Segoe UI', system-ui, Roboto, 'Helvetica Neue', Arial, sans-serif;
  --caz-display: ui-serif, 'New York', 'Iowan Old Style', Charter, Georgia, serif;
}

*, *::before, *::after { box-sizing: border-box; }

html {
  background-color: var(--caz-ink);
  -webkit-text-size-adjust: 100%;
  text-size-adjust: 100%;
}

body {
  position: relative;
  isolation: isolate;
  margin: 0;
  min-height: 100vh;
  min-height: 100dvh;
  padding-top: max(var(--caz-gutter), env(safe-area-inset-top, 0px));
  padding-right: max(var(--caz-gutter), env(safe-area-inset-right, 0px));
  padding-bottom: max(calc(var(--caz-gutter) * 1.5), env(safe-area-inset-bottom, 0px));
  padding-left: max(var(--caz-gutter), env(safe-area-inset-left, 0px));
  color: var(--caz-text);
  font-family: var(--caz-sans);
  font-size: clamp(1rem, 0.97rem + 0.15vw, 1.0625rem);
  line-height: 1.6;
  overflow-wrap: anywhere;
  -webkit-font-smoothing: antialiased;
  text-rendering: optimizeLegibility;
}

/* ---- Ambient architecture: fixed, behind content, never interactive ---- */
body::before,
body::after {
  content: '';
  position: fixed;
  z-index: -1;
  pointer-events: none;
}

body::before {
  inset: -20vmax;
  background:
    radial-gradient(circle 42vmax at 80% 22%, rgba(159, 216, 192, 0.18), transparent 62%),
    radial-gradient(circle 34vmax at 12% 72%, rgba(118, 146, 206, 0.11), transparent 64%),
    radial-gradient(circle 46vmax at 52% 108%, rgba(214, 196, 160, 0.07), transparent 70%);
}

body::after {
  inset: 0;
  background-image:
    linear-gradient(rgba(236, 239, 233, 0.045) 1px, transparent 1px),
    linear-gradient(90deg, rgba(236, 239, 233, 0.045) 1px, transparent 1px);
  background-size: 56px 56px;
  -webkit-mask-image: radial-gradient(ellipse 70% 60% at 72% 18%, #000 0%, transparent 76%);
  mask-image: radial-gradient(ellipse 70% 60% at 72% 18%, #000 0%, transparent 76%);
}

::selection { background: rgba(159, 216, 192, 0.38); color: inherit; }

:focus-visible {
  outline: 3px solid var(--caz-accent);
  outline-offset: 3px;
}

a { color: var(--caz-accent); text-underline-offset: 0.2em; }

pre { white-space: pre-wrap; }

/* ---- Page frame ---- */
main {
  width: 100%;
  max-width: 46rem;
  margin-inline: auto;
}

h1 {
  margin: clamp(1rem, 4vw, 3rem) 0 0.75rem;
  font-family: var(--caz-display);
  font-size: clamp(2.1rem, 1.5rem + 3vw, 3.4rem);
  font-weight: 500;
  line-height: 1.06;
  letter-spacing: -0.022em;
  text-wrap: balance;
}

.meta {
  margin: 0 0 0.5rem;
  color: var(--caz-muted);
  font-size: 0.9375rem;
  line-height: 1.5;
}

fieldset {
  position: relative;
  min-width: 0;
  margin: clamp(1.75rem, 5vw, 3rem) 0 0;
  padding: 0;
  border: 0;
}

legend {
  max-width: 100%;
  margin-bottom: 1rem;
  padding: 0;
  color: var(--caz-accent);
  font-size: 0.8125rem;
  font-weight: 600;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  white-space: normal;
}

/* ---- One-at-a-time decision cards ---- */
/* Radios stay in the accessibility tree and tab order; only visually clipped. */
.card-radio {
  position: absolute;
  top: 0;
  left: 0;
  width: 1px;
  height: 1px;
  margin: -1px;
  padding: 0;
  border: 0;
  overflow: hidden;
  clip: rect(0 0 0 0);
  clip-path: inset(50%);
  white-space: nowrap;
  -webkit-appearance: none;
  appearance: none;
}

.card-radio + .decision-card { display: none; }

.card-radio:checked + .decision-card {
  display: block;
  animation: caz-enter 360ms var(--caz-ease) both;
}

/* If nothing is checked, show every card rather than hide content. */
main:not(:has(.card-radio:checked)) .card-radio + .decision-card { display: block; }

.card-radio:focus-visible + .decision-card {
  outline: 3px solid var(--caz-accent);
  outline-offset: 5px;
}

.decision-card {
  color-scheme: light;
  position: relative;
  min-width: 0;
  margin: 0;
  padding: clamp(1.25rem, 0.8rem + 2.6vw, 2.75rem);
  border: 1px solid rgba(255, 255, 255, 0.55);
  border-radius: var(--caz-radius);
  background: linear-gradient(180deg, #fbf8f2 0%, var(--caz-surface) 40%, #f2ede3 100%);
  color: var(--caz-card-ink);
  box-shadow:
    0 0 0 1px rgba(159, 216, 192, 0.12),
    inset 0 1px 0 rgba(255, 255, 255, 0.7),
    0 40px 90px -40px rgba(0, 0, 0, 0.8),
    0 12px 30px -18px rgba(0, 0, 0, 0.5);
  overflow-wrap: anywhere;
}

.decision-card::before {
  content: '';
  position: absolute;
  top: -1px;
  left: clamp(1.25rem, 0.8rem + 2.6vw, 2.75rem);
  width: 3.5rem;
  height: 3px;
  border-radius: 0 0 3px 3px;
  background: var(--caz-accent-deep);
  pointer-events: none;
}

.decision-card > :first-child { margin-top: 0; }
.decision-card > :last-child { margin-bottom: 0; }

.decision-card :focus-visible { outline-color: var(--caz-accent-deep); }

.decision-card .meta {
  color: var(--caz-card-muted);
  font-size: 0.875rem;
  letter-spacing: 0.01em;
}

.decision-card h2 {
  margin: 0.5rem 0 1.25rem;
  font-family: var(--caz-display);
  font-size: clamp(1.4rem, 1.1rem + 1.3vw, 2rem);
  font-weight: 500;
  line-height: 1.18;
  letter-spacing: -0.012em;
  text-wrap: pretty;
}

.decision-card h3 {
  margin: 1.5rem 0 0.4rem;
  color: var(--caz-accent-deep);
  font-size: 0.8125rem;
  font-weight: 650;
  letter-spacing: 0.12em;
  text-transform: uppercase;
}

.decision-card p { margin: 0 0 1rem; max-width: 62ch; }
.decision-card strong { font-weight: 650; }

.decision-card dl { margin: 0 0 1.25rem; }
.decision-card dt {
  margin-top: 1rem;
  color: var(--caz-accent-deep);
  font-size: 0.8125rem;
  font-weight: 650;
  letter-spacing: 0.12em;
  text-transform: uppercase;
}
.decision-card dd { margin: 0.25rem 0 0; }

.decision-card details {
  margin: 1.25rem 0;
  border: 1px solid rgba(23, 27, 32, 0.09);
  border-radius: 16px;
  background: rgba(23, 27, 32, 0.03);
}

.decision-card summary {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  min-height: 44px;
  padding: 0.7rem 1rem;
  border-radius: 15px;
  font-weight: 600;
  list-style: none;
  cursor: pointer;
  transition: background-color 160ms ease;
}

.decision-card summary::-webkit-details-marker { display: none; }

.decision-card summary::before {
  content: '';
  flex: none;
  width: 0.5rem;
  height: 0.5rem;
  border-right: 2px solid currentColor;
  border-bottom: 2px solid currentColor;
  transform: rotate(-45deg);
  transition: transform 200ms var(--caz-ease);
}

.decision-card details[open] > summary::before { transform: rotate(45deg); }

.decision-card details > :not(summary) { margin: 0 1rem 1rem; }
.decision-card details > summary + * { margin-top: 0.25rem; }

.decision-card blockquote {
  white-space: pre-wrap;
  margin: 0 0 1rem;
  padding: 0.9rem 1.1rem;
  border-left: 3px solid var(--caz-accent-deep);
  border-radius: 0 12px 12px 0;
  background: var(--caz-surface-sunk);
}

.decision-card blockquote > :last-child { margin-bottom: 0; }

.decision-card details ol,
.decision-card > ol {
  margin: 0 0 1rem;
  padding-left: 1.4rem;
}

.decision-card li + li { margin-top: 0.4rem; }
.decision-card li::marker { color: var(--caz-accent-deep); font-weight: 600; }

/* ---- Card footer: drafts, then navigation ---- */
.decision-card .choices {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.625rem;
  margin: 1.75rem 0 0;
  padding: 1.25rem 0 0;
  border-top: 1px solid var(--caz-hairline);
  list-style: none;
}

.decision-card .choices li { margin: 0; }
.decision-card .choices li::marker { content: none; }

.decision-card button {
  min-height: 44px;
  padding: 0.65rem 1.15rem;
  border: 1px solid var(--caz-card-ink);
  border-radius: 999px;
  background: var(--caz-card-ink);
  color: var(--caz-surface);
  font: inherit;
  font-size: 0.9375rem;
  font-weight: 600;
  line-height: 1.3;
}

.decision-card button:disabled {
  border: 1px dashed rgba(23, 27, 32, 0.45);
  background: transparent;
  color: var(--caz-card-muted);
  cursor: not-allowed;
}

.decision-card nav {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
  margin-top: 1rem;
}

.decision-card nav :where(ul, ol) {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  gap: 0.75rem;
  width: 100%;
  margin: 0;
  padding: 0;
  list-style: none;
}

.decision-card nav label {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 44px;
  min-height: 44px;
  padding: 0.6rem 1.15rem;
  border: 1px solid rgba(23, 27, 32, 0.18);
  border-radius: 999px;
  background: rgba(255, 255, 255, 0.6);
  color: var(--caz-card-ink);
  font-size: 0.9375rem;
  font-weight: 600;
  line-height: 1.3;
  text-align: center;
  cursor: pointer;
  -webkit-user-select: none;
  user-select: none;
  -webkit-tap-highlight-color: transparent;
  transition: background-color 160ms ease, border-color 160ms ease, transform 160ms var(--caz-ease);
}

.decision-card nav label:active { transform: translateY(1px); }

@media (hover: hover) {
  .decision-card summary:hover { background: rgba(23, 27, 32, 0.045); }
  .decision-card nav label:hover {
    border-color: var(--caz-accent-deep);
    background: #fff;
  }
}

@media (max-width: 30rem) {
  .decision-card .choices > * { flex: 1 1 100%; }
  .decision-card .choices button { width: 100%; }
  .decision-card nav label { flex: 1 1 8rem; }
}

/* ---- Host session control ---- */
.caz-session-control { margin-top: 2rem; }
.caz-session-control button {
  min-height: 44px; padding: 0.6rem 1rem; border: 1px solid var(--caz-muted);
  border-radius: 999px; background: transparent; color: var(--caz-text);
  font: inherit; cursor: pointer;
}

/* ---- Sign-in document ---- */
.caz-sign-in {
  display: grid;
  place-items: center;
}

.caz-sign-in main { max-width: 28rem; }

.caz-panel {
  color-scheme: light;
  position: relative;
  padding: clamp(1.75rem, 1rem + 4vw, 3rem);
  border: 1px solid rgba(255, 255, 255, 0.55);
  border-radius: var(--caz-radius);
  background: linear-gradient(180deg, #fbf8f2 0%, var(--caz-surface) 45%, #f2ede3 100%);
  color: var(--caz-card-ink);
  box-shadow:
    0 0 0 1px rgba(159, 216, 192, 0.12),
    inset 0 1px 0 rgba(255, 255, 255, 0.7),
    0 40px 90px -40px rgba(0, 0, 0, 0.8);
  animation: caz-enter 420ms var(--caz-ease) both;
}

.caz-panel :focus-visible { outline-color: var(--caz-accent-deep); }

.caz-mark {
  display: block;
  width: 3rem;
  height: 3rem;
  margin-bottom: 1.75rem;
  border-radius: 50%;
  background: radial-gradient(circle at 32% 30%, #dcf2e8 0%, var(--caz-accent) 40%, #3f8f76 100%);
  box-shadow: 0 0 0 6px rgba(29, 106, 84, 0.08), 0 12px 30px -10px rgba(29, 106, 84, 0.55);
}

.caz-panel h1 {
  margin: 0 0 0.75rem;
  font-size: clamp(2.25rem, 1.6rem + 3vw, 3rem);
}

.caz-lede {
  max-width: 34ch;
  margin: 0 0 2rem;
  color: var(--caz-card-muted);
  font-size: 1.0625rem;
}

.caz-panel form { margin: 0; }

.caz-signin-button {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.75rem;
  width: 100%;
  min-height: 52px;
  padding: 0.85rem 1.5rem;
  border: 1px solid var(--caz-card-ink);
  border-radius: 999px;
  background: var(--caz-card-ink);
  color: var(--caz-surface);
  font: inherit;
  font-size: 1rem;
  font-weight: 600;
  line-height: 1.3;
  cursor: pointer;
  -webkit-tap-highlight-color: transparent;
  transition: background-color 160ms ease, transform 160ms var(--caz-ease);
}

.caz-signin-button::before {
  content: '';
  flex: none;
  width: 0.5rem;
  height: 0.5rem;
  border-radius: 50%;
  background: var(--caz-accent);
  box-shadow: 0 0 0 4px rgba(159, 216, 192, 0.2);
}

.caz-signin-button:active { transform: translateY(1px); }

@media (hover: hover) {
  .caz-signin-button:hover { background: #1f2b2a; }
}

/* ---- Motion ---- */
@keyframes caz-enter {
  from { opacity: 0; transform: translateY(10px); }
  to { opacity: 1; transform: none; }
}

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation: none !important;
    transition: none !important;
    scroll-behavior: auto !important;
  }
}

/* ---- Higher contrast preference ---- */
@media (prefers-contrast: more) {
  :root {
    --caz-muted: #d3dbd7;
    --caz-card-muted: #2c322f;
    --caz-hairline: rgba(23, 27, 32, 0.4);
  }
  body::after { display: none; }
}

/* ---- Forced colors: drop decoration, keep structure ---- */
@media (forced-colors: active) {
  body::before, body::after, .decision-card::before { display: none; }
  .decision-card, .caz-panel, .decision-card details, .decision-card blockquote {
    border: 1px solid CanvasText;
  }
  .card-radio:focus-visible + .decision-card { outline: 3px solid Highlight; }
  :focus-visible { outline-color: Highlight; }
  .decision-card nav label, .decision-card button, .caz-signin-button {
    border: 1px solid ButtonText;
  }
  .decision-card button:disabled { border-color: GrayText; color: GrayText; }
  .caz-mark { border: 2px solid CanvasText; }
}

/* ---- Print: every card, every detail, no decoration ---- */
@media print {
  html, body { background: #fff !important; color: #000 !important; }
  body { display: block; padding: 0; }
  body::before, body::after, .decision-card::before, .caz-mark { display: none !important; }
  legend { color: #000; }
  .meta, .decision-card .meta { color: #333; }
  .card-radio + .decision-card {
    display: block !important;
    margin: 0 0 1.5rem;
    border: 1px solid #888;
    background: #fff;
    box-shadow: none;
    animation: none !important;
  }
  .decision-card h2, .decision-card summary { break-after: avoid; }
  main details > :not(summary) { display: block !important; }
  .decision-card blockquote { background: none; }
  .decision-card nav { display: none; }
  .caz-panel { box-shadow: none; border: 1px solid #888; animation: none; }
}

@media print {
  main details::details-content { content-visibility: visible; display: block; }
}
"""


_SIGN_IN_HEAD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="dark">
<title>Caz AI</title>
<style>"""

_SIGN_IN_BODY = """</style>
</head>
<body class="caz-sign-in">
<main>
<div class="caz-panel">
<span class="caz-mark" aria-hidden="true"></span>
<h1>Caz AI</h1>
<p class="caz-lede">A private workspace for its owner. Sign in with your Google account to continue.</p>
<form method="post" action="/login">
<button class="caz-signin-button" type="submit">Sign in with Google</button>
</form>
</div>
</main>
</body>
</html>
"""

_SIGN_IN_DOCUMENT = _SIGN_IN_HEAD + CAZ_STYLE + _SIGN_IN_BODY


def render_sign_in() -> str:
    """Return the fixed, standalone owner sign-in document."""
    return _SIGN_IN_DOCUMENT
