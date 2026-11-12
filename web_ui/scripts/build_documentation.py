#!/usr/bin/env python3
# /// script
# dependencies = ["markdown-it-py==4.0.0"]
# ///
"""Build the in-app guide from the checked-in GitHub wiki Markdown.

Run from the repository root with: uv run web_ui/scripts/build_documentation.py
The wiki source stays byte-for-byte identical to the fetched revision; only
this generated HTML is served by the existing documentation navigation link.
"""
from __future__ import annotations

import hashlib
import html
from pathlib import Path
import re

from markdown_it import MarkdownIt

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "web_ui" / "docs" / "wiki" / "Home.md"
DESTINATION = ROOT / "web_ui" / "public" / "documentation.html"
WIKI_URL = "https://github.com/deangoldhill/RadiusStack/wiki"


def github_slug(text: str) -> str:
    text = text.lower().strip()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def build(source: str) -> str:
    # GitHub wiki uses literal break tags; keep them as breaks without enabling
    # untrusted raw HTML in the Markdown renderer.
    display_source = re.sub(r"<br\s*/>", "  \n", source, flags=re.I)
    md = MarkdownIt("commonmark", {"html": False, "breaks": True})
    md.enable("table")
    original_fence = md.renderer.rules["fence"]

    def render_fence(renderer, tokens, idx, options, env):
        token = tokens[idx]
        if token.info.strip().split(" ")[0] == "mermaid":
            return '<pre class="mermaid">' + html.escape(token.content) + '</pre>\n'
        return original_fence(tokens, idx, options, env)

    md.add_render_rule("fence", render_fence)
    tokens = md.parse(display_source)
    sections = []
    slug_counts = {}
    for idx, token in enumerate(tokens):
        if token.type == "heading_open":
            title = "".join(c.content for c in tokens[idx + 1].children if c.type in ("text", "code_inline"))
            slug = github_slug(title)
            count = slug_counts.get(slug, 0)
            slug_counts[slug] = count + 1
            if count:
                slug += f"-{count}"
            token.attrSet("id", slug)
            if token.tag != "h1":
                sections.append((slug, title, int(token.tag[1])))
    # The wiki's hand-written contents still links to three renamed headings.
    # Repair only those rendered fragments; keep the fetched Markdown unchanged.
    legacy_anchors = {
        "managing-users--totp-2fa": "managing-users--mfa",
        "administrators--2fa": "administration",
        "reporting-and-analyitcs": "reporting-and-analytics",
    }
    known_ids = {token.attrGet("id") for token in tokens if token.type == "heading_open"}
    for token in tokens:
        if token.type == "inline":
            for child in token.children or []:
                href = child.attrGet("href") or ""
                if child.type == "link_open" and href.startswith("#"):
                    anchor = href[1:].lower()
                    if anchor not in known_ids and legacy_anchors.get(anchor) in known_ids:
                        anchor = legacy_anchors[anchor]
                    child.attrSet("href", "#" + anchor)
    content = md.renderer.render(tokens, md.options, {})
    toc = "\n".join(
        f'<a class="toc-link depth-{depth}" href="#{html.escape(slug)}">{html.escape(title)}</a>'
        for slug, title, depth in sections
    )
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
    return f'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="wiki-source-sha256" content="{digest}">
  <title>RadiusStack Documentation</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    html {{ scroll-behavior: smooth; }}
    body {{ color: #1e293b; background: #f8fafc; }}
    .doc-grid {{ display:grid; grid-template-columns: 17rem minmax(0,1fr); gap:2rem; }}
    .toc {{ position:sticky; top:1.5rem; max-height:calc(100vh - 3rem); overflow:auto; align-self:start; }}
    .toc-link {{ display:block; padding:.25rem 0; color:#1d4ed8; text-decoration:none; }}
    .toc-link:hover, .toc-link:focus {{ text-decoration:underline; }}
    .depth-3 {{ padding-left:1rem; font-size:.9rem; }}
    .depth-4 {{ padding-left:2rem; font-size:.85rem; }}
    .wiki-content {{ min-width:0; line-height:1.7; }}
    .wiki-content h1, .wiki-content h2, .wiki-content h3 {{ color:#0f172a; font-weight:800; line-height:1.25; scroll-margin-top:1rem; }}
    .wiki-content h1 {{ font-size:2rem; margin:0 0 1rem; }}
    .wiki-content h2 {{ font-size:1.5rem; margin:2rem 0 .7rem; border-bottom:1px solid #e2e8f0; padding-bottom:.35rem; }}
    .wiki-content h3 {{ font-size:1.2rem; margin:1.4rem 0 .5rem; }}
    .wiki-content p, .wiki-content ul, .wiki-content ol {{ margin:.65rem 0; }}
    .wiki-content ul, .wiki-content ol {{ padding-left:1.6rem; }}
    .wiki-content ul {{ list-style:disc; }}
    .wiki-content ol {{ list-style:decimal; }}
    .wiki-content li {{ margin:.25rem 0; }}
    .wiki-content a {{ color:#1d4ed8; text-decoration:underline; }}
    .wiki-content blockquote {{ border-left:3px solid #60a5fa; padding:.25rem 1rem; background:#eff6ff; }}
    .wiki-content pre {{ overflow:auto; padding:1rem; background:#0f172a; color:#e2e8f0; border-radius:.7rem; }}
    .wiki-content pre.mermaid {{ background:#fff; color:#0f172a; text-align:center; border:1px solid #e2e8f0; }}
    .wiki-content pre.mermaid svg {{ max-width:100%; height:auto; }}
    .wiki-content code {{ background:#e2e8f0; border-radius:.2rem; padding:.08rem .25rem; }}
    .wiki-content pre code {{ padding:0; background:transparent; }}
    .wiki-content hr {{ border:0; border-top:1px solid #cbd5e1; margin:2rem 0; }}
    @media(max-width:900px) {{ .doc-grid {{ grid-template-columns:1fr; }} .toc {{ position:static; max-height:18rem; }} }}
  </style>
</head>
<body>
<main class="mx-auto max-w-screen-2xl px-4 py-8 lg:px-8">
  <header class="mb-6"><p class="text-sm font-semibold text-blue-700">RadiusStack help centre</p>
    <p class="text-slate-600">Documentation from the <a class="text-blue-700 underline" href="{WIKI_URL}" target="_blank" rel="noopener noreferrer">RadiusStack GitHub wiki</a>.</p>
  </header>
  <div class="doc-grid">
    <nav class="toc rounded-xl border border-slate-200 bg-white p-4" aria-label="Documentation table of contents">
      <p class="mb-2 text-sm font-bold uppercase tracking-wide text-slate-500">On this page</p>
      {toc}
    </nav>
    <article class="wiki-content rounded-xl border border-slate-200 bg-white p-5 md:p-8">{content}</article>
  </div>
</main>
<script type="module">
  import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@11.17.2/dist/mermaid.esm.min.mjs';
  mermaid.initialize({{ startOnLoad: false, securityLevel: 'strict', theme: 'default' }});
  mermaid.run({{ querySelector: '.mermaid' }});
</script>
<script src="/js/layout.js"></script>
<script src="/js/field-help.js"></script>
</body></html>
'''


if __name__ == "__main__":
    DESTINATION.write_text(build(SOURCE.read_text(encoding="utf-8")), encoding="utf-8")
    print(f"Built {DESTINATION} from {SOURCE}")
