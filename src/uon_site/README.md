# uon_site

## Overview
The `uon_site` architecture encapsulates all code required to build the Zero-Trust execution web portal. It parses static markdown (`.md`) structures and statically compiles them into a blistering fast, `<10ms` dependency-free HTML matrix.

## Core Directories

1. **`src/`:** The DOM templates, raw styling tokens (`styles.css`), and the overarching page scaffolds.
2. **`content/`:** The authoritative documentation articles, written strictly in normalized Markdown format.
3. **`scripts/`:** Holds the Node.js optimization tools (`build.js`) alongside the Python Jinja generation scripts (`generate_articles.py`).
4. **`assets/`:** Houses the SVG UI vector components and any static media arrays (like WebP demonstrations).
5. **`dist/`:** The output artifact directory. 

## Build Philosophy
The codebase is violently optimized for First Contentful Paint. External CSS imports are statically inlined, contrast ratios are pegged to WCAG AAA standards, and any interactive UI logic (e.g. CLI Installation Widgets, FIDO2 terminal typing mocks) is aggressively bound into native `Vanilla JS` loops rather than leveraging heavy upstream JS frameworks.
