import os
import markdown

# Base template mimicking articles.html layout with comprehensive SEO meta tags
TEMPLATE = """<!DOCTYPE html>
<html lang="en-GB">
<head>
  <meta charset="UTF-8" />
  <meta itemprop="datePublished" content="Sun, 22 Feb 2026 12:00:00 +0000" id="date">
  <meta itemprop="dateModified" content="Sun, 22 Feb 2026 12:00:00 +0000" id="last-modified">
  <title>{title} | uon Terminal</title>

  <!-- # Start Primary Meta Tags -->
  <meta name="author" content="contact@sebastienrousseau.com (Sebastien Rousseau)">
  <meta name="description" content="{description}">
  <meta name="generator" content="uon static compiler">
  <meta name="keywords" content="SSH, FIDO2, WebAuthn, Attestation, Zero-Trust, Rust, WebAssembly, Security">
  <meta name="language" content="en-GB">
  <meta name="permalink" content="https://sebastienrousseau.github.io/uon/{id}/index.html">
  <meta name="rating" content="general">
  <meta name="referrer" content="no-referrer">
  <meta name="robots" content="index, follow">
  <meta name="title" content="{title}">
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
  <!-- # End Primary Meta Tags -->

  <!-- # Start Open Graph / Facebook Meta Tags -->
  <meta name="og:description" content="{description}">
  <meta name="og:image" content="https://kura.pro/stock/images/banners/sebastien-rousseau.png">
  <meta name="og:image:alt" content="Black and White Portrait of Sebastien Rousseau">
  <meta name="og:image:height" content="162">
  <meta name="og:image:width" content="162">
  <meta name="og:locale" content="en_GB">
  <meta name="og:title" content="{title}">
  <meta name="og:type" content="website">
  <meta property="og:url" content="https://sebastienrousseau.github.io/uon/articles/{id}/">
  <!-- # End Open Graph / Facebook Meta Tags -->

  <!-- # Start Accessibility Meta Tags -->
  <meta name="accessibility" content="ARIA, fullKeyboardControl, noFlashingHazard" />
  <!-- # End Accessibility Meta Tags -->

  <!-- # Start Apple Meta Tags -->
  <meta name="apple_mobile_web_app_orientations" content="portrait">
  <meta name="apple_touch_icon_sizes" content="192x192">
  <!-- # End Apple Meta Tags -->

  <link rel="icon" href="/favicon.png" type="image/png" />
  <script>
    const savedTheme = localStorage.getItem('uon-theme');
    if (savedTheme) {{
      document.documentElement.setAttribute('data-theme', savedTheme);
    }}
  </script>
  <style>{minified_css}</style>
  <style>
    /* Article specific typography */
    .article-content {{
        font-size: 1.125rem;
        line-height: 1.8;
        color: var(--text-muted);
    }}
    .article-content h1 {{
        font-size: clamp(2.5rem, 5vw, 4rem);
        color: var(--brand-color);
        margin-bottom: 2rem;
        line-height: 1.1;
        letter-spacing: -0.04em;
    }}
    .article-content h2 {{
        font-size: 2rem;
        color: var(--text-main);
        margin-top: 3rem;
        margin-bottom: 1rem;
    }}
    .article-content p {{
        margin-bottom: 1.5rem;
    }}
    .article-content code {{
        background: var(--card-bg);
        padding: 0.2em 0.4em;
        border-radius: 6px;
        font-family: monospace;
        font-size: 0.9em;
        color: var(--brand-color);
    }}
    .article-content pre {{
        background: var(--card-bg);
        padding: 1.5rem;
        border-radius: 12px;
        overflow-x: auto;
        border: 1px solid var(--glass-border);
        margin: 2rem 0;
    }}
    .article-content pre code {{
        background: transparent;
        padding: 0;
        color: var(--text-muted);
    }}
  </style>
</head>
<body>
  <div class="ambient-glow" aria-hidden="true"></div>
  <a href="#main-content" class="skip-link">Skip to Content</a>
  <nav aria-label="Main Navigation">
    <div class="container nav-content flex items-center justify-between">
      <a href="/" class="logo" aria-label="uon home">uon<span>.</span></a>
      <div class="flex items-center gap-4">
        <a href="/articles" class="nav-link">Articles</a>
        <a href="/faq" class="nav-link">FAQ</a>
        <a href="/download" class="nav-link">Download</a>
        <button id="theme-toggle" class="nav-icon-btn" aria-label="Toggle dark mode">
          <svg id="icon-moon" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display: none;">
            <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
          </svg>
          <svg id="icon-sun" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display: none;">
            <circle cx="12" cy="12" r="5"></circle>
            <line x1="12" y1="1" x2="12" y2="3"></line>
            <line x1="12" y1="21" x2="12" y2="23"></line>
            <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line>
            <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>
            <line x1="1" y1="12" x2="3" y2="12"></line>
            <line x1="21" y1="12" x2="23" y2="12"></line>
            <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line>
            <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>
          </svg>
        </button>
      </div>
    </div>
  </nav>

  <main id="main-content" tabindex="-1">
    <section class="container" style="padding-top: 120px; padding-bottom: 80px;">
      <article class="article-content max-w-3xl mx-auto">
        {content}
      </article>
      <div class="text-center mt-12">
        <a href="/articles" class="btn btn-secondary" aria-label="Back to Articles">← Back to Articles</a>
      </div>
    </section>
  </main>

  <footer>
    <div class="container flex flex-col items-center gap-6" style="padding: 2rem 0;">
      <div class="flex gap-4 justify-center" style="flex-wrap: wrap;">
        <a href="/articles" class="nav-link">Articles</a>
        <a href="/faq" class="nav-link">FAQ</a>
        <a href="/download" class="nav-link">Download</a>
        <a href="mailto:support@uon.local" class="nav-link">support@uon.local</a>
      </div>
      <p>&copy; <script>document.write(new Date().getFullYear())</script> Sebastien Rousseau.</p>
    </div>
  </footer>

  <script>
    document.addEventListener("DOMContentLoaded", () => {{
      const themeBtn = document.getElementById("theme-toggle");
      const iconSun = document.getElementById("icon-sun");
      const iconMoon = document.getElementById("icon-moon");

      function applyTheme(theme) {{
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('uon-theme', theme);
        if (theme === 'dark') {{
          iconSun.style.display = 'block';
          iconMoon.style.display = 'none';
        }} else {{
          iconSun.style.display = 'none';
          iconMoon.style.display = 'block';
        }}
      }}

      const activeTheme = document.documentElement.getAttribute('data-theme') || 
        (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
      applyTheme(activeTheme);

      themeBtn.addEventListener("click", () => {{
        const newTheme = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
        applyTheme(newTheme);
      }});
    }});
  </script>
</body>
</html>
"""

import re
import glob
import frontmatter

def minify_css(css_path):
    with open(css_path, "r", encoding="utf-8") as style_file:
        cssContent = style_file.read()
    
    cssContent = re.sub(r"/\*[\s\S]*?\*/", "", cssContent)
    cssContent = re.sub(r"\s+", " ", cssContent)
    cssContent = re.sub(r"\s*([{}:;>])\s*", r"\1", cssContent)
    cssContent = cssContent.replace(";}", "}")
    return cssContent.strip()

def build():
    # Base directory relative to this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Read and minify CSS to inject into articles
    minified_css = minify_css(os.path.join(script_dir, "../src/styles.css"))

    # Output directly to dist directory
    out_dir = os.path.join(script_dir, "../dist")
    os.makedirs(out_dir, exist_ok=True)
    
    content_dir = os.path.join(script_dir, "../content/*.md")
    drafts = glob.glob(content_dir)
    article_cards_html = ""
    
    for draft in drafts:
        post = frontmatter.load(draft)
        article_id = os.path.basename(draft).replace(".md", "")
        title = post.metadata.get("title", article_id)
        desc = post.metadata.get("desc", "")
        category = post.metadata.get("category", "")
        
        feature_image_name = post.metadata.get("feature_image", f"{article_id}.webp")
        feature_image = f"https://kura.pro/stock/images/banners/{feature_image_name}"
        
        html_content = markdown.markdown(post.content)
        
        # Inject feature image to top of content
        content_with_image = f'<figure class="article-feature" style="margin-bottom: 2.5rem;"><img src="{feature_image}" alt="{title}" onerror="this.onerror=null; this.src=\'/fallback.webp\';" style="width: 100%; height: auto; border-radius: 24px;"></figure>\n{html_content}'
        
        final_html = TEMPLATE.format(
            title=title, 
            description=desc,
            id=article_id,
            content=content_with_image,
            minified_css=minified_css
        )
        
        # Ensure subdirectory exists inside dist/articles/
        article_dir = os.path.join(out_dir, "articles", article_id)
        os.makedirs(article_dir, exist_ok=True)
        
        file_path = os.path.join(article_dir, "index.html")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(final_html)
            
        print(f"Generated {file_path}")
        
        # Build HTML for the articles list
        article_cards_html += f'''
        <article class="card article-card cursor-pointer" onclick="window.location.href='/articles/{article_id}/index.html'">
          <figure class="article-card-image">
            <img src="{feature_image}" alt="{title}" onerror="this.onerror=null; this.src='/fallback.webp';" style="width: 100%; height: 100%; object-fit: cover; display: block;" loading="lazy" />
          </figure>
          <div class="article-card-content">
            <span class="tag">{category}</span>
            <h3>{title}</h3>
            <p>{desc}</p>
          </div>
        </article>
        '''

    # Inject cards into dist/articles/index.html
    articles_index_path = os.path.join(out_dir, "articles", "index.html")
    if os.path.exists(articles_index_path):
        with open(articles_index_path, "r", encoding="utf-8") as f:
            articles_html = f.read()
            
        pattern = re.compile(r'(<div id="dynamic-articles-container"[^>]*>)(.*?)(</div>)', re.DOTALL)
        articles_html = pattern.sub(rf'\1\n{article_cards_html}\n\3', articles_html)
        
        with open(articles_index_path, "w", encoding="utf-8") as f:
            f.write(articles_html)
            
        print(f"Injected metadata for {len(drafts)} articles into {articles_index_path}")

if __name__ == "__main__":
    build()
