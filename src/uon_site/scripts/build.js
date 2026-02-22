const fs = require('fs');
const path = require('path');

// Target paths
const SOURCE_HTML_DIR = path.join(__dirname, '../src');
const SOURCE_CSS = path.join(__dirname, '../src', 'styles.css');
const SOURCE_FAVICON = path.join(__dirname, '../assets', 'noun-rune-3458897.png');
const OUTPUT_DIR = path.join(__dirname, '../dist');
const OUTPUT_HTML = path.join(__dirname, '../dist', 'index.html');
const OUTPUT_FAVICON = path.join(__dirname, '../dist', 'favicon.png');
const SOURCE_PKG = path.join(__dirname, '../pkg');
const OUTPUT_PKG = path.join(__dirname, '../dist', 'pkg');

console.log('🚀 Starting uon ultra-lightweight build...');

try {
  // Clean dist directory automatically
  if (fs.existsSync(OUTPUT_DIR)) {
    fs.rmSync(OUTPUT_DIR, { recursive: true, force: true });
  }
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });

  // Minify CSS
  let cssContent = fs.readFileSync(SOURCE_CSS, 'utf8');
  const minifiedCSS = cssContent
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\s+/g, ' ')
    .replace(/\s*([{}:;>])\s*/g, '$1')
    .replace(/;}/g, '}')
    .trim();

  let finalSizeHTML = '';

  fs.writeFileSync(path.join(OUTPUT_DIR, 'styles.css'), minifiedCSS);

  const PAGES = ['index', 'articles', 'faq', 'download'];
  for (let page of PAGES) {
    let htmlContent = fs.readFileSync(path.join(__dirname, '../src', page + '.html'), 'utf8');

    // No longer injecting minified CSS directly into HTML (Red List Sanitation).
    // Native <link> element handles stylesheet linkage to leverage CDNs and caching.

    const splitIndex = htmlContent.indexOf('<!DOCTYPE html>');
    let cliHeader = htmlContent.substring(0, splitIndex);
    let domBody = htmlContent.substring(splitIndex);

    // Strip HTML comments from DOM
    domBody = domBody.replace(/<!--[\s\S]*?-->/g, '');
    domBody = domBody.replace(/>\s+</g, '><');

    // Inline CSS into domBody to eliminate render-blocking network requests
    // Using a regex to catch any variance in spacing or trailing slashes
    domBody = domBody.replace(
      /<link\s+rel="stylesheet"\s+href="\/styles\.css"\s*\/?>/i,
      `<style>${minifiedCSS}</style>`
    );

    const finalPayload = cliHeader + domBody;

    // Determine output path (e.g. dist/articles/index.html to avoid using .html extensions in URL routing)
    let outDir = OUTPUT_DIR;
    if (page !== 'index') {
      outDir = path.join(OUTPUT_DIR, page);
      if (!fs.existsSync(outDir)) {
        fs.mkdirSync(outDir, { recursive: true });
      }
    } else {
      if (!fs.existsSync(outDir)) {
        fs.mkdirSync(outDir, { recursive: true });
      }
      finalSizeHTML = finalPayload;
    }
    fs.writeFileSync(path.join(outDir, 'index.html'), finalPayload);
  }

  // Copy favicon and webp fallback
  if (fs.existsSync(SOURCE_FAVICON)) {
    fs.copyFileSync(SOURCE_FAVICON, OUTPUT_FAVICON);
  }
  const SOURCE_FALLBACK = path.join(__dirname, '../assets', 'fallback.webp');
  const OUTPUT_FALLBACK = path.join(__dirname, '../dist', 'fallback.webp');
  if (fs.existsSync(SOURCE_FALLBACK)) {
    fs.copyFileSync(SOURCE_FALLBACK, OUTPUT_FALLBACK);
  }

  // Copy pkg directory
  if (fs.existsSync(SOURCE_PKG)) {
    if (!fs.existsSync(OUTPUT_PKG)) fs.mkdirSync(OUTPUT_PKG, { recursive: true });
    fs.readdirSync(SOURCE_PKG).forEach(file => {
      fs.copyFileSync(path.join(SOURCE_PKG, file), path.join(OUTPUT_PKG, file));
    });
  }

  // Validate payload size
  const stats = fs.statSync(OUTPUT_HTML);
  const sizeKB = (stats.size / 1024).toFixed(2);

  if (stats.size > 15360) {
    console.warn(`⚠️ WARNING: Final payload is ${sizeKB}KB (Exceeds <15KB goal).`);
  } else {
    console.log(`✅ Success! Final payload is incredibly light: ${sizeKB}KB.`);
  }

} catch (e) {
  console.error('❌ Build failed:', e.message);
  process.exit(1);
}
