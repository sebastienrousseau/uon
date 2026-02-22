const fs = require('fs');
const path = require('path');

// Target paths
const SOURCE_HTML = path.join(__dirname, 'index.html');
const SOURCE_CSS = path.join(__dirname, 'styles.css');
const SOURCE_FAVICON = path.join(__dirname, 'noun-rune-3458897.png');
const OUTPUT_DIR = path.join(__dirname, 'dist');
const OUTPUT_HTML = path.join(__dirname, 'dist', 'index.html');
const OUTPUT_FAVICON = path.join(__dirname, 'dist', 'favicon.png');

console.log('🚀 Starting uon ultra-lightweight build...');

try {
  // Minify CSS
  let cssContent = fs.readFileSync(SOURCE_CSS, 'utf8');
  const minifiedCSS = cssContent
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\s+/g, ' ')
    .replace(/\s*([{}:;>])\s*/g, '$1')
    .replace(/;}/g, '}')
    .trim();

  let finalSizeHTML = '';

  const PAGES = ['index', 'articles', 'faq', 'download'];
  for (let page of PAGES) {
    let htmlContent = fs.readFileSync(path.join(__dirname, page + '.html'), 'utf8');

    // Inject CSS into HTML inside a <style> block, replacing the placeholder
    const styleBlock = `<style>${minifiedCSS}</style>`;
    htmlContent = htmlContent.replace('<!-- <link rel="stylesheet" href="./styles.css" /> -->', styleBlock);

    const splitIndex = htmlContent.indexOf('<!DOCTYPE html>');
    const cliHeader = htmlContent.substring(0, splitIndex);
    let domBody = htmlContent.substring(splitIndex);

    // Strip HTML comments from DOM
    domBody = domBody.replace(/<!--[\s\S]*?-->/g, '');
    domBody = domBody.replace(/\s+/g, ' ');
    domBody = domBody.replace(/> </g, '><');

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

  // Copy favicon
  if (fs.existsSync(SOURCE_FAVICON)) {
    fs.copyFileSync(SOURCE_FAVICON, OUTPUT_FAVICON);
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
