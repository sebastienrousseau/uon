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
  // Read inputs
  let htmlContent = fs.readFileSync(SOURCE_HTML, 'utf8');
  let cssContent = fs.readFileSync(SOURCE_CSS, 'utf8');

  // Minify CSS (Simple Regex Minifier for Zero-Dependencies)
  // 1. Remove comments
  // 2. Remove whitespace around braces, colons, semi-colons
  // 3. Remove newlines
  const minifiedCSS = cssContent
    .replace(/\/\*[\s\S]*?\*\//g, '')  // Replace block comments
    .replace(/\s+/g, ' ')              // Collapse whitespace
    .replace(/\s*([{}:;>])\s*/g, '$1') // Remove spaces around syntax
    .replace(/;}/g, '}')               // Remove trailing semicolons
    .trim();

  // Inject CSS into HTML inside a <style> block, replacing the placeholder
  const styleBlock = `<style>${minifiedCSS}</style>`;
  htmlContent = htmlContent.replace('<!-- <link rel="stylesheet" href="./styles.css" /> -->', styleBlock);

  // Minify HTML
  // DO NOT minify the ASCII header comment. Only minify the DOM payload.
  // We'll split the file at '<!DOCTYPE html>' to preserve the top CLI comment perfectly.
  const splitIndex = htmlContent.indexOf('<!DOCTYPE html>');
  const cliHeader = htmlContent.substring(0, splitIndex);
  let domBody = htmlContent.substring(splitIndex);

  // Strip normal HTML comments from DOM (excluding the CLI Header which we already separated)
  domBody = domBody.replace(/<!--[\s\S]*?-->/g, '');
  // Collapse whitespace between tags
  domBody = domBody.replace(/>\s+</g, '><');

  // Re-combine header and minified DOM
  const finalPayload = cliHeader + domBody;

  // Ensure output directory exists
  if (!fs.existsSync(OUTPUT_DIR)) {
    fs.mkdirSync(OUTPUT_DIR, { recursive: true });
  }

  // Write out the single ~15KB output
  fs.writeFileSync(OUTPUT_HTML, finalPayload, 'utf8');

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
