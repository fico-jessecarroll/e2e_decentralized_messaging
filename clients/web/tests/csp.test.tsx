import { readFileSync } from 'fs';
import path from 'node:path';

// This test checks that the source index.html contains the CSP meta tag.
test('source index.html contains CSP meta tag', () => {
  const srcIndex = readFileSync(path.resolve(__dirname, '..', 'index.html'), 'utf8');
  expect(srcIndex).toContain(
    `\u003cmeta http-equiv="Content-Security-Policy" content="default-src 'self'; connect-src 'self' ws: wss:; script-src 'self'; style-src 'self' 'unsafe-inline'" /\u003e`
  );
});