const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const { test, before, after } = require('node:test');
const { chromium } = require('playwright');

const repo = path.resolve(__dirname, '../..');
const theme = path.join(repo, 'deploy/docker-compose/chat/keycloak-themes/jjdguard/login');
const brandSource = fs.readFileSync(path.join(repo, 'enterprise-ai-portal/src/lib/brand.ts'), 'utf8');
const brandName = brandSource.match(/name: process\.env\.BRAND_NAME \?\? "([^"]+)"/)[1];
let browser;
let server;
let origin;

function message(locale, key) {
  const file = path.join(theme, 'messages', `messages_${locale}.properties`);
  if (!fs.existsSync(file)) return 'JJDGuard';
  const line = fs.readFileSync(file, 'utf8').split(/\r?\n/).find(line => line.startsWith(`${key}=`));
  return line?.slice(key.length + 1).replace(/\\u([0-9a-f]{4})/gi, (_, digits) => String.fromCharCode(parseInt(digits, 16)));
}

function fixture(page) {
  const header = message('zh_CN', 'loginTitleHtml');
  const properties = fs.readFileSync(path.join(theme, 'theme.properties'), 'utf8');
  const styles = properties.split(/\r?\n/).find(line => line.startsWith('styles=')).slice(7).split(/\s+/);
  const customStylesheet = styles.find(item => item.startsWith('css/jjdguard'));
  assert.ok(customStylesheet, 'theme custom stylesheet is unavailable');
  const body = page === 'logout'
    ? '<p class="instruction">Confirm sign out?</p><form id="kc-logout-confirm"><input class="pf-v5-c-button pf-m-primary" type="submit" value="Sign out"></form>'
    : '<form id="kc-form-login"><div class="pf-v5-c-form__group"><label for="username">Username</label><span class="pf-v5-c-form-control"><input id="username" name="username" autocomplete="username"></span></div><div class="pf-v5-c-form__group"><label for="password">Password</label><div class="pf-v5-c-input-group"><span class="pf-v5-c-form-control"><input id="password" name="password" type="password" autocomplete="current-password"></span><button class="pf-v5-c-button pf-m-control" type="button" aria-label="Show password">Eye</button></div></div><div id="kc-form-buttons"><input class="pf-v5-c-button pf-m-primary" id="kc-login" type="submit" value="Sign in"></div></form>';
  // The inherited template owns form fields and actions. This fixture exercises its shared layout.
  return `<!doctype html><html lang="zh-CN" class="login-pf"><head><meta name="viewport" content="width=device-width, initial-scale=1"><style>
    *{box-sizing:border-box}body{margin:0}.pf-v5-c-login{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:32px}
    .pf-v5-c-login__container{display:grid;grid-template-columns:34rem;grid-template-areas:"header" "main";gap:40px}
    .pf-v5-c-login__main{background:white;box-shadow:0 8px 16px #0002}.pf-v5-c-login__main-header{display:grid;grid-template-columns:70% 30%;padding:32px;border-top:4px solid #06c}
    .pf-v5-c-login__main-body{padding:0 32px 32px}.pf-v5-c-form-control{display:flex;border:1px solid #999}input{font:inherit;min-width:0}input:not([type=submit]){width:100%;padding:8px}button{font:inherit}
    .pf-v5-c-form__group{margin-bottom:20px}.pf-v5-c-form__group label{display:block;margin-bottom:6px}.pf-v5-c-button.pf-m-primary{width:100%;padding:10px;border:0;color:white;background:#06c}
    .pf-v5-c-login__header{grid-area:header}.pf-v5-c-login__main{grid-area:main}.pf-v5-c-input-group{display:flex}.pf-v5-c-input-group .pf-v5-c-form-control{flex:1;min-width:0}
    @media(min-width:1200px){.pf-v5-c-login__container{grid-template-areas:"header main";padding-inline:6.125rem}}
    #kc-header-wrapper{text-align:center}#kc-page-title{margin:0;font-size:28px}.pf-v5-c-login__main-header-utilities{justify-self:end}select{font:inherit}p{margin:0 0 20px}
  </style><link rel="stylesheet" href="/${customStylesheet}"></head><body data-page-id="login-${page}"><div class="pf-v5-c-login"><div class="pf-v5-c-login__container"><header id="kc-header" class="pf-v5-c-login__header"><div id="kc-header-wrapper" class="pf-v5-c-brand">${header}</div></header><main class="pf-v5-c-login__main"><div class="pf-v5-c-login__main-header"><h1 class="pf-v5-c-title pf-m-3xl" id="kc-page-title">${page === 'logout' ? 'Sign out' : 'Sign in'}</h1><div class="pf-v5-c-login__main-header-utilities"><span class="pf-v5-c-form-control"><select aria-label="Language"><option>Language</option></select></span></div></div><div class="pf-v5-c-login__main-body">${body}</div></main></div></div><script>document.querySelector('form').addEventListener('submit', e => {e.preventDefault();document.body.dataset.submitted='true'});</script></body></html>`;
}

before(async () => {
  server = http.createServer((req, res) => {
    const pathname = new URL(req.url, 'http://localhost').pathname;
    if (pathname.startsWith('/css/') || pathname.startsWith('/img/')) {
      const file = path.join(theme, 'resources', pathname.slice(1));
      res.setHeader('Content-Type', pathname.endsWith('.svg') ? 'image/svg+xml' : 'text/css');
      res.end(fs.readFileSync(file));
    } else {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end(fixture(req.url === '/logout' ? 'logout' : 'login'));
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
  browser = await chromium.launch({ executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH });
});

after(async () => {
  await browser?.close();
  await new Promise(resolve => server?.close(resolve));
});

test('brand title uses formal localized messages while authentication stays inherited', () => {
  assert.equal(message('zh_CN', 'loginTitleHtml'), brandName);
  assert.equal(message('zh_CN', 'loginTitle'), brandName);
  assert.ok(message('en', 'loginTitleHtml'));
  assert.equal(fs.existsSync(path.join(theme, 'template.ftl')), false);
  assert.equal(fs.existsSync(path.join(theme, 'login.ftl')), false);
  assert.equal(fs.existsSync(path.join(theme, 'logout-confirm.ftl')), false);
  const properties = fs.readFileSync(path.join(theme, 'theme.properties'), 'utf8');
  assert.match(properties, /^parent=keycloak\.v2$/m);
});

test('browser resource versions change with the portal skin', async () => {
  const properties = fs.readFileSync(path.join(theme, 'theme.properties'), 'utf8');
  assert.match(properties, /css\/jjdguard-portal-20261005\.css\?v=portal-20261005/);
  const page = await browser.newPage();
  try {
    await page.goto(`${origin}/login`);
    const image = await page.locator('#kc-header-wrapper').evaluate(element => getComputedStyle(element).backgroundImage);
    assert.match(image, /jjdguard-logo-portal-20261005\.svg\?v=portal-20261005/);
  } finally { await page.close(); }
});

test('custom theme assets have immutable physical version paths', () => {
  const properties = fs.readFileSync(path.join(theme, 'theme.properties'), 'utf8');
  assert.match(properties, /^styles=css\/styles\.css css\/jjdguard-portal-20261005\.css\?v=portal-20261005$/m);
  const css = fs.readFileSync(path.join(theme, 'resources/css/jjdguard-portal-20261005.css'), 'utf8');
  assert.match(css, /\.\.\/img\/jjdguard-logo-portal-20261005\.svg\?v=portal-20261005/);
  assert.ok(fs.existsSync(path.join(theme, 'resources/img/jjdguard-logo-portal-20261005.svg')));
  assert.equal(fs.existsSync(path.join(theme, 'resources/css/jjdguard.css')), false);
  assert.equal(fs.existsSync(path.join(theme, 'resources/img/jjdguard-logo.svg')), false);
});

test('invalid fields keep a visible error indication', async () => {
  const page = await browser.newPage();
  try {
    await page.goto(`${origin}/login`);
    const border = await page.locator('#username').evaluate(input => {
      input.closest('.pf-v5-c-form-control').classList.add('pf-m-error');
      input.setAttribute('aria-invalid', 'true');
      return getComputedStyle(input.closest('.pf-v5-c-form-control')).borderColor;
    });
    assert.equal(border, 'rgb(211, 47, 47)');
  } finally { await page.close(); }
});

for (const width of [1440, 390, 320]) {
  for (const surface of ['login', 'logout']) {
    test(`${surface} shares the portal brand and fits at ${width}px`, async () => {
      const page = await browser.newPage({ viewport: { width, height: 900 } });
      try {
        await page.goto(`${origin}/${surface}`);
        const styles = await page.evaluate(() => {
          const main = document.querySelector('main');
          const title = document.querySelector('#kc-header-wrapper');
          const primary = document.querySelector('.pf-m-primary');
          const style = getComputedStyle(main);
          const brand = getComputedStyle(title);
          return { title: title.textContent, border: style.borderTopWidth, shadow: style.boxShadow,
            primary: getComputedStyle(primary).backgroundColor, primaryHeight: primary.getBoundingClientRect().height,
            brandImage: brand.backgroundImage, brandImageSize: brand.backgroundSize,
            mainWidth: main.getBoundingClientRect().width,
            overflow: document.documentElement.scrollWidth > innerWidth,
            text: brand.color, background: getComputedStyle(document.body).backgroundColor };
        });
        assert.equal(styles.title, brandName);
        assert.equal(styles.border, '0px');
        assert.equal(styles.shadow, 'none');
        assert.equal(styles.primary, 'rgb(36, 81, 235)');
        assert.ok(styles.primaryHeight >= 44, JSON.stringify(styles));
        assert.match(styles.brandImage, /jjdguard-logo-portal-20261005\.svg/);
        assert.match(styles.brandImageSize, /56px/);
        assert.equal(styles.mainWidth, Math.min(384, width - (width <= 480 ? 32 : 48)), JSON.stringify(styles));
        assert.equal(styles.overflow, false);
        assert.notEqual(styles.text, 'rgba(0, 0, 0, 0)');
        assert.notEqual(styles.background, 'rgb(255, 255, 255)');
        assert.equal(await page.locator('select').isVisible(), true);
        if (surface === 'login') {
          await page.locator('#username').fill('regression-user');
          await page.locator('#password').fill('fixture-password');
          assert.equal(await page.locator('#username').inputValue(), 'regression-user');
          assert.equal(await page.locator('#password').inputValue(), 'fixture-password');
        }
        await page.locator('.pf-m-primary').click();
        assert.equal(await page.locator('body').getAttribute('data-submitted'), 'true');
        if (process.env.JJD_THEME_SCREENSHOTS) {
          fs.mkdirSync(process.env.JJD_THEME_SCREENSHOTS, { recursive: true });
          await page.screenshot({ path: path.join(process.env.JJD_THEME_SCREENSHOTS, `${surface}-${width}.png`) });
        }
      } finally { await page.close(); }
    });
  }
}
