// Captures the documentation screenshots.
//
// Runs a real GateKeeper against a seeded database and photographs every page at
// three widths in both themes. See scripts/README.md for how to drive it.
//
//   node scripts/screenshots.mjs
//
// Environment:
//   PUBLIC_URL   public side, default http://localhost:18282
//   ADMIN_URL    admin side,  default http://localhost:18283
//   OUT_DIR      where PNGs are written, default docs/public/screenshots
//   COOKIES      JSON file holding {"user":"...","admin":"..."} session values

import puppeteer from 'puppeteer'
import fs from 'fs'
import path from 'path'

const PUBLIC = process.env.PUBLIC_URL || 'http://localhost:18282'
const ADMIN = process.env.ADMIN_URL || 'http://localhost:18283'
const OUT = process.env.OUT_DIR || 'docs/public/screenshots'
const COOKIES = process.env.COOKIES || 'cookies.json'

const cookies = JSON.parse(fs.readFileSync(COOKIES, 'utf8'))

// Widths worth documenting. The admin panel switches to a bottom navigation bar
// under 760px, so the phone size shows a genuinely different layout.
const viewports = [
  { name: '', width: 1440, height: 900, scale: 2 },
  { name: '-tablet', width: 820, height: 1180, scale: 2 },
  { name: '-mobile', width: 390, height: 844, scale: 3 },
]

const pages = [
  { name: 'login', url: PUBLIC + '/login', auth: null },
  { name: 'user-home', url: PUBLIC + '/', auth: 'user' },
  { name: 'admin-dashboard', url: ADMIN + '/', auth: 'admin' },
  { name: 'admin-users', url: ADMIN + '/users', auth: 'admin' },
  { name: 'admin-clients', url: ADMIN + '/clients', auth: 'admin' },
  { name: 'admin-policies', url: ADMIN + '/policies', auth: 'admin' },
  { name: 'admin-groups', url: ADMIN + '/groups', auth: 'admin' },
  { name: 'admin-audit', url: ADMIN + '/audit', auth: 'admin' },
  { name: 'admin-settings', url: ADMIN + '/settings', auth: 'admin' },
  { name: 'admin-backups', url: ADMIN + '/backups', auth: 'admin' },
]

// Only the widths that add something. Repeating every admin page on a phone
// produces near identical images and a heavier repository.
const mobilePages = new Set(['login', 'user-home', 'admin-dashboard', 'admin-users', 'admin-audit'])
const tabletPages = new Set(['login', 'user-home', 'admin-dashboard', 'admin-clients'])

function wanted(page, viewport) {
  if (viewport.name === '-mobile') return mobilePages.has(page.name)
  if (viewport.name === '-tablet') return tabletPages.has(page.name)
  return true
}

const wait = (ms) => new Promise((r) => setTimeout(r, ms))

// Closing a context occasionally races with the browser releasing it, which is
// not worth failing a capture run over.
async function closeQuietly(ctx) {
  try {
    await ctx.close()
  } catch {}
}

async function main() {
  fs.mkdirSync(OUT, { recursive: true })
  const browser = await puppeteer.launch({
    args: ['--no-sandbox', '--disable-dev-shm-usage'],
  })

  let taken = 0
  for (const theme of ['light', 'dark']) {
    for (const viewport of viewports) {
      for (const page of pages) {
        if (!wanted(page, viewport)) continue

        // A fresh context per shot, so a signed-in session never leaks into the
        // public sign-in page capture.
        const ctx = browser.createBrowserContext
          ? await browser.createBrowserContext()
          : await browser.createIncognitoBrowserContext()
        const tab = await ctx.newPage()
        await tab.setViewport({
          width: viewport.width,
          height: viewport.height,
          deviceScaleFactor: viewport.scale,
          isMobile: viewport.name === '-mobile',
          hasTouch: viewport.name !== '',
        })

        const origin = page.url.startsWith(ADMIN) ? ADMIN : PUBLIC
        // The theme is read from local storage by an inline script on load.
        await tab.goto(origin + '/favicon.svg', { waitUntil: 'domcontentloaded' }).catch(() => {})
        await tab.evaluate((t) => localStorage.setItem('gk_theme', t), theme)

        if (page.auth === 'user') {
          await tab.setCookie({ name: 'gk_session', value: cookies.user, url: PUBLIC })
        } else if (page.auth === 'admin') {
          await tab.setCookie({ name: 'gk_admin', value: cookies.admin, url: ADMIN })
        }

        try {
          await tab.goto(page.url, { waitUntil: 'networkidle2', timeout: 20000 })
        } catch (err) {
          console.log(`skip ${page.name}${viewport.name} ${theme}: ${err.message}`)
          await closeQuietly(ctx)
          continue
        }
        await wait(900)

        const file = path.join(OUT, `${page.name}${viewport.name}-${theme}.png`)
        await tab.screenshot({ path: file })
        console.log(`${theme.padEnd(5)} ${(viewport.name || '-desktop').padEnd(9)} ${page.name}`)
        taken++
        await tab.close().catch(() => {})
        await closeQuietly(ctx)
      }
    }
  }

  await browser.close()
  console.log(`\n${taken} screenshots written to ${OUT}`)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
