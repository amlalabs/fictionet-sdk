"""Records the dashboard while nmap scans the scan example's subnet.

Run by record.sh, which starts the Docker Compose stack first. This script
opens the dashboard in Chromium with Playwright's video recording, puts a
terminal panel beside it that shows nmap's real output as it runs, and
drives the dashboard the way a viewer would: it opens a group, watches the
scanner's link, and drags a node. The video lands in the output folder as
dashboard.webm.

    uv run --with playwright python record.py <dashboard url> <out dir> <compose args...>
"""

import asyncio
import os
import shutil
import sys
from pathlib import Path

from playwright.async_api import async_playwright

URL = sys.argv[1]
OUT = Path(sys.argv[2])
COMPOSE = sys.argv[3:]  # how to run `docker compose` for this stack
W, H = 1920, 1080
PANEL = 600  # the terminal panel's width

DISCOVERY = ["nmap", "-sn", "-n", "10.0.0.0/24"]
PORT_SCAN = ["nmap", "-sS", "-sV", "-n", "-p", "1-1024", "--max-rate", "200", "10.0.0.0/24"]

# The terminal panel, the captions and a pointer, added to the page. Only
# the recording has them; the dashboard itself is unchanged.
SETUP = r"""
(panel) => {
  const css = document.createElement('style');
  css.textContent = `
    .app { width: calc(100vw - ${panel}px); }
    #rec-term { position: fixed; top: 0; right: 0; bottom: 0; width: ${panel}px; display: flex; flex-direction: column;
      background: #141915; color: #dfe3d6; border-left: 1px solid #2a312b; font: 13px/1.5 'IBM Plex Mono', 'JetBrains Mono', 'DejaVu Sans Mono', monospace; }
    #rec-term header { display: flex; align-items: center; gap: 10px; height: 52px; padding: 0 18px; border-bottom: 1px solid #2a312b;
      font: 600 14px 'DM Sans', system-ui, sans-serif; color: #e2e4d6; }
    #rec-term header i { width: 9px; height: 9px; border-radius: 2px; background: #f0704c; }
    #rec-term header span { font-weight: 400; color: #9ba391; }
    #rec-term pre { flex: 1; margin: 0; padding: 14px 18px; overflow: hidden; white-space: pre-wrap; word-break: break-word; font-size: 12.5px; line-height: 1.45; }
    #rec-term .prompt { color: #8fcb84; }
    #rec-term .cmd { color: #f7f6f0; font-weight: 600; }
    #rec-term .up { color: #f0b48f; }
    #rec-term .open { color: #8fcb84; }
    #rec-term .real { color: #f0704c; font-weight: 600; }
    #rec-term .caret { display: inline-block; width: 8px; height: 15px; vertical-align: -2px; background: #dfe3d6; }
    #rec-caption { flex: none; min-height: 132px; padding: 18px 22px 20px; border-top: 1px solid #2a312b; background: #1b211c;
      color: #e2e4d6; font: 400 18px/1.45 'DM Sans', system-ui, sans-serif; transition: opacity .35s; }
    #rec-caption b { color: #f0b48f; font-weight: 600; }
    #rec-pointer { position: fixed; left: 0; top: 0; width: 22px; height: 22px; z-index: 100; pointer-events: none;
      transition: transform 0s; }
    #rec-ripple { position: fixed; width: 34px; height: 34px; margin: -17px 0 0 -17px; border-radius: 50%;
      border: 2px solid #df5835; z-index: 99; pointer-events: none; opacity: 0; }
    #rec-ripple.on { animation: rec-ripple .5s ease-out; }
    @keyframes rec-ripple { from { opacity: .9; transform: scale(.4); } to { opacity: 0; transform: scale(1.3); } }
  `;
  document.head.appendChild(css);
  const term = document.createElement('aside');
  term.id = 'rec-term';
  term.innerHTML = '<header><i></i>scanner <span>the agent’s sandbox, 10.0.9.2</span></header><pre></pre>';
  document.body.appendChild(term);
  const cap = document.createElement('div');
  cap.id = 'rec-caption';
  term.appendChild(cap);
  const ptr = document.createElement('div');
  ptr.id = 'rec-pointer';
  ptr.innerHTML = '<svg viewBox="0 0 22 22" width="22" height="22"><path d="M3 2l15 9-6.5 1.6L8.7 19z" fill="#141915" stroke="#f7f6f0" stroke-width="1.6" stroke-linejoin="round"/></svg>';
  document.body.appendChild(ptr);
  const rip = document.createElement('div');
  rip.id = 'rec-ripple';
  document.body.appendChild(rip);
  window.rec = {
    pre: term.querySelector('pre'),
    caption(html) {
      cap.innerHTML = html;
    },
    // Appends text to the terminal. Lines nmap prints get colors.
    write(text, cls) {
      const pre = this.pre;
      pre.querySelector('.caret')?.remove();
      for (const line of text.split(/(\n)/)) {
        if (line === '\n') { pre.append('\n'); continue; }
        if (!line) continue;
        const s = document.createElement('span');
        let c = cls || '';
        if (!cls) {
          if (/^Nmap scan report for 10\.0\.0\.50/.test(line)) c = 'real';
          else if (/^Nmap scan report|Host is up|hosts up/.test(line)) c = 'up';
          else if (/\/tcp\s+open/.test(line)) c = 'open';
        }
        if (c) s.className = c;
        s.textContent = line;
        pre.append(s);
      }
      const caret = document.createElement('span');
      caret.className = 'caret';
      pre.append(caret);
      // Keep the newest lines in view.
      while (pre.scrollHeight > pre.clientHeight && pre.firstChild) pre.firstChild.remove();
    },
    pointer(x, y, ms = 0) {
      ptr.style.transition = `transform ${ms}ms linear`;
      ptr.style.transform = `translate(${x - 3}px, ${y - 2}px)`;
    },
    ripple(x, y) { rip.style.left = x + 'px'; rip.style.top = y + 'px'; rip.classList.remove('on'); void rip.offsetWidth; rip.classList.add('on'); },
  };
  window.rec.pointer(innerWidth / 2 - panel / 2, innerHeight / 2);
}
"""


class Pointer:
    """Moves Playwright's mouse and the pointer drawn on the page together."""

    def __init__(self, page):
        self.page = page
        self.x, self.y = (W - PANEL) / 2, H / 2

    async def move(self, x, y, ms=500):
        # The drawn pointer glides with a CSS transition; the real mouse
        # moves in steps over the same time.
        await self.page.evaluate("([x, y, ms]) => rec.pointer(x, y, ms)", [x, y, ms])
        steps = max(1, int(ms / 25))
        x0, y0 = self.x, self.y
        for i in range(1, steps + 1):
            t = i / steps
            await self.page.mouse.move(x0 + (x - x0) * t, y0 + (y - y0) * t)
            await asyncio.sleep(ms / 1000 / steps)
        self.x, self.y = x, y

    async def click(self, x, y, double=False):
        await self.move(x, y)
        await self.page.evaluate("([x, y]) => rec.ripple(x, y)", [x, y])
        await self.page.mouse.click(x, y, click_count=2 if double else 1, delay=40)

    async def drag(self, x, y, dx, dy, ms=1100):
        await self.move(x, y)
        await self.page.mouse.down()
        await self.move(x + dx, y + dy, ms)
        await self.page.mouse.up()


async def edge_point(page, test, at=0.5):
    """A point on screen on the first drawn edge that `test` (JavaScript, given
    the edge d and its two ends a and b) picks."""
    return await page.evaluate(
        """([test, at]) => {
          const pick = new Function('d', 'a', 'b', 'return ' + test);
          const d = [...view.dedges.values()].find((d) => pick(d, view.items.get(d.a), view.items.get(d.b)));
          const p = d.wire.getPointAtLength(d.len * at);
          const m = d.wire.getScreenCTM();
          return [p.x * m.a + m.e, p.y * m.d + m.f];
        }""",
        [test, at],
    )


async def center(page, selector):
    box = await page.locator(selector).first.bounding_box()
    return box["x"] + box["width"] / 2, box["y"] + box["height"] / 2


async def type_command(page, argv):
    await page.evaluate("t => rec.write(t, 'prompt')", "root@scanner:~# ")
    for word in " ".join(argv):
        await page.evaluate("t => rec.write(t, 'cmd')", word)
        await asyncio.sleep(0.035)
    await page.evaluate("t => rec.write(t)", "\n")


async def run_command(page, argv):
    """Runs a command in the scanner container, and shows its output."""
    proc = await asyncio.create_subprocess_exec(
        *COMPOSE, "exec", "-T", "scanner", *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
    )
    out = []
    while line := await proc.stdout.readline():
        text = line.decode(errors="replace")
        out.append(text)
        await page.evaluate("t => rec.write(t)", text)
    await proc.wait()
    (OUT / "nmap.txt").open("a").write("$ " + " ".join(argv) + "\n" + "".join(out) + "\n")
    return "".join(out)


async def main():
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "nmap.txt").write_text("")
    video_dir = OUT / "video"
    shutil.rmtree(video_dir, ignore_errors=True)
    async with async_playwright() as p:
        browser = await p.chromium.launch(executable_path=os.environ.get("CHROMIUM") or None)
        context = await browser.new_context(
            viewport={"width": W, "height": H},
            # The dashboard's CSP allows no inline styles; the panel above needs them.
            bypass_csp=True,
            record_video_dir=str(video_dir), record_video_size={"width": W, "height": H}
        )
        page = await context.new_page()
        page.on("pageerror", lambda e: print("page error:", e, file=sys.stderr))
        await page.goto(URL + "?theme=light")
        # A fresh layout: no places or open groups from an earlier visit.
        await page.evaluate("() => localStorage.clear()")
        await page.reload()
        await page.wait_for_selector("g.node.group")
        await page.evaluate(SETUP, PANEL)
        await asyncio.sleep(0.6)
        await page.click("#fit")
        ptr = Pointer(page)
        await page.evaluate("t => rec.caption(t)", "A simulated subnet: <b>four simulated hosts</b> and <b>one real container</b>, behind a router. The <b>scanner</b> is the agent.")
        await asyncio.sleep(3.5)

        # Host discovery.
        await page.evaluate("t => rec.caption(t)", "<b>Host discovery.</b> nmap pings the /24, and the scanner’s link lights up.")
        await type_command(page, DISCOVERY)
        await run_command(page, DISCOVERY)
        await asyncio.sleep(1.5)

        # The port scan runs while the viewer looks around.
        await page.evaluate("t => rec.caption(t)", "<b>SYN scan</b> of ports 1–1024 on every host that answered, then <b>service detection</b>.")
        await type_command(page, PORT_SCAN)
        scan = asyncio.create_task(run_command(page, PORT_SCAN))
        await asyncio.sleep(2.5)

        # Open one host's group, in place.
        x, y = await center(page, 'g.node.group:has-text("www")')
        await page.evaluate("t => rec.caption(t)", "<b>Groups.</b> Each host is a group. Double-click one to open it and see its tasks.")
        await ptr.click(x - 30, y, double=True)
        await asyncio.sleep(3.0)

        # The scanner's link: SYNs out, RSTs back.
        await page.evaluate("t => rec.caption(t)", "Click the <b>scanner\u2019s link</b> to watch its packets: <b>SYN</b>s out to every port, <b>RST</b>s back from the closed ones.")
        x, y = await edge_point(page, "b && b.kind === 'sandbox' && b.name === 'scanner'", 0.5)
        await ptr.click(x, y)
        await asyncio.sleep(0.8)
        fx, fy = await center(page, "#fit")
        await ptr.click(fx, fy)
        await asyncio.sleep(2.5)

        # Pause the list, and open an RST.
        await page.evaluate("t => rec.caption(t)", "<b>Pause</b> the list and select a packet to see its layers, as in Wireshark.")
        px, py = await center(page, "#pause")
        await ptr.click(px, py)
        await asyncio.sleep(0.6)
        rst = page.locator("#prows tr:not([hidden])", has_text="RST").last
        if await rst.count():
            await rst.scroll_into_view_if_needed()
            rb = await rst.bounding_box()
            await ptr.click(rb["x"] + 300, rb["y"] + rb["height"] / 2)
        await asyncio.sleep(3.0)
        await ptr.click(px, py)
        await asyncio.sleep(0.5)

        # Close a group: its links add up into one edge.
        await page.evaluate("t => rec.caption(t)", "<b>Closed groups add up</b> the links that cross their edge. Close \u201csimulated hosts\u201d, and its four links become one.")
        x, y = await center(page, 'g.frame .fhead:has-text("simulated hosts") .toggle')
        await ptr.click(x, y)
        await asyncio.sleep(2.2)
        await page.evaluate("t => rec.caption(t)", "The packet view of an added-up edge <b>merges the packets</b> of every link it stands for.")
        x, y = await edge_point(page, "d.members.length > 1", 0.5)
        await ptr.click(x, y)
        await asyncio.sleep(0.6)
        await ptr.click(fx, fy)
        await ptr.move(fx - 300, fy - 120, 500)
        await asyncio.sleep(3.0)

        # Drag a node, then a group.
        await page.evaluate("t => rec.caption(t)", "<b>Drag</b> any node or group. It stays where you drop it, and its edges follow.")
        x, y = await center(page, 'g.node:has-text("router")')
        await ptr.drag(x, y, 10, 60)
        await asyncio.sleep(0.8)
        x, y = await center(page, 'g.frame .fhead:has-text("real container")')
        await ptr.drag(x - 40, y, -10, -50)
        await ptr.move(x + 120, y + 260, 500)
        await asyncio.sleep(1.5)

        await scan
        await page.evaluate(
            "t => rec.caption(t)",
            "<b>All five hosts found.</b> 10.0.0.50 is the <b>real container</b>: nmap names its real nginx and OpenSSH.",
        )
        await asyncio.sleep(5.0)
        await context.close()
        await browser.close()
    videos = sorted(video_dir.glob("*.webm"))
    videos[-1].rename(OUT / "dashboard.webm")
    shutil.rmtree(video_dir, ignore_errors=True)


asyncio.run(main())
