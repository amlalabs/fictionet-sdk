use super::*;
use serde_json::json;

struct Pointer {
    x: f64,
    y: f64,
    down: bool,
}

impl Pointer {
    fn move_to(&mut self, browser: &mut Browser, x: f64, y: f64, ms: u64) -> Result {
        browser.eval(&format!("rec.pointer({x}, {y}, {ms})"))?;
        let steps = (ms / 25).max(1);
        for i in 1..=steps {
            let t = i as f64 / steps as f64;
            browser.call("Input.dispatchMouseEvent", json!({"type":"mouseMoved", "x":self.x+(x-self.x)*t, "y":self.y+(y-self.y)*t, "button": if self.down {"left"} else {"none"}, "buttons": u8::from(self.down)}))?;
            browser.wait(ms as f64 / 1000.0 / steps as f64)?;
        }
        self.x = x;
        self.y = y;
        Ok(())
    }

    fn button(&self, browser: &mut Browser, down: bool, count: u8) -> Result {
        browser.call("Input.dispatchMouseEvent", json!({"type":if down {"mousePressed"} else {"mouseReleased"}, "x":self.x,"y":self.y,"button":"left","buttons":u8::from(down),"clickCount":count}))?;
        Ok(())
    }

    fn click(&mut self, browser: &mut Browser, x: f64, y: f64, double: bool) -> Result {
        self.move_to(browser, x, y, 500)?;
        browser.eval(&format!("rec.ripple({x}, {y})"))?;
        for count in 1..=if double { 2 } else { 1 } {
            self.button(browser, true, count)?;
            browser.wait(0.04)?;
            self.button(browser, false, count)?;
        }
        Ok(())
    }

    fn drag(&mut self, browser: &mut Browser, x: f64, y: f64, dx: f64, dy: f64) -> Result {
        self.move_to(browser, x, y, 500)?;
        self.button(browser, true, 1)?;
        self.down = true;
        self.move_to(browser, x + dx, y + dy, 1100)?;
        self.button(browser, false, 1)?;
        self.down = false;
        Ok(())
    }
}

fn point(value: serde_json::Value) -> Result<(f64, f64)> {
    Ok((
        value[0].as_f64().ok_or("missing x coordinate")?,
        value[1].as_f64().ok_or("missing y coordinate")?,
    ))
}

fn center(browser: &mut Browser, element: &str) -> Result<(f64, f64)> {
    browser.until(&format!("Boolean({element})"))?;
    point(browser.eval(&format!("(() => {{ const b = ({element}).getBoundingClientRect(); return [b.x+b.width/2, b.y+b.height/2]; }})()"))?)
}

fn edge(browser: &mut Browser, element: &str) -> Result<(f64, f64)> {
    point(browser.eval(&format!(
        r#"(() => {{
      const edge = ({element});
      if (!edge) throw new Error('The dashboard has no matching edge: ' + {description});
      const wire = edge.querySelector('path.wire');
      const p = wire.getPointAtLength(wire.getTotalLength() * 0.5), m = wire.getScreenCTM();
      return [p.x*m.a+m.e, p.y*m.d+m.f];
    }})()"#,
        description = serde_json::to_string(element)?,
    ))?)
}

fn caption(browser: &mut Browser, text: &str) -> Result {
    browser.eval(&format!("rec.caption({})", serde_json::to_string(text)?))?;
    Ok(())
}

fn type_command(browser: &mut Browser, argv: &[&str]) -> Result {
    browser.eval("rec.write('root@scanner:~# ', 'prompt')")?;
    for character in argv.join(" ").chars() {
        browser.eval(&format!(
            "rec.write({}, 'cmd')",
            serde_json::to_string(&character.to_string())?
        ))?;
        browser.wait(0.035)?;
    }
    browser.eval("rec.write('\\n')")?;
    Ok(())
}

pub fn record(browser: &mut Browser, compose: &Compose) -> Result {
    browser.eval(&format!("({SETUP})(600)"))?;
    browser.start_video()?;
    browser.wait(0.6)?;
    browser.eval("document.querySelector('#fit').click()")?;
    let mut pointer = Pointer {
        x: 660.0,
        y: 540.0,
        down: false,
    };
    caption(
        browser,
        "A simulated subnet: <b>four simulated hosts</b> and <b>one real container</b>, behind a router. The <b>scanner</b> is the agent.",
    )?;
    browser.wait(3.5)?;
    caption(
        browser,
        "<b>Host discovery.</b> nmap pings the /24, and the scanner’s link lights up.",
    )?;
    type_command(browser, DISCOVERY)?;
    browser.scan(compose, DISCOVERY)?;
    browser.finish_scan()?;
    browser.wait(1.5)?;
    caption(
        browser,
        "<b>SYN scan</b> of ports 1–1024 on every host that answered, then <b>service detection</b>.",
    )?;
    type_command(browser, PORT_SCAN)?;
    browser.scan(compose, PORT_SCAN)?;
    browser.wait(2.5)?;
    let (x, y) = center(
        browser,
        "[...document.querySelectorAll('g.node.group')].find(e => e.textContent.includes('www'))",
    )?;
    caption(
        browser,
        "<b>Groups.</b> Each host is a group. Double-click one to open it and see its tasks.",
    )?;
    pointer.click(browser, x - 30.0, y, true)?;
    browser.wait(3.0)?;
    caption(
        browser,
        "Click the <b>scanner’s link</b> to watch its packets: <b>SYN</b>s out to every port, <b>RST</b>s back from the closed ones.",
    )?;
    let (x, y) = edge(
        browser,
        r#"[...document.querySelectorAll('g.edge')].find(e => e.dataset.b === document.querySelector('g.node.sandbox[aria-label="Sandbox scanner"]').dataset.id)"#,
    )?;
    pointer.click(browser, x, y, false)?;
    browser.wait(0.8)?;
    let (fx, fy) = center(browser, "document.querySelector('#fit')")?;
    pointer.click(browser, fx, fy, false)?;
    browser.wait(2.5)?;
    caption(
        browser,
        "<b>Pause</b> the list and select a packet to see its layers, as in Wireshark.",
    )?;
    let (px, py) = center(browser, "document.querySelector('#pause')")?;
    pointer.click(browser, px, py, false)?;
    browser.wait(0.6)?;
    let rst = "[...document.querySelectorAll('#prows tr:not([hidden])')].filter(e => e.textContent.includes('RST')).at(-1)";
    if browser.eval(&format!("Boolean({rst})"))? == true {
        browser.eval(&format!("({rst}).scrollIntoView({{block:'nearest'}})"))?;
        let (x,y) = point(browser.eval(&format!("(() => {{ const b=({rst}).getBoundingClientRect(); return [b.x+300, b.y+b.height/2]; }})()"))?)?;
        pointer.click(browser, x, y, false)?;
    }
    browser.wait(3.0)?;
    pointer.click(browser, px, py, false)?;
    browser.wait(0.5)?;
    caption(
        browser,
        "<b>Closed groups add up</b> the links that cross their edge. Close “simulated hosts”, and its four links become one.",
    )?;
    let (x, y) = center(
        browser,
        "[...document.querySelectorAll('g.frame .fhead')].find(e => e.textContent.includes('simulated hosts'))?.querySelector('.toggle')",
    )?;
    pointer.click(browser, x, y, false)?;
    browser.wait(2.2)?;
    caption(
        browser,
        "The packet view of an added-up edge <b>merges the packets</b> of every link it stands for.",
    )?;
    let (x, y) = edge(browser, "document.querySelector('g.edge.merged')")?;
    pointer.click(browser, x, y, false)?;
    browser.wait(0.6)?;
    pointer.click(browser, fx, fy, false)?;
    pointer.move_to(browser, fx - 300.0, fy - 120.0, 500)?;
    browser.wait(3.0)?;
    caption(
        browser,
        "<b>Drag</b> any node or group. It stays where you drop it, and its edges follow.",
    )?;
    let (x, y) = center(
        browser,
        "[...document.querySelectorAll('g.node')].find(e => e.textContent.includes('router'))",
    )?;
    pointer.drag(browser, x, y, 10.0, 60.0)?;
    browser.wait(0.8)?;
    let (x, y) = center(
        browser,
        "[...document.querySelectorAll('g.frame .fhead')].find(e => e.textContent.includes('real container'))",
    )?;
    pointer.drag(browser, x - 40.0, y, -10.0, -50.0)?;
    pointer.move_to(browser, x + 120.0, y + 260.0, 500)?;
    browser.wait(1.5)?;
    browser.finish_scan()?;
    caption(
        browser,
        "<b>All five hosts found.</b> 10.0.0.50 is the <b>real container</b>: nmap names its real nginx and OpenSSH.",
    )?;
    browser.wait(5.0)
}

const SETUP: &str = r###"
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
"###;
