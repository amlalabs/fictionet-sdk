import { scoped } from '../dom.mjs';

export const addressOf = (value) => value.startsWith('[') ? value.slice(1, value.indexOf(']')) : value.split(':').length === 2 ? value.replace(/:\d+$/, '') : value;
export const kindOf = (p) => p.tags.some((tag) => ['dns-error', 'malformed'].includes(tag)) ? 'bad'
  : p.proto.startsWith('TLS') && p.info === 'Encrypted Alert' ? 'tcp'
  : p.proto.startsWith('TLS') ? 'tls' : p.proto.startsWith('HTTP') ? 'http' : 'tcp';
const dataRow = (p) => p.proto.startsWith('HTTP') && /^DATA(?:\[|\b)/.test(p.info);
const flow = (p) => `${p.link}:${[p.src, p.dst].sort().join('|')}`;
// The decoder joins the frames of one packet with ", ", as in
// "Magic, SETTINGS, WINDOW_UPDATE[0] +12517377, HEADERS[1]: GET /".
const frames = (p) => p.info.split(/, (?=[A-Z][A-Z_]*\b)/);
const control = /^(?:Magic|PING(?: ack)?|SETTINGS(?: ack)?|WINDOW_UPDATE(?:\[\d+\])? \+\d+|PRIORITY(?:\[\d+\])?|GOAWAY NO_ERROR)$/;

export function conversationRows(rows) {
  const decoded = new Set(rows.filter((p) => /^(TLS|HTTP)/.test(p.proto)).map(flow));
  return rows.filter((p) => {
    if (p.tags.some((tag) => ['gap', 'malformed'].includes(tag))) return true;
    if (p.proto === 'HTTP/2' && frames(p).every((frame) => control.test(frame))) return false;
    if (p.proto !== 'TCP') return true;
    const flags = p.info.match(/\[([^\]]+)\]/)?.[1].split(/,\s*/) || [];
    if (flags.length === 1 && flags[0] === 'ACK' && /\bLen=[01]\b/.test(p.info)) return false;
    if (flags.some((flag) => ['SYN', 'FIN', 'RST'].includes(flag)) || p.tags.some((tag) => tag !== 'decrypted')) return true;
    // TCP keeps partial records until TLS or HTTP completes them. Only hide
    // payload on a decoded connection, including decrypted TCP without an
    // application message. Keep unknown protocols and tagged loss.
    return !(/\bLen=[1-9]\d*\b/.test(p.info) && (p.tags.includes('decrypted') || decoded.has(flow(p))) && flags.every((flag) => ['ACK', 'PSH'].includes(flag)));
  });
}

export function dnsRow(p) {
  if (p.proto !== 'DNS') return null;
  const question = p.info.match(/^Standard query(?: response)? \S+ \S+ (\S+)/);
  if (!question) return null;
  const name = question[1];
  const answers = [...p.info.slice(question[0].length).matchAll(/\b(A|AAAA) ([\da-f.:]+)(?=\s|$)/gi)].map((m) => ({ type: m[1], address: m[2] }));
  return { name: name.replace(/\.$/, ''), answers, back: p.info.startsWith('Standard query response') };
}

export function chipText(p) {
  const dns = dnsRow(p);
  if (dns) return p.tags.includes('dns-error') ? 'no such name' : dns.back ? dns.answers.map((a) => `${a.type} ${a.address}`).join(' · ') || 'DNS' : 'DNS';
  if (p.proto === 'TCP') return p.info.match(/\[([^\]]+)\]/)?.[1].split(/,\s*/).sort((a, b) => (a === 'ACK') - (b === 'ACK')).join('·') || 'TCP';
  if (p.proto.startsWith('TLS')) return p.info === 'Encrypted Alert' ? 'TLS close' : p.info.match(/Client Hello|Server Hello|Certificate|Finished/)?.[0] || p.info.slice(0, 22);
  if (dataRow(p)) return `DATA ${p.len > 999 ? `${(p.len / 1024).toFixed(1)}k` : p.len}`;
  // A packet that joins frames is named by its request or reply.
  const info = p.proto === 'HTTP/2' ? frames(p).find((frame) => frame.startsWith('HEADERS')) || frames(p).find((frame) => !control.test(frame)) || p.info : p.info;
  const status = info.match(/^(?:HTTP\/\S+ |HEADERS\[\d+\]: )?(\d{3})\b/);
  if (status) return status[1];
  const text = info.replace(/^HEADERS\[\d+\]: /, '').replace(/ \([^)]*\)$/, '').replace(/ HTTP\/\d(?:\.\d)?$/, '');
  return text.length > 22 ? `${text.slice(0, 21)}…` : text;
}

export function createLanes(root, { name, local, addressFor, animate }) {
  const { el } = scoped(root);
  const lanes = new Map();
  const closes = new Map();
  function trim(lane) {
    for (const item of lane.items) {
      const left = item.node.offsetLeft ?? item.node.getBoundingClientRect().left - lane.chips.getBoundingClientRect().left;
      item.node.style.visibility = left < 0 ? 'hidden' : '';
    }
  }
  const ResizeObserver = root.ownerDocument.defaultView?.ResizeObserver;
  const size = ResizeObserver ? new ResizeObserver(() => lanes.forEach(trim)) : null;
  const quiet = () => el('div', { class: 'packet-lanes-quiet', text: '—' }, root);
  quiet();
  function clear() { size?.disconnect(); root.replaceChildren(); lanes.clear(); closes.clear(); quiet(); }
  function add(p, motion = true) {
    const connection = flow(p);
    if (p.proto === 'TCP' && /\[(?:SYN|SYN, ACK)\]/.test(p.info)) closes.delete(connection);
    const closing = p.proto === 'TCP' && /\[[^\]]*\bFIN\b/.test(p.info) || p.proto.startsWith('TLS') && p.info === 'Encrypted Alert';
    if (closing) { closes.delete(connection); closes.set(connection, p.t); }
    while (closes.size > 256) closes.delete(closes.keys().next().value);
    const reset = p.proto === 'TCP' && /\[[^\]]*\bRST\b/.test(p.info);
    const quietReset = reset && closes.has(connection) && closes.get(connection) <= p.t;
    const dns = dnsRow(p);
    const back = dns ? dns.back : !local(p.src);
    const remote = back ? p.src : p.dst;
    if (!dns && !local(p.src) && !local(p.dst)) return;
    const address = dns ? dns.answers[0]?.address || addressFor(dns.name) : addressOf(remote);
    const host = dns ? address && name(address) !== address ? name(address) : dns.name : name(remote);
    const key = address || host;
    const previousKey = dns?.name || host;
    let lane = lanes.get(key) || lanes.get(previousKey);
    if (lane && key !== previousKey && lanes.has(previousKey)) { lanes.delete(previousKey); lanes.set(key, lane); }
    if (!lane) {
      root.querySelector('.packet-lanes-quiet')?.remove();
      const node = el('div', { class: 'packet-lane' }, root);
      const head = el('div', { class: 'packet-lane-head' }, node);
      const title = el('b', { text: host, title: host }, head);
      const label = el('span', { text: address || 'no address' }, head);
      lane = { node, title, address: label, last: -Infinity, items: [], chips: el('div', { class: 'packet-chips' }, node) };
      lanes.set(key, lane);
      size?.observe(lane.chips);
    } else if (dns?.answers.length) lane.address.textContent = dns.answers[0].address;
    lane.title.textContent = host;
    lane.title.setAttribute('title', host);
    lane.last = Math.max(lane.last, p.t);
    const ordered = [...lanes.values()].sort((a, b) => b.last - a.last);
    const before = lane.node.getBoundingClientRect().top;
    ordered.forEach((item, index) => {
      if (root.children[index] !== item.node) root.insertBefore(item.node, root.children[index] || null);
    });
    const distance = before - lane.node.getBoundingClientRect().top;
    if (motion && (distance || lane.items.length === 0)) animate(lane.node, `translateY(${distance || 8}px)`, 240);
    const texts = p.proto.startsWith('TLS') ? p.info.match(/Client Hello|Server Hello|Certificate(?=,|$)|Finished/g) || [chipText(p)] : [chipText(p)];
    const data = dataRow(p);
    const last = lane.items.at(-1);
    if (data && last?.data && last.back === back && p.t >= last.t) {
      last.bytes += p.len;
      last.count++;
      last.t = p.t;
      last.label.textContent = chipText({ ...p, len: last.bytes });
      last.counter ||= el('small', { class: 'packet-chip-count' }, last.node);
      last.counter.textContent = `×${last.count}`;
      if (motion) animate(last.node, 'scale(.96)', 160);
    } else for (const text of texts) {
      const chip = el('span', { class: `packet-chip ${kindOf(p)}${back ? ' back' : ''}${(p.quiet || quietReset) && kindOf(p) !== 'bad' ? ' quiet' : ''}`, title: p.info }, lane.chips);
      const label = data ? el('span', { text }, chip) : chip;
      if (!data) chip.textContent = text;
      lane.items.push({ node: chip, t: p.t, data, back, bytes: p.len, count: 1, label });
      if (motion) animate(chip, 'translateX(10px) scale(.9)', 220);
    }
    lane.items.sort((a, b) => a.t - b.t);
    while (lane.items.length > 11) lane.items.shift().node.remove();
    lane.items.forEach((item, index) => {
      if (lane.chips.children[index] !== item.node) lane.chips.insertBefore(item.node, lane.chips.children[index] || null);
    });
    trim(lane);
    while (lanes.size > 7) {
      const last = root.children[root.children.length - 1];
      for (const [key, value] of lanes) if (value.node === last) { size?.unobserve(value.chips); lanes.delete(key); }
      last.remove();
    }
  }
  return { add, clear, dispose() { size?.disconnect(); }, replace(rows) { clear(); rows.forEach((p) => add(p, false)); } };
}
