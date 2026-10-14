// DOM helpers shared by the dashboard and its packet drawer.
const $ = (id) => document.getElementById(id);
const SVGNS = 'http://www.w3.org/2000/svg';

const el = (tag, attrs = {}, parent) => {
  const e = tag.startsWith('svg:') ? document.createElementNS(SVGNS, tag.slice(4)) : document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'text') e.textContent = v;
    else if (k === 'class') e.setAttribute('class', v);
    else e.setAttribute(k, v);
  }
  if (parent) parent.appendChild(e);
  return e;
};

export { $, el };
