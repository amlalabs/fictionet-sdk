// The CLI composes the shared map and packet views.
import { mount as mountMap } from './components/map.mjs';
import { mount as mountPackets } from './components/packets.mjs';
import { createTheme } from './theme.mjs';
import { createTransport } from './transport.mjs';
import { createSelection } from './selection.mjs';
import { listen } from './dom.mjs';

const root = document.querySelector('.app');
let packets;
const setStatus = (kind, text) => {
  root.querySelector('#status').dataset.state = kind;
  root.querySelector('#status-text').textContent = text;
};
const transport = createTransport({ setStatus, onLogout: () => packets?.close() });
const services = { transport, setStatus, selection: createSelection(),
  openPackets: (id) => packets.open(id), openLinks: (...args) => packets.openLinks(...args),
};
let map;
const stopMap = mountMap(root, services, { persist: true, onReady: (api) => { map = api; } });
const stopPackets = mountPackets(root.querySelector('#drawer'), services, { ...map, drawer: true, onReady: (api) => { packets = api; } });
const theme = createTheme(root.querySelector('#theme'));
const stopLogout = listen(root.querySelector('#logout'), 'click', () => { transport.logout(); location.reload(); });
const stopShow = listen(window, 'pageshow', (event) => { if (event.persisted) location.reload(); });
addEventListener('pagehide', () => {
  stopMap();
  stopPackets();
  stopLogout();
  stopShow();
  theme.dispose();
  transport.close();
}, { once: true });
