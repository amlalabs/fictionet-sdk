import { mount as view } from '../assets/search/view.mjs';
export function mount(root, services, options) {
  return view(root, services, { ...options, forwardedHosts });
}
