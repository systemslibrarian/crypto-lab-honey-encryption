/**
 * Honey Encryption — entry point.
 *
 * Tabs, and nothing else. Each exhibit mounts itself into its own panel, and
 * every panel is built on arrival so that the default state on screen is the
 * state the tests scan rather than something a click produced.
 */

import './style.css';
import { mountOrdinary } from './ui/ex1-ordinary';
import { mountEncoder } from './ui/ex2-encoder';
import { mountHoney } from './ui/ex3-honey';
import { mountSearch } from './ui/ex4-search';
import { mountSmall } from './ui/ex5-small';
import { mountLimits } from './ui/ex6-limits';

const MOUNTS: Record<string, (root: HTMLElement) => void> = {
  ordinary: mountOrdinary,
  encoder: mountEncoder,
  honey: mountHoney,
  search: mountSearch,
  small: mountSmall,
  limits: mountLimits,
};

function panelFor(name: string): HTMLElement {
  const p = document.getElementById(`panel-${name}`);
  if (!p) throw new Error(`main: no panel for ${name}`);
  return p as HTMLElement;
}

function mountAll(): void {
  for (const [name, mount] of Object.entries(MOUNTS)) {
    mount(panelFor(name));
  }
}

function wireTabs(): void {
  const buttons = Array.from(document.querySelectorAll<HTMLButtonElement>('.tab-btn'));

  function select(name: string): void {
    for (const b of buttons) {
      const on = b.dataset.panel === name;
      b.setAttribute('aria-selected', String(on));
      b.tabIndex = on ? 0 : -1;
      // `hidden` is the only thing that hides a panel. No class sets display
      // on these, so the attribute and the rendering cannot disagree.
      panelFor(b.dataset.panel!).hidden = !on;
    }
  }

  for (const b of buttons) {
    b.addEventListener('click', () => select(b.dataset.panel!));
    // Arrow-key navigation within the tab list, per the ARIA tabs pattern.
    b.addEventListener('keydown', (ev) => {
      const i = buttons.indexOf(b);
      let next = -1;
      if (ev.key === 'ArrowRight') next = (i + 1) % buttons.length;
      else if (ev.key === 'ArrowLeft') next = (i - 1 + buttons.length) % buttons.length;
      else if (ev.key === 'Home') next = 0;
      else if (ev.key === 'End') next = buttons.length - 1;
      if (next === -1) return;
      ev.preventDefault();
      const target = buttons[next]!;
      select(target.dataset.panel!);
      target.focus();
    });
  }
}

mountAll();
wireTabs();
