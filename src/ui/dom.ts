/**
 * Small DOM helpers.
 *
 * Nothing here decides anything about the cryptography; the exhibits compute
 * first and render second, so that a rendering bug cannot invent a verdict.
 */

export type Attrs = Record<string, string | number | boolean | undefined>;

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  children: Array<Node | string> = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === false) continue;
    if (k === 'class') node.className = String(v);
    else if (v === true) node.setAttribute(k, '');
    else node.setAttribute(k, String(v));
  }
  for (const c of children) node.append(typeof c === 'string' ? document.createTextNode(c) : c);
  return node;
}

export function text(s: string): Text {
  return document.createTextNode(s);
}

/** Replace an element's children. */
export function fill(target: Element, children: Array<Node | string>): void {
  target.replaceChildren(...children.map((c) => (typeof c === 'string' ? text(c) : c)));
}

/** The verdict states this lab paints. */
export type VerdictKind = 'held' | 'broken' | 'rejected' | 'warned' | 'stale';

/**
 * The icon for each verdict state.
 *
 * A real character in the markup, not a background image and not a colour:
 * WCAG 1.4.1 forbids conveying state by colour alone, and a grayscale or
 * deuteranopic render has to carry the same meaning.
 */
const VERDICT_ICON: Record<VerdictKind, string> = {
  held: '=',
  broken: '!',
  rejected: 'x',
  warned: '~',
  stale: '-',
};

/**
 * Render a verdict.
 *
 * `data-verdict` is the marker the claims suite and the mutation script key
 * off; `data-claim` names which claim this verdict is making, so a test can
 * find one verdict among several without matching on its copy.
 */
export function verdict(
  kind: VerdictKind,
  headline: string,
  detail?: string | Node,
  claim?: string,
): HTMLElement {
  const body = el('span', { class: 'verdict-body' }, [
    el('strong', { class: 'verdict-text' }, [headline]),
  ]);
  if (detail !== undefined) {
    body.append(el('span', { class: 'verdict-detail' }, [detail]));
  }
  return el(
    'div',
    {
      class: 'verdict',
      'data-verdict': kind,
      'data-claim': claim,
      role: 'status',
      'aria-live': 'polite',
    },
    [el('span', { class: 'verdict-icon', 'aria-hidden': 'true' }, [VERDICT_ICON[kind]]), body],
  );
}

/** The verdict shown when an input changed and the old answer no longer applies. */
export function staleVerdict(what: string): HTMLElement {
  return verdict(
    'stale',
    'RETIRED',
    `${what} changed, so the previous result no longer describes what is on screen. Run it again.`,
    'retired',
  );
}

/** A labelled field wrapping a control. */
export function field(
  id: string,
  label: string,
  control: HTMLElement,
  hint?: string,
): HTMLElement {
  const children: Array<Node | string> = [el('label', { for: id }, [label]), control];
  if (hint) children.push(el('span', { class: 'field-hint', id: `${id}-hint` }, [hint]));
  return el('div', { class: 'field' }, children);
}

/** A scrollable table region: reachable by keyboard and named, per WCAG. */
export function tableWrap(label: string, table: HTMLElement): HTMLElement {
  return el('div', { class: 'table-wrap', role: 'region', tabindex: '0', 'aria-label': label }, [
    table,
  ]);
}

export function card(children: Array<Node | string>): HTMLElement {
  return el('div', { class: 'card' }, children);
}

/** A statistic with its denominator kept beside it. */
export function stat(label: string, value: string, sub?: string): HTMLElement {
  const children: Array<Node | string> = [
    el('span', { class: 'stat-label' }, [label]),
    el('span', { class: 'stat-value' }, [value]),
  ];
  if (sub) children.push(el('span', { class: 'stat-sub' }, [sub]));
  return el('div', { class: 'stat' }, children);
}

/** A disclosure. Shut on arrival — the shut state is what every reader meets. */
export function disclosure(summary: string, children: Array<Node | string>): HTMLElement {
  return el('details', {}, [el('summary', {}, [summary]), ...children]);
}

export function note(children: Array<Node | string>): HTMLElement {
  return el('p', { class: 'note' }, children);
}

/** The "what this is not" note every non-goal gets, per §1. */
export function scopeNote(children: Array<Node | string>): HTMLElement {
  return el('p', { class: 'scope-note' }, children);
}
