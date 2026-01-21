/**
 * @license
 * Copyright 2019 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const x = globalThis, D = x.ShadowRoot && (x.ShadyCSS === void 0 || x.ShadyCSS.nativeShadow) && "adoptedStyleSheets" in Document.prototype && "replace" in CSSStyleSheet.prototype, z = Symbol(), X = /* @__PURE__ */ new WeakMap();
let ht = class {
  constructor(t, e, s) {
    if (this._$cssResult$ = !0, s !== z) throw Error("CSSResult is not constructable. Use `unsafeCSS` or `css` instead.");
    this.cssText = t, this.t = e;
  }
  get styleSheet() {
    let t = this.o;
    const e = this.t;
    if (D && t === void 0) {
      const s = e !== void 0 && e.length === 1;
      s && (t = X.get(e)), t === void 0 && ((this.o = t = new CSSStyleSheet()).replaceSync(this.cssText), s && X.set(e, t));
    }
    return t;
  }
  toString() {
    return this.cssText;
  }
};
const _t = (i) => new ht(typeof i == "string" ? i : i + "", void 0, z), te = (i, ...t) => {
  const e = i.length === 1 ? i[0] : t.reduce(((s, r, n) => s + ((o) => {
    if (o._$cssResult$ === !0) return o.cssText;
    if (typeof o == "number") return o;
    throw Error("Value passed to 'css' function must be a 'css' function result: " + o + ". Use 'unsafeCSS' to pass non-literal values, but take care to ensure page security.");
  })(r) + i[n + 1]), i[0]);
  return new ht(e, i, z);
}, ft = (i, t) => {
  if (D) i.adoptedStyleSheets = t.map(((e) => e instanceof CSSStyleSheet ? e : e.styleSheet));
  else for (const e of t) {
    const s = document.createElement("style"), r = x.litNonce;
    r !== void 0 && s.setAttribute("nonce", r), s.textContent = e.cssText, i.appendChild(s);
  }
}, Y = D ? (i) => i : (i) => i instanceof CSSStyleSheet ? ((t) => {
  let e = "";
  for (const s of t.cssRules) e += s.cssText;
  return _t(e);
})(i) : i;
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const { is: At, defineProperty: gt, getOwnPropertyDescriptor: mt, getOwnPropertyNames: yt, getOwnPropertySymbols: vt, getPrototypeOf: bt } = Object, R = globalThis, F = R.trustedTypes, St = F ? F.emptyScript : "", Et = R.reactiveElementPolyfillSupport, S = (i, t) => i, O = { toAttribute(i, t) {
  switch (t) {
    case Boolean:
      i = i ? St : null;
      break;
    case Object:
    case Array:
      i = i == null ? i : JSON.stringify(i);
  }
  return i;
}, fromAttribute(i, t) {
  let e = i;
  switch (t) {
    case Boolean:
      e = i !== null;
      break;
    case Number:
      e = i === null ? null : Number(i);
      break;
    case Object:
    case Array:
      try {
        e = JSON.parse(i);
      } catch {
        e = null;
      }
  }
  return e;
} }, B = (i, t) => !At(i, t), J = { attribute: !0, type: String, converter: O, reflect: !1, hasChanged: B };
Symbol.metadata ??= Symbol("metadata"), R.litPropertyMetadata ??= /* @__PURE__ */ new WeakMap();
class y extends HTMLElement {
  static addInitializer(t) {
    this._$Ei(), (this.l ??= []).push(t);
  }
  static get observedAttributes() {
    return this.finalize(), this._$Eh && [...this._$Eh.keys()];
  }
  static createProperty(t, e = J) {
    if (e.state && (e.attribute = !1), this._$Ei(), this.elementProperties.set(t, e), !e.noAccessor) {
      const s = Symbol(), r = this.getPropertyDescriptor(t, s, e);
      r !== void 0 && gt(this.prototype, t, r);
    }
  }
  static getPropertyDescriptor(t, e, s) {
    const { get: r, set: n } = mt(this.prototype, t) ?? { get() {
      return this[e];
    }, set(o) {
      this[e] = o;
    } };
    return { get() {
      return r?.call(this);
    }, set(o) {
      const a = r?.call(this);
      n.call(this, o), this.requestUpdate(t, a, s);
    }, configurable: !0, enumerable: !0 };
  }
  static getPropertyOptions(t) {
    return this.elementProperties.get(t) ?? J;
  }
  static _$Ei() {
    if (this.hasOwnProperty(S("elementProperties"))) return;
    const t = bt(this);
    t.finalize(), t.l !== void 0 && (this.l = [...t.l]), this.elementProperties = new Map(t.elementProperties);
  }
  static finalize() {
    if (this.hasOwnProperty(S("finalized"))) return;
    if (this.finalized = !0, this._$Ei(), this.hasOwnProperty(S("properties"))) {
      const e = this.properties, s = [...yt(e), ...vt(e)];
      for (const r of s) this.createProperty(r, e[r]);
    }
    const t = this[Symbol.metadata];
    if (t !== null) {
      const e = litPropertyMetadata.get(t);
      if (e !== void 0) for (const [s, r] of e) this.elementProperties.set(s, r);
    }
    this._$Eh = /* @__PURE__ */ new Map();
    for (const [e, s] of this.elementProperties) {
      const r = this._$Eu(e, s);
      r !== void 0 && this._$Eh.set(r, e);
    }
    this.elementStyles = this.finalizeStyles(this.styles);
  }
  static finalizeStyles(t) {
    const e = [];
    if (Array.isArray(t)) {
      const s = new Set(t.flat(1 / 0).reverse());
      for (const r of s) e.unshift(Y(r));
    } else t !== void 0 && e.push(Y(t));
    return e;
  }
  static _$Eu(t, e) {
    const s = e.attribute;
    return s === !1 ? void 0 : typeof s == "string" ? s : typeof t == "string" ? t.toLowerCase() : void 0;
  }
  constructor() {
    super(), this._$Ep = void 0, this.isUpdatePending = !1, this.hasUpdated = !1, this._$Em = null, this._$Ev();
  }
  _$Ev() {
    this._$ES = new Promise(((t) => this.enableUpdating = t)), this._$AL = /* @__PURE__ */ new Map(), this._$E_(), this.requestUpdate(), this.constructor.l?.forEach(((t) => t(this)));
  }
  addController(t) {
    (this._$EO ??= /* @__PURE__ */ new Set()).add(t), this.renderRoot !== void 0 && this.isConnected && t.hostConnected?.();
  }
  removeController(t) {
    this._$EO?.delete(t);
  }
  _$E_() {
    const t = /* @__PURE__ */ new Map(), e = this.constructor.elementProperties;
    for (const s of e.keys()) this.hasOwnProperty(s) && (t.set(s, this[s]), delete this[s]);
    t.size > 0 && (this._$Ep = t);
  }
  createRenderRoot() {
    const t = this.shadowRoot ?? this.attachShadow(this.constructor.shadowRootOptions);
    return ft(t, this.constructor.elementStyles), t;
  }
  connectedCallback() {
    this.renderRoot ??= this.createRenderRoot(), this.enableUpdating(!0), this._$EO?.forEach(((t) => t.hostConnected?.()));
  }
  enableUpdating(t) {
  }
  disconnectedCallback() {
    this._$EO?.forEach(((t) => t.hostDisconnected?.()));
  }
  attributeChangedCallback(t, e, s) {
    this._$AK(t, s);
  }
  _$EC(t, e) {
    const s = this.constructor.elementProperties.get(t), r = this.constructor._$Eu(t, s);
    if (r !== void 0 && s.reflect === !0) {
      const n = (s.converter?.toAttribute !== void 0 ? s.converter : O).toAttribute(e, s.type);
      this._$Em = t, n == null ? this.removeAttribute(r) : this.setAttribute(r, n), this._$Em = null;
    }
  }
  _$AK(t, e) {
    const s = this.constructor, r = s._$Eh.get(t);
    if (r !== void 0 && this._$Em !== r) {
      const n = s.getPropertyOptions(r), o = typeof n.converter == "function" ? { fromAttribute: n.converter } : n.converter?.fromAttribute !== void 0 ? n.converter : O;
      this._$Em = r, this[r] = o.fromAttribute(e, n.type), this._$Em = null;
    }
  }
  requestUpdate(t, e, s) {
    if (t !== void 0) {
      if (s ??= this.constructor.getPropertyOptions(t), !(s.hasChanged ?? B)(this[t], e)) return;
      this.P(t, e, s);
    }
    this.isUpdatePending === !1 && (this._$ES = this._$ET());
  }
  P(t, e, s) {
    this._$AL.has(t) || this._$AL.set(t, e), s.reflect === !0 && this._$Em !== t && (this._$Ej ??= /* @__PURE__ */ new Set()).add(t);
  }
  async _$ET() {
    this.isUpdatePending = !0;
    try {
      await this._$ES;
    } catch (e) {
      Promise.reject(e);
    }
    const t = this.scheduleUpdate();
    return t != null && await t, !this.isUpdatePending;
  }
  scheduleUpdate() {
    return this.performUpdate();
  }
  performUpdate() {
    if (!this.isUpdatePending) return;
    if (!this.hasUpdated) {
      if (this.renderRoot ??= this.createRenderRoot(), this._$Ep) {
        for (const [r, n] of this._$Ep) this[r] = n;
        this._$Ep = void 0;
      }
      const s = this.constructor.elementProperties;
      if (s.size > 0) for (const [r, n] of s) n.wrapped !== !0 || this._$AL.has(r) || this[r] === void 0 || this.P(r, this[r], n);
    }
    let t = !1;
    const e = this._$AL;
    try {
      t = this.shouldUpdate(e), t ? (this.willUpdate(e), this._$EO?.forEach(((s) => s.hostUpdate?.())), this.update(e)) : this._$EU();
    } catch (s) {
      throw t = !1, this._$EU(), s;
    }
    t && this._$AE(e);
  }
  willUpdate(t) {
  }
  _$AE(t) {
    this._$EO?.forEach(((e) => e.hostUpdated?.())), this.hasUpdated || (this.hasUpdated = !0, this.firstUpdated(t)), this.updated(t);
  }
  _$EU() {
    this._$AL = /* @__PURE__ */ new Map(), this.isUpdatePending = !1;
  }
  get updateComplete() {
    return this.getUpdateComplete();
  }
  getUpdateComplete() {
    return this._$ES;
  }
  shouldUpdate(t) {
    return !0;
  }
  update(t) {
    this._$Ej &&= this._$Ej.forEach(((e) => this._$EC(e, this[e]))), this._$EU();
  }
  updated(t) {
  }
  firstUpdated(t) {
  }
}
y.elementStyles = [], y.shadowRootOptions = { mode: "open" }, y[S("elementProperties")] = /* @__PURE__ */ new Map(), y[S("finalized")] = /* @__PURE__ */ new Map(), Et?.({ ReactiveElement: y }), (R.reactiveElementVersions ??= []).push("2.0.4");
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const V = globalThis, H = V.trustedTypes, G = H ? H.createPolicy("lit-html", { createHTML: (i) => i }) : void 0, at = "$lit$", f = `lit$${Math.random().toFixed(9).slice(2)}$`, ct = "?" + f, Ct = `<${ct}>`, m = document, C = () => m.createComment(""), w = (i) => i === null || typeof i != "object" && typeof i != "function", q = Array.isArray, wt = (i) => q(i) || typeof i?.[Symbol.iterator] == "function", j = `[ 	
\f\r]`, b = /<(?:(!--|\/[^a-zA-Z])|(\/?[a-zA-Z][^>\s]*)|(\/?$))/g, Q = /-->/g, tt = />/g, A = RegExp(`>|${j}(?:([^\\s"'>=/]+)(${j}*=${j}*(?:[^ 	
\f\r"'\`<>=]|("|')|))|$)`, "g"), et = /'/g, st = /"/g, lt = /^(?:script|style|textarea|title)$/i, Pt = (i) => (t, ...e) => ({ _$litType$: i, strings: t, values: e }), Ut = Pt(1), $ = Symbol.for("lit-noChange"), u = Symbol.for("lit-nothing"), it = /* @__PURE__ */ new WeakMap(), g = m.createTreeWalker(m, 129);
function dt(i, t) {
  if (!q(i) || !i.hasOwnProperty("raw")) throw Error("invalid template strings array");
  return G !== void 0 ? G.createHTML(t) : t;
}
const Tt = (i, t) => {
  const e = i.length - 1, s = [];
  let r, n = t === 2 ? "<svg>" : t === 3 ? "<math>" : "", o = b;
  for (let a = 0; a < e; a++) {
    const h = i[a];
    let l, d, c = -1, p = 0;
    for (; p < h.length && (o.lastIndex = p, d = o.exec(h), d !== null); ) p = o.lastIndex, o === b ? d[1] === "!--" ? o = Q : d[1] !== void 0 ? o = tt : d[2] !== void 0 ? (lt.test(d[2]) && (r = RegExp("</" + d[2], "g")), o = A) : d[3] !== void 0 && (o = A) : o === A ? d[0] === ">" ? (o = r ?? b, c = -1) : d[1] === void 0 ? c = -2 : (c = o.lastIndex - d[2].length, l = d[1], o = d[3] === void 0 ? A : d[3] === '"' ? st : et) : o === st || o === et ? o = A : o === Q || o === tt ? o = b : (o = A, r = void 0);
    const _ = o === A && i[a + 1].startsWith("/>") ? " " : "";
    n += o === b ? h + Ct : c >= 0 ? (s.push(l), h.slice(0, c) + at + h.slice(c) + f + _) : h + f + (c === -2 ? a : _);
  }
  return [dt(i, n + (i[e] || "<?>") + (t === 2 ? "</svg>" : t === 3 ? "</math>" : "")), s];
};
class P {
  constructor({ strings: t, _$litType$: e }, s) {
    let r;
    this.parts = [];
    let n = 0, o = 0;
    const a = t.length - 1, h = this.parts, [l, d] = Tt(t, e);
    if (this.el = P.createElement(l, s), g.currentNode = this.el.content, e === 2 || e === 3) {
      const c = this.el.content.firstChild;
      c.replaceWith(...c.childNodes);
    }
    for (; (r = g.nextNode()) !== null && h.length < a; ) {
      if (r.nodeType === 1) {
        if (r.hasAttributes()) for (const c of r.getAttributeNames()) if (c.endsWith(at)) {
          const p = d[o++], _ = r.getAttribute(c).split(f), T = /([.?@])?(.*)/.exec(p);
          h.push({ type: 1, index: n, name: T[2], strings: _, ctor: T[1] === "." ? Nt : T[1] === "?" ? Ot : T[1] === "@" ? Ht : k }), r.removeAttribute(c);
        } else c.startsWith(f) && (h.push({ type: 6, index: n }), r.removeAttribute(c));
        if (lt.test(r.tagName)) {
          const c = r.textContent.split(f), p = c.length - 1;
          if (p > 0) {
            r.textContent = H ? H.emptyScript : "";
            for (let _ = 0; _ < p; _++) r.append(c[_], C()), g.nextNode(), h.push({ type: 2, index: ++n });
            r.append(c[p], C());
          }
        }
      } else if (r.nodeType === 8) if (r.data === ct) h.push({ type: 2, index: n });
      else {
        let c = -1;
        for (; (c = r.data.indexOf(f, c + 1)) !== -1; ) h.push({ type: 7, index: n }), c += f.length - 1;
      }
      n++;
    }
  }
  static createElement(t, e) {
    const s = m.createElement("template");
    return s.innerHTML = t, s;
  }
}
function v(i, t, e = i, s) {
  if (t === $) return t;
  let r = s !== void 0 ? e._$Co?.[s] : e._$Cl;
  const n = w(t) ? void 0 : t._$litDirective$;
  return r?.constructor !== n && (r?._$AO?.(!1), n === void 0 ? r = void 0 : (r = new n(i), r._$AT(i, e, s)), s !== void 0 ? (e._$Co ??= [])[s] = r : e._$Cl = r), r !== void 0 && (t = v(i, r._$AS(i, t.values), r, s)), t;
}
class xt {
  constructor(t, e) {
    this._$AV = [], this._$AN = void 0, this._$AD = t, this._$AM = e;
  }
  get parentNode() {
    return this._$AM.parentNode;
  }
  get _$AU() {
    return this._$AM._$AU;
  }
  u(t) {
    const { el: { content: e }, parts: s } = this._$AD, r = (t?.creationScope ?? m).importNode(e, !0);
    g.currentNode = r;
    let n = g.nextNode(), o = 0, a = 0, h = s[0];
    for (; h !== void 0; ) {
      if (o === h.index) {
        let l;
        h.type === 2 ? l = new U(n, n.nextSibling, this, t) : h.type === 1 ? l = new h.ctor(n, h.name, h.strings, this, t) : h.type === 6 && (l = new Mt(n, this, t)), this._$AV.push(l), h = s[++a];
      }
      o !== h?.index && (n = g.nextNode(), o++);
    }
    return g.currentNode = m, r;
  }
  p(t) {
    let e = 0;
    for (const s of this._$AV) s !== void 0 && (s.strings !== void 0 ? (s._$AI(t, s, e), e += s.strings.length - 2) : s._$AI(t[e])), e++;
  }
}
class U {
  get _$AU() {
    return this._$AM?._$AU ?? this._$Cv;
  }
  constructor(t, e, s, r) {
    this.type = 2, this._$AH = u, this._$AN = void 0, this._$AA = t, this._$AB = e, this._$AM = s, this.options = r, this._$Cv = r?.isConnected ?? !0;
  }
  get parentNode() {
    let t = this._$AA.parentNode;
    const e = this._$AM;
    return e !== void 0 && t?.nodeType === 11 && (t = e.parentNode), t;
  }
  get startNode() {
    return this._$AA;
  }
  get endNode() {
    return this._$AB;
  }
  _$AI(t, e = this) {
    t = v(this, t, e), w(t) ? t === u || t == null || t === "" ? (this._$AH !== u && this._$AR(), this._$AH = u) : t !== this._$AH && t !== $ && this._(t) : t._$litType$ !== void 0 ? this.$(t) : t.nodeType !== void 0 ? this.T(t) : wt(t) ? this.k(t) : this._(t);
  }
  O(t) {
    return this._$AA.parentNode.insertBefore(t, this._$AB);
  }
  T(t) {
    this._$AH !== t && (this._$AR(), this._$AH = this.O(t));
  }
  _(t) {
    this._$AH !== u && w(this._$AH) ? this._$AA.nextSibling.data = t : this.T(m.createTextNode(t)), this._$AH = t;
  }
  $(t) {
    const { values: e, _$litType$: s } = t, r = typeof s == "number" ? this._$AC(t) : (s.el === void 0 && (s.el = P.createElement(dt(s.h, s.h[0]), this.options)), s);
    if (this._$AH?._$AD === r) this._$AH.p(e);
    else {
      const n = new xt(r, this), o = n.u(this.options);
      n.p(e), this.T(o), this._$AH = n;
    }
  }
  _$AC(t) {
    let e = it.get(t.strings);
    return e === void 0 && it.set(t.strings, e = new P(t)), e;
  }
  k(t) {
    q(this._$AH) || (this._$AH = [], this._$AR());
    const e = this._$AH;
    let s, r = 0;
    for (const n of t) r === e.length ? e.push(s = new U(this.O(C()), this.O(C()), this, this.options)) : s = e[r], s._$AI(n), r++;
    r < e.length && (this._$AR(s && s._$AB.nextSibling, r), e.length = r);
  }
  _$AR(t = this._$AA.nextSibling, e) {
    for (this._$AP?.(!1, !0, e); t && t !== this._$AB; ) {
      const s = t.nextSibling;
      t.remove(), t = s;
    }
  }
  setConnected(t) {
    this._$AM === void 0 && (this._$Cv = t, this._$AP?.(t));
  }
}
class k {
  get tagName() {
    return this.element.tagName;
  }
  get _$AU() {
    return this._$AM._$AU;
  }
  constructor(t, e, s, r, n) {
    this.type = 1, this._$AH = u, this._$AN = void 0, this.element = t, this.name = e, this._$AM = r, this.options = n, s.length > 2 || s[0] !== "" || s[1] !== "" ? (this._$AH = Array(s.length - 1).fill(new String()), this.strings = s) : this._$AH = u;
  }
  _$AI(t, e = this, s, r) {
    const n = this.strings;
    let o = !1;
    if (n === void 0) t = v(this, t, e, 0), o = !w(t) || t !== this._$AH && t !== $, o && (this._$AH = t);
    else {
      const a = t;
      let h, l;
      for (t = n[0], h = 0; h < n.length - 1; h++) l = v(this, a[s + h], e, h), l === $ && (l = this._$AH[h]), o ||= !w(l) || l !== this._$AH[h], l === u ? t = u : t !== u && (t += (l ?? "") + n[h + 1]), this._$AH[h] = l;
    }
    o && !r && this.j(t);
  }
  j(t) {
    t === u ? this.element.removeAttribute(this.name) : this.element.setAttribute(this.name, t ?? "");
  }
}
class Nt extends k {
  constructor() {
    super(...arguments), this.type = 3;
  }
  j(t) {
    this.element[this.name] = t === u ? void 0 : t;
  }
}
class Ot extends k {
  constructor() {
    super(...arguments), this.type = 4;
  }
  j(t) {
    this.element.toggleAttribute(this.name, !!t && t !== u);
  }
}
class Ht extends k {
  constructor(t, e, s, r, n) {
    super(t, e, s, r, n), this.type = 5;
  }
  _$AI(t, e = this) {
    if ((t = v(this, t, e, 0) ?? u) === $) return;
    const s = this._$AH, r = t === u && s !== u || t.capture !== s.capture || t.once !== s.once || t.passive !== s.passive, n = t !== u && (s === u || r);
    r && this.element.removeEventListener(this.name, this, s), n && this.element.addEventListener(this.name, this, t), this._$AH = t;
  }
  handleEvent(t) {
    typeof this._$AH == "function" ? this._$AH.call(this.options?.host ?? this.element, t) : this._$AH.handleEvent(t);
  }
}
class Mt {
  constructor(t, e, s) {
    this.element = t, this.type = 6, this._$AN = void 0, this._$AM = e, this.options = s;
  }
  get _$AU() {
    return this._$AM._$AU;
  }
  _$AI(t) {
    v(this, t);
  }
}
const Rt = V.litHtmlPolyfillSupport;
Rt?.(P, U), (V.litHtmlVersions ??= []).push("3.2.1");
const kt = (i, t, e) => {
  const s = e?.renderBefore ?? t;
  let r = s._$litPart$;
  if (r === void 0) {
    const n = e?.renderBefore ?? null;
    s._$litPart$ = r = new U(t.insertBefore(C(), n), n, void 0, e ?? {});
  }
  return r._$AI(i), r;
};
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
let N = class extends y {
  constructor() {
    super(...arguments), this.renderOptions = { host: this }, this._$Do = void 0;
  }
  createRenderRoot() {
    const t = super.createRenderRoot();
    return this.renderOptions.renderBefore ??= t.firstChild, t;
  }
  update(t) {
    const e = this.render();
    this.hasUpdated || (this.renderOptions.isConnected = this.isConnected), super.update(t), this._$Do = kt(e, this.renderRoot, this.renderOptions);
  }
  connectedCallback() {
    super.connectedCallback(), this._$Do?.setConnected(!0);
  }
  disconnectedCallback() {
    super.disconnectedCallback(), this._$Do?.setConnected(!1);
  }
  render() {
    return $;
  }
};
N._$litElement$ = !0, N.finalized = !0, globalThis.litElementHydrateSupport?.({ LitElement: N });
const jt = globalThis.litElementPolyfillSupport;
jt?.({ LitElement: N });
(globalThis.litElementVersions ??= []).push("4.1.1");
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const se = (i) => (t, e) => {
  e !== void 0 ? e.addInitializer((() => {
    customElements.define(i, t);
  })) : customElements.define(i, t);
};
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const It = { attribute: !0, type: String, converter: O, reflect: !1, hasChanged: B }, Lt = (i = It, t, e) => {
  const { kind: s, metadata: r } = e;
  let n = globalThis.litPropertyMetadata.get(r);
  if (n === void 0 && globalThis.litPropertyMetadata.set(r, n = /* @__PURE__ */ new Map()), n.set(e.name, i), s === "accessor") {
    const { name: o } = e;
    return { set(a) {
      const h = t.get.call(this);
      t.set.call(this, a), this.requestUpdate(o, h, i);
    }, init(a) {
      return a !== void 0 && this.P(o, void 0, i), a;
    } };
  }
  if (s === "setter") {
    const { name: o } = e;
    return function(a) {
      const h = this[o];
      t.call(this, a), this.requestUpdate(o, h, i);
    };
  }
  throw Error("Unsupported decorator location: " + s);
};
function Dt(i) {
  return (t, e) => typeof e == "object" ? Lt(i, t, e) : ((s, r, n) => {
    const o = r.hasOwnProperty(n);
    return r.constructor.createProperty(n, o ? { ...s, wrapped: !0 } : s), o ? Object.getOwnPropertyDescriptor(r, n) : void 0;
  })(i, t, e);
}
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
function ie(i) {
  return Dt({ ...i, state: !0, attribute: !1 });
}
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const ut = (i, t, e) => (e.configurable = !0, e.enumerable = !0, Reflect.decorate && typeof t != "object" && Object.defineProperty(i, t, e), e);
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
function re(i, t) {
  return (e, s, r) => {
    const n = (o) => o.renderRoot?.querySelector(i) ?? null;
    return ut(e, s, { get() {
      return n(this);
    } });
  };
}
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
let zt;
function ne(i) {
  return (t, e) => ut(t, e, { get() {
    return (this.renderRoot ?? (zt ??= document.createDocumentFragment())).querySelectorAll(i);
  } });
}
/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const Bt = (i) => i === null || typeof i != "object" && typeof i != "function", Vt = (i) => i.strings === void 0;
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const W = { ATTRIBUTE: 1, CHILD: 2 }, K = (i) => (...t) => ({ _$litDirective$: i, values: t });
let Z = class {
  constructor(t) {
  }
  get _$AU() {
    return this._$AM._$AU;
  }
  _$AT(t, e, s) {
    this._$Ct = t, this._$AM = e, this._$Ci = s;
  }
  _$AS(t, e) {
    return this.update(t, e);
  }
  update(t, e) {
    return this.render(...e);
  }
};
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const E = (i, t) => {
  const e = i._$AN;
  if (e === void 0) return !1;
  for (const s of e) s._$AO?.(t, !1), E(s, t);
  return !0;
}, M = (i) => {
  let t, e;
  do {
    if ((t = i._$AM) === void 0) break;
    e = t._$AN, e.delete(i), i = t;
  } while (e?.size === 0);
}, $t = (i) => {
  for (let t; t = i._$AM; i = t) {
    let e = t._$AN;
    if (e === void 0) t._$AN = e = /* @__PURE__ */ new Set();
    else if (e.has(i)) break;
    e.add(i), Kt(t);
  }
};
function qt(i) {
  this._$AN !== void 0 ? (M(this), this._$AM = i, $t(this)) : this._$AM = i;
}
function Wt(i, t = !1, e = 0) {
  const s = this._$AH, r = this._$AN;
  if (r !== void 0 && r.size !== 0) if (t) if (Array.isArray(s)) for (let n = e; n < s.length; n++) E(s[n], !1), M(s[n]);
  else s != null && (E(s, !1), M(s));
  else E(this, i);
}
const Kt = (i) => {
  i.type == W.CHILD && (i._$AP ??= Wt, i._$AQ ??= qt);
};
class Zt extends Z {
  constructor() {
    super(...arguments), this._$AN = void 0;
  }
  _$AT(t, e, s) {
    super._$AT(t, e, s), $t(this), this.isConnected = t._$AU;
  }
  _$AO(t, e = !0) {
    t !== this.isConnected && (this.isConnected = t, t ? this.reconnected?.() : this.disconnected?.()), e && (E(this, t), M(this));
  }
  setValue(t) {
    if (Vt(this._$Ct)) this._$Ct._$AI(t, this);
    else {
      const e = [...this._$Ct._$AH];
      e[this._$Ci] = t, this._$Ct._$AI(e, this, 0);
    }
  }
  disconnected() {
  }
  reconnected() {
  }
}
/**
 * @license
 * Copyright 2021 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
class Xt {
  constructor(t) {
    this.Y = t;
  }
  disconnect() {
    this.Y = void 0;
  }
  reconnect(t) {
    this.Y = t;
  }
  deref() {
    return this.Y;
  }
}
let Yt = class {
  constructor() {
    this.Z = void 0, this.q = void 0;
  }
  get() {
    return this.Z;
  }
  pause() {
    this.Z ??= new Promise(((t) => this.q = t));
  }
  resume() {
    this.q?.(), this.Z = this.q = void 0;
  }
};
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const rt = (i) => !Bt(i) && typeof i.then == "function", nt = 1073741823;
class Ft extends Zt {
  constructor() {
    super(...arguments), this._$Cwt = nt, this._$Cbt = [], this._$CK = new Xt(this), this._$CX = new Yt();
  }
  render(...t) {
    return t.find(((e) => !rt(e))) ?? $;
  }
  update(t, e) {
    const s = this._$Cbt;
    let r = s.length;
    this._$Cbt = e;
    const n = this._$CK, o = this._$CX;
    this.isConnected || this.disconnected();
    for (let a = 0; a < e.length && !(a > this._$Cwt); a++) {
      const h = e[a];
      if (!rt(h)) return this._$Cwt = a, h;
      a < r && h === s[a] || (this._$Cwt = nt, r = 0, Promise.resolve(h).then((async (l) => {
        for (; o.get(); ) await o.get();
        const d = n.deref();
        if (d !== void 0) {
          const c = d._$Cbt.indexOf(h);
          c > -1 && c < d._$Cwt && (d._$Cwt = c, d.setValue(l));
        }
      })));
    }
    return $;
  }
  disconnected() {
    this._$CK.disconnect(), this._$CX.pause();
  }
  reconnected() {
    this._$CK.reconnect(this), this._$CX.resume();
  }
}
const ae = K(Ft);
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
let I = class extends Z {
  constructor(t) {
    if (super(t), this.it = u, t.type !== W.CHILD) throw Error(this.constructor.directiveName + "() can only be used in child bindings");
  }
  render(t) {
    if (t === u || t == null) return this._t = void 0, this.it = t;
    if (t === $) return t;
    if (typeof t != "string") throw Error(this.constructor.directiveName + "() called with a non-string value");
    if (t === this.it) return this._t;
    this.it = t;
    const e = [t];
    return e.raw = e, this._t = { _$litType$: this.constructor.resultType, strings: e, values: [] };
  }
};
I.directiveName = "unsafeHTML", I.resultType = 1;
/**
 * @license
 * Copyright 2017 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
class L extends I {
}
L.directiveName = "unsafeSVG", L.resultType = 2;
const le = K(L);
/**
 * @license
 * Copyright 2021 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
function de(i, t, e) {
  return i ? t(i) : e?.(i);
}
/**
 * @license
 * Copyright 2018 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const ue = K(class extends Z {
  constructor(i) {
    if (super(i), i.type !== W.ATTRIBUTE || i.name !== "class" || i.strings?.length > 2) throw Error("`classMap()` can only be used in the `class` attribute and must be the only part in the attribute.");
  }
  render(i) {
    return " " + Object.keys(i).filter(((t) => i[t])).join(" ") + " ";
  }
  update(i, [t]) {
    if (this.st === void 0) {
      this.st = /* @__PURE__ */ new Set(), i.strings !== void 0 && (this.nt = new Set(i.strings.join(" ").split(/\s/).filter(((s) => s !== ""))));
      for (const s in t) t[s] && !this.nt?.has(s) && this.st.add(s);
      return this.render(t);
    }
    const e = i.element.classList;
    for (const s of this.st) s in t || (e.remove(s), this.st.delete(s));
    for (const s in t) {
      const r = !!t[s];
      r === this.st.has(s) || this.nt?.has(s) || (r ? (e.add(s), this.st.add(s)) : (e.remove(s), this.st.delete(s)));
    }
    return $;
  }
});
/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const pt = Symbol.for(""), Jt = (i) => {
  if (i?.r === pt) return i?._$litStatic$;
}, $e = (i, ...t) => ({ _$litStatic$: t.reduce(((e, s, r) => e + ((n) => {
  if (n._$litStatic$ !== void 0) return n._$litStatic$;
  throw Error(`Value passed to 'literal' function must be a 'literal' result: ${n}. Use 'unsafeStatic' to pass non-literal values, but
            take care to ensure page security.`);
})(s) + i[r + 1]), i[0]), r: pt }), ot = /* @__PURE__ */ new Map(), Gt = (i) => (t, ...e) => {
  const s = e.length;
  let r, n;
  const o = [], a = [];
  let h, l = 0, d = !1;
  for (; l < s; ) {
    for (h = t[l]; l < s && (n = e[l], (r = Jt(n)) !== void 0); ) h += r + t[++l], d = !0;
    l !== s && a.push(n), o.push(h), l++;
  }
  if (l === s && o.push(t[s]), d) {
    const c = o.join("$$lit$$");
    (t = ot.get(c)) === void 0 && (o.raw = o, ot.set(c, t = o)), e = a;
  }
  return i(t, ...e);
}, pe = Gt(Ut);
/**
 * @license
 * Copyright 2018 Google LLC
 * SPDX-License-Identifier: BSD-3-Clause
 */
const _e = (i) => i ?? u;
export {
  u as E,
  N as a,
  $e as b,
  _e as c,
  de as d,
  ue as e,
  ie as f,
  re as g,
  ne as h,
  te as i,
  ae as m,
  Dt as n,
  le as o,
  _t as r,
  se as t,
  pe as u,
  Ut as x
};
