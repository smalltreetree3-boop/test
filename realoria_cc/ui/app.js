"use strict";
// REALORIA 統合管制室 UI (Claude Code 独立実装・試作)
// 方針: 外部ライブラリ/CDN なし。データは textContent でのみ描画 (XSS 対策)。

(() => {
  // ------------------------------------------------------------ icons (自作の線画)
  const P = {
    home: '<path d="M3 11l9-7 9 7"/><path d="M5 10v10h14V10"/>',
    org: '<rect x="9" y="3" width="6" height="5" rx="1"/><rect x="2" y="16" width="6" height="5" rx="1"/><rect x="9" y="16" width="6" height="5" rx="1"/><rect x="16" y="16" width="6" height="5" rx="1"/><path d="M12 8v4M5 16v-4h14v4M12 12v4"/>',
    network: '<circle cx="12" cy="12" r="3"/><circle cx="4" cy="5" r="2"/><circle cx="20" cy="5" r="2"/><circle cx="4" cy="19" r="2"/><circle cx="20" cy="19" r="2"/><path d="M6 6l4 4M18 6l-4 4M6 18l4-4M18 18l-4-4"/>',
    chat: '<path d="M4 5h16v11H9l-5 4z"/>',
    jobs: '<path d="M4 6h16M4 12h16M4 18h10"/><circle cx="19" cy="18" r="2"/>',
    audit: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M8.5 12l2.5 2.5 4.5-5"/>',
    briefcase: '<rect x="3" y="7" width="18" height="13" rx="2"/><path d="M9 7V5h6v2M3 13h18"/>',
    pen: '<path d="M4 20l4-1 11-11-3-3L5 16z"/><path d="M14 6l3 3"/>',
    users: '<circle cx="9" cy="8" r="3"/><path d="M3 20c0-3.5 3-6 6-6s6 2.5 6 6"/><circle cx="17" cy="9" r="2.5"/><path d="M16 14c3 0 5 2 5 5"/>',
    chart: '<path d="M4 20V4M4 20h16"/><path d="M8 16v-5M12 16V8M16 16v-3"/>',
    server: '<rect x="4" y="4" width="16" height="7" rx="1.5"/><rect x="4" y="13" width="16" height="7" rx="1.5"/><path d="M8 7.5h.01M8 16.5h.01"/>',
    archive: '<rect x="3" y="4" width="18" height="5" rx="1"/><path d="M5 9v11h14V9M10 13h4"/>',
    mic: '<rect x="9" y="3" width="6" height="11" rx="3"/><path d="M5 11a7 7 0 0014 0M12 18v3"/>',
    send: '<path d="M4 12l16-8-6 16-2-7z"/>',
  };
  const icon = (name, cls = "icon") =>
    `<svg class="${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${P[name] || ""}</svg>`;

  // ------------------------------------------------------------ helpers
  const $ = (s) => document.querySelector(s);
  function h(tag, attrs = {}, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "html") el.innerHTML = v; // 静的アイコン専用
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : v);
    }
    for (const kid of kids.flat()) {
      if (kid === null || kid === undefined || kid === false) continue;
      el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    }
    return el;
  }
  const jst = new Intl.DateTimeFormat("ja-JP", { timeZone: "Asia/Tokyo", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
  const fmtTime = (t) => (t ? jst.format(new Date(t * 1000)) + " JST" : "—");
  const CLS = ["公開", "内部", "機密", "厳秘"];
  const STATE = { queued: "待機", running: "実行中", paused: "一時停止", held: "Hold隔離", succeeded: "完了", failed: "失敗", cancelled: "中止" };
  const STATE_CLASS = { queued: "info", running: "info", paused: "warn", held: "warn", succeeded: "ok", failed: "bad", cancelled: "" };
  const pill = (text, cls = "") => h("span", { class: `pill ${cls}` }, text);

  let token = null;
  try { token = sessionStorage.getItem("rcc_token"); } catch (_) { /* 保存不可でも動作 */ }
  let me = null, overview = null, view = "home", orgHq = "HQ1";
  let outputMode = "text";

  async function api(method, path, body) {
    const opt = { method, headers: {} };
    if (token) opt.headers.Authorization = `Bearer ${token}`;
    if (body !== undefined) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
    const r = await fetch(path, opt);
    const data = await r.json().catch(() => ({}));
    if (r.status === 401) { logoutLocal(); throw new Error(data.error || "未認証"); }
    if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
    return data;
  }

  function toast(msg, bad = false) {
    showDialog(bad ? "エラー" : "お知らせ", h("p", { class: bad ? "error" : "" }, msg));
  }
  function showDialog(title, body) {
    $("#dlg-title").textContent = title;
    const b = $("#dlg-body"); b.replaceChildren(body);
    const d = $("#dlg"); if (!d.open) d.showModal();
  }
  $("#dlg-close").addEventListener("click", () => $("#dlg").close());

  // ------------------------------------------------------------ auth
  function logoutLocal() {
    token = null; try { sessionStorage.removeItem("rcc_token"); } catch (_) {}
    $("#app").hidden = true; $("#login").hidden = false;
  }
  $("#login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    $("#login-error").textContent = "";
    try {
      const r = await api("POST", "/api/login", { id: f.get("id"), password: f.get("password") });
      token = r.token; try { sessionStorage.setItem("rcc_token", token); } catch (_) {}
      e.target.reset(); await boot();
    } catch (err) { $("#login-error").textContent = err.message; }
  });
  $("#btn-logout").addEventListener("click", async () => { try { await api("POST", "/api/logout"); } catch (_) {} logoutLocal(); });
  $("#btn-stop").addEventListener("click", () => {
    const reason = h("input", { placeholder: "停止理由 (監査ログに記録)" });
    showDialog("緊急停止", h("div", {},
      h("p", {}, "実行中のジョブは Hold に隔離され、新規受付も停止します。再開には管理者の操作と監査検証の成功が必要です。"),
      h("label", {}, "理由", reason),
      h("button", { class: "btn danger", onclick: async () => {
        try { await api("POST", "/api/system/stop", { reason: reason.value || "UIからの緊急停止" }); $("#dlg").close(); refresh(); }
        catch (err) { toast(err.message, true); }
      } }, "停止する")));
  });

  // ------------------------------------------------------------ nav
  const VIEWS = [["home", "ホーム", "home"], ["org", "組織", "org"], ["network", "連携図", "network"], ["chat", "AI対話", "chat"], ["jobs", "ジョブ", "jobs"], ["audit", "監査", "audit"]];
  function buildNav() {
    $("#nav").replaceChildren(...VIEWS.map(([id, label, ic]) =>
      h("button", { "aria-current": view === id ? "page" : null, onclick: () => go(id), html: icon(ic) + `<span>${label}</span>` })));
  }
  function go(id) {
    view = id; buildNav();
    for (const [v] of VIEWS) $(`#view-${v}`).hidden = v !== id;
    render();
  }

  // ------------------------------------------------------------ data
  async function refresh() {
    overview = await api("GET", "/api/overview");
    renderTop();
    if (view !== "chat") render();
  }
  function renderTop() {
    const st = overview.status;
    const sp = $("#sys-pill");
    sp.className = "pill " + (st.halted ? "bad" : "ok");
    sp.textContent = st.halted ? `緊急停止中: ${st.halt_reason || ""}` : "稼働中";
    const a = st.last_audit_verify, ap = $("#audit-pill");
    ap.className = "pill " + (!a ? "" : a.ok ? "ok" : "bad");
    ap.textContent = !a ? "監査 未検証" : a.ok ? `監査 正常 (最終検証 ${fmtTime(a.at)})` : "監査 異常";
    $("#reg-pill").hidden = overview.org.verified;
    $("#me").textContent = me ? `${me.display_name} (${me.roles.join(", ")})` : "";
    $("#btn-stop").disabled = st.halted || !(me.roles.includes("operator") || me.roles.includes("admin"));
  }
  function render() {
    if (!overview) return;
    ({ home: renderHome, org: renderOrg, network: renderNetwork, chat: renderChat, jobs: renderJobs, audit: renderAudit })[view]();
  }
  const fnsOf = (hq) => overview.org.functions.filter((f) => f.hq === hq);
  const hqOf = (id) => overview.org.headquarters.find((x) => x.id === id);
  const hqIdx = (id) => id.slice(2);

  // ------------------------------------------------------------ home
  function renderHome() {
    const c = overview.status.job_counts, act = overview.activity;
    const k = (label, v, cls = "") => h("div", { class: `card kpi ${cls}` }, h("div", { class: "k-label" }, label), h("div", { class: "k-value" }, v ?? 0));
    const kpis = h("div", { class: "grid kpis" },
      k("待機", c.queued), k("実行中", c.running), k("一時停止", c.paused, c.paused ? "warn" : ""),
      k("Hold隔離", c.held, c.held ? "warn" : ""), k("完了", c.succeeded), k("失敗", c.failed, c.failed ? "bad" : ""));
    const hqs = h("div", { class: "grid hq-grid" }, overview.org.headquarters.map((hq) => {
      const fns = fnsOf(hq.id);
      const active = fns.reduce((n, f) => n + ((act[f.id] || {}).active || 0), 0);
      return h("button", { class: "card hq-card", onclick: () => { orgHq = hq.id; go("org"); } },
        h("div", { class: "hq-head" },
          h("div", { class: `hq-badge hq${hqIdx(hq.id)}`, html: icon(hq.icon, "icon icon-lg") }),
          h("div", {}, h("div", { class: "hq-title" }, `${hq.label} ${hq.name}`),
            h("div", { class: "hq-sub" }, `基幹機能 ${String(hq.range[0]).padStart(2, "0")}〜${String(hq.range[1]).padStart(2, "0")} ・ 処理中 ${active}`))),
        h("div", { class: "dots" }, fns.map((f) => {
          const a = act[f.id] || {};
          const cls = ["dot", a.held ? "held" : a.active ? "active" : "", f.mode === "signal_only" ? "signal" : ""].join(" ");
          return h("span", { class: cls, title: `${f.name}${f.mode === "signal_only" ? " ・Signal限定" : ""}` }, f.id);
        })));
    }));
    const recent = h("ul", { class: "list" }, overview.recent_jobs.length ? overview.recent_jobs.map((j) =>
      h("li", {}, pill(STATE[j.state] || j.state, STATE_CLASS[j.state]), h("span", { class: "mono" }, `機能${j.function_id}`),
        h("span", { class: "grow muted hide-sm" }, `${j.provider}:${j.model}`), h("span", { class: "fine" }, fmtTime(j.updated_at)),
        h("button", { class: "btn sm", onclick: () => openJob(j.id) }, "詳細"))) : h("li", { class: "muted" }, "まだジョブはありません"));
    const notes = h("ul", { class: "list" }, overview.status.notifications.length ? overview.status.notifications.slice(0, 8).map((n) =>
      h("li", {}, pill(n.level === "critical" ? "重大" : n.level === "warning" ? "注意" : "情報", n.level === "critical" ? "bad" : "warn"),
        h("span", { class: "grow" }, n.message), h("span", { class: "fine" }, fmtTime(n.created_at)))) : h("li", { class: "muted" }, "通知はありません"));
    const unverified = overview.org.verified ? null : h("div", { class: "notice" },
      "組織定義は正式情報源と未照合です。33機能の名称・権限・承認条件は確定しておらず、承認機能は無効化されています。");
    $("#view-home").replaceChildren(unverified || "", kpis,
      h("h2", {}, "6本部・33基幹機能"), hqs,
      h("div", { class: "grid two-col" },
        h("div", { class: "card" }, h("h3", {}, "最新の処理と成果"), recent),
        h("div", { class: "card" }, h("h3", {}, "異常・通知"), notes)));
  }

  // ------------------------------------------------------------ org
  function renderOrg() {
    const tabs = h("div", { class: "tabs" }, overview.org.headquarters.map((hq) =>
      h("button", { class: "btn", "aria-pressed": String(orgHq === hq.id), onclick: () => { orgHq = hq.id; renderOrg(); } }, `${hq.label} ${hq.name}`)));
    const hq = hqOf(orgHq);
    const grid = h("div", { class: "grid fn-grid" }, fnsOf(orgHq).map((f) => {
      const a = overview.activity[f.id] || {};
      return h("button", { class: "card fn-tile", onclick: () => openFunction(f) },
        h("div", { class: "fn-num" }, f.id),
        h("div", {}, f.name),
        h("div", { class: "tags" }, pill("未照合", "warn"), f.mode === "signal_only" ? pill("Signal限定", "info") : null,
          a.active ? pill(`処理中 ${a.active}`, "info") : null, a.held ? pill(`Hold ${a.held}`, "warn") : null),
        h("div", { class: "fine" }, a.last_at ? `最終: ${STATE[a.last_state]} ${fmtTime(a.last_at)}` : "履歴なし"));
    }));
    const gov = h("div", { class: "card" }, h("h3", {}, "委員会・横断統制"),
      h("div", { class: "tags" }, [...overview.org.committees, ...overview.org.governance].map((g) => pill(g.name, "warn"))),
      h("p", { class: "fine" }, "名称・権限は正式情報源の提供後に照合します。推測による権限設定は行っていません。"));
    $("#view-org").replaceChildren(h("h2", {}, "組織"), tabs,
      h("p", { class: "muted" }, `${hq.label} ${hq.name}`), grid, h("div", { class: "spacer" }), gov);
  }
  function openFunction(f) {
    const hq = hqOf(f.hq);
    showDialog(`基幹機能 ${f.id}`, h("div", {},
      h("dl", { class: "kv" },
        h("dt", {}, "名称"), h("dd", {}, f.name),
        h("dt", {}, "所属"), h("dd", {}, `${hq.label} ${hq.name}`),
        h("dt", {}, "照合状態"), h("dd", {}, f.verification === "verified" ? "照合済み" : "未照合"),
        h("dt", {}, "出力可能"), h("dd", {}, f.allowed_outputs.join(" / ")),
        h("dt", {}, "承認権限"), h("dd", {}, f.approval_authority || "なし (未照合のため無効)"),
        h("dt", {}, "備考"), h("dd", {}, f.note)),
      h("p", {}, h("button", { class: "btn primary", onclick: () => { $("#dlg").close(); chatFn = f.id; go("chat"); } }, "この機能のAIに依頼する"))));
  }

  // ------------------------------------------------------------ network
  function renderNetwork() {
    const NS = "http://www.w3.org/2000/svg";
    const s = (tag, attrs, text) => { const e = document.createElementNS(NS, tag); for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v); if (text !== undefined) e.textContent = text; return e; };
    const W = 720, C = W / 2, R1 = 150, R2 = 290;
    const svg = s("svg", { viewBox: `0 0 ${W} ${W}`, class: "net", role: "img", "aria-label": "AI組織ネットワーク図" });
    svg.append(s("circle", { cx: C, cy: C, r: R1, class: "ring" }), s("circle", { cx: C, cy: C, r: R2, class: "ring" }));
    const fns = overview.org.functions, act = overview.activity;
    const pos = (i, n, r, off = -Math.PI / 2) => [C + r * Math.cos(off + (2 * Math.PI * i) / n), C + r * Math.sin(off + (2 * Math.PI * i) / n)];
    const hqPos = {};
    overview.org.headquarters.forEach((hq) => {
      const idx = fns.map((f, i) => (f.hq === hq.id ? i : -1)).filter((i) => i >= 0);
      const mid = (idx[0] + idx[idx.length - 1]) / 2;
      hqPos[hq.id] = pos(mid, fns.length, R1);
    });
    // edges
    overview.org.headquarters.forEach((hq) => svg.append(s("line", { x1: C, y1: C, x2: hqPos[hq.id][0], y2: hqPos[hq.id][1], class: "edge unverified" })));
    fns.forEach((f, i) => { const [x, y] = pos(i, fns.length, R2); svg.append(s("line", { x1: hqPos[f.hq][0], y1: hqPos[f.hq][1], x2: x, y2: y, class: "edge unverified" })); });
    // core
    svg.append(s("circle", { cx: C, cy: C, r: 54, class: "core" }), s("text", { x: C, y: C - 4, "text-anchor": "middle", class: "core-label" }, "総合・統括"), s("text", { x: C, y: C + 13, "text-anchor": "middle", class: "core-sub" }, "人間が最終判断"));
    // governance ring around core
    const gov = [...overview.org.committees, ...overview.org.governance];
    gov.forEach((g, i) => { const [x, y] = pos(i, gov.length, 90, -Math.PI / 2 + 0.3); svg.append(s("circle", { cx: x, cy: y, r: 14, class: "gov" }), s("text", { x, y: y + 4, "text-anchor": "middle" }, g.id)); });
    // HQ nodes
    overview.org.headquarters.forEach((hq) => {
      const [x, y] = hqPos[hq.id];
      svg.append(s("circle", { cx: x, cy: y, r: 30, class: `fn s-hq${hqIdx(hq.id)}` }), s("text", { x, y: y + 4, "text-anchor": "middle" }, hq.label));
    });
    // function nodes
    fns.forEach((f, i) => {
      const [x, y] = pos(i, fns.length, R2), a = act[f.id] || {};
      const g = s("g", { tabindex: "0", role: "button", "aria-label": f.name });
      g.append(s("circle", { cx: x, cy: y, r: 17, class: `fn s-hq${hqIdx(f.hq)} ${a.held ? "held" : a.active ? "active" : ""}` }), s("text", { x, y: y + 4, "text-anchor": "middle" }, f.id));
      g.addEventListener("click", () => openFunction(f));
      g.addEventListener("keydown", (e) => { if (e.key === "Enter") openFunction(f); });
      svg.append(g);
    });
    const legend = h("div", { class: "legend" },
      overview.org.headquarters.map((hq) => h("span", {}, h("span", { class: `pill`, }, `${hq.label}: ${hq.name}`))),
      h("span", {}, "点線 = 正式情報源と未照合の関係"), h("span", {}, "内側の小円 = 委員会C1〜C3・横断統制G1〜G5"));
    $("#view-network").replaceChildren(h("h2", {}, "AI組織ネットワーク"),
      h("div", { class: "card net-wrap" }, svg, legend));
  }

  // ------------------------------------------------------------ chat
  let chatFn = "07";
  const chatLog = [];
  let sources = [];
  async function renderChat() {
    try { sources = await api("GET", "/api/sources"); } catch (_) { sources = []; }
    const providers = overview.providers;
    const fnSel = h("select", { onchange: (e) => { chatFn = e.target.value; } }, overview.org.functions.map((f) =>
      h("option", { value: f.id, selected: f.id === chatFn || null }, `${f.id} ${hqOf(f.hq).name}${f.mode === "signal_only" ? " (Signal限定)" : ""}`)));
    const provSel = h("select", {}, providers.map((p) => h("option", { value: p.name, disabled: !p.enabled || null }, `${p.label}${p.enabled ? "" : " — " + p.reason}`)));
    const modelSel = h("select", {});
    const fillModels = () => { const p = providers.find((x) => x.name === provSel.value); modelSel.replaceChildren(...p.models.map((m) => h("option", { value: m }, m))); };
    provSel.addEventListener("change", fillModels); fillModels();
    const clsSel = h("select", {}, CLS.map((c, i) => h("option", { value: i }, `${c}`)));
    const srcBox = h("div", {}, sources.length ? sources.map((s) =>
      h("label", { class: "fine check" }, h("input", { type: "checkbox", value: s.id, class: "src-cb" }), h("span", {}, `${s.title} [${CLS[s.classification]}・${s.status}]`))) : h("p", { class: "fine" }, "登録済み資料はありません"));
    const seg = h("div", { class: "seg", role: "group", "aria-label": "出力方法" }, [["text", "文字"], ["voice", "音声"], ["both", "両方"]].map(([v, l]) =>
      h("button", { "aria-pressed": String(outputMode === v), onclick: (e) => { outputMode = v; for (const b of seg.children) b.setAttribute("aria-pressed", String(b === e.currentTarget)); } }, l)));
    const ttsOk = "speechSynthesis" in window;
    const side = h("div", { class: "card" },
      h("h3", {}, "依頼の設定"),
      h("label", {}, "担当する基幹機能", fnSel),
      h("label", {}, "AIプロバイダ", provSel),
      h("label", {}, "モデル (実行中は変更されません)", modelSel),
      h("label", {}, "情報区分 (資料の区分より下げられません)", clsSel),
      h("div", {}, h("div", { class: "fine" }, "根拠資料"), srcBox),
      h("div", {}, h("div", { class: "fine" }, "出力"), seg, ttsOk ? null : h("div", { class: "fine" }, "この端末は音声出力に未対応です")),
      h("p", { class: "fine" }, "外部AI (OpenAI / Claude) は未接続・送信無効です。厳秘区分は外部へ送信されません。"));
    const logEl = h("div", { class: "chat-log", "aria-live": "polite" });
    chatLog.forEach((m) => logEl.append(m));
    const input = h("textarea", { placeholder: "依頼内容を入力 (例: 読者アンケートから改善点を整理して)", rows: 3 });
    const voiceAllowed = overview.voice_input_enabled && ("webkitSpeechRecognition" in window || "SpeechRecognition" in window);
    const micBtn = h("button", { class: "btn", title: voiceAllowed ? "音声入力" : "音声入力は無効 (ブラウザの音声認識は音声を外部サーバへ送る場合があるため、運用者の許可が必要)", disabled: !voiceAllowed || null, html: icon("mic"), onclick: () => startVoice(input) });
    const send = h("button", { class: "btn primary", html: icon("send") + "<span>送信</span>", onclick: async () => {
      const text = input.value.trim(); if (!text) return;
      const src = [...document.querySelectorAll(".src-cb:checked")].map((x) => x.value);
      const fn = overview.org.functions.find((f) => f.id === chatFn);
      const body = { function_id: chatFn, instruction: text, source_ids: src, classification: Number(clsSel.value), provider: provSel.value, model: modelSel.value, output_kind: fn.mode === "signal_only" ? "signal" : "analysis" };
      const um = h("div", { class: "msg user" }, h("div", { class: "meta" }, `あなた → 機能${chatFn}`), text);
      chatLog.push(um); logEl.append(um); input.value = "";
      try {
        const job = await api("POST", "/api/jobs", body);
        const am = h("div", { class: "msg ai" }); chatLog.push(am); logEl.append(am);
        pollJob(job.id, am, logEl);
      } catch (err) {
        const em = h("div", { class: "msg ai" }, h("span", { class: "error" }, err.message)); chatLog.push(em); logEl.append(em);
      }
    } });
    const composer = h("div", { class: "composer" }, input, micBtn, send);
    $("#view-chat").replaceChildren(h("h2", {}, "AI対話"),
      h("div", { class: "notice info" }, "AIの出力は判断材料の下書きです。公開・承認・契約・支払は行いません。根拠のない記述は「要確認」として表示します。"),
      h("div", { class: "chat" }, side, h("div", { class: "card" }, logEl, composer)));
  }
  function startVoice(input) {
    const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
    const rec = new SR(); rec.lang = "ja-JP"; rec.interimResults = false;
    rec.onresult = (e) => { input.value += e.results[0][0].transcript; };
    rec.onerror = (e) => toast(`音声入力エラー: ${e.error}`, true);
    rec.start();
  }
  function speak(text) {
    if (!("speechSynthesis" in window)) return;
    const u = new SpeechSynthesisUtterance(text); u.lang = "ja-JP"; speechSynthesis.cancel(); speechSynthesis.speak(u);
  }
  async function pollJob(id, el, logEl) {
    for (let i = 0; i < 60; i++) {
      let j; try { j = await api("GET", `/api/jobs/${id}`); } catch (err) { el.replaceChildren(h("span", { class: "error" }, err.message)); return; }
      renderAiMsg(el, j); logEl.scrollTop = logEl.scrollHeight;
      if (["succeeded", "failed", "cancelled", "held", "paused"].includes(j.state)) {
        if (j.state === "succeeded" && outputMode !== "text") {
          const c = j.proposals[0]?.content || {};
          speak([c.summary, ...(c.findings || []).map((f) => f.text)].filter(Boolean).join("。"));
          if (outputMode === "voice") el.querySelector(".body")?.setAttribute("hidden", "");
        }
        refresh().catch(() => {}); return;
      }
      await new Promise((r) => setTimeout(r, 1000));
    }
  }
  function renderAiMsg(el, j) {
    const p = j.proposals[0];
    const step = (label, cls) => h("span", { class: `step ${cls}` }, label);
    const done = j.state === "succeeded";
    const steps = h("div", { class: "steps" },
      step("受付", "done"), step("実行", ["running", "queued"].includes(j.state) ? "" : "done"),
      step("根拠検査", !done ? "" : p.grounding.passed ? "done" : "fail"), step(done ? (p.status === "draft" ? "下書き" : "要確認") : STATE[j.state], done ? (p.status === "draft" ? "done" : "fail") : j.state === "held" || j.state === "failed" ? "fail" : ""));
    const meta = h("div", { class: "meta" }, h("span", {}, `機能${j.function_id}`), pill(STATE[j.state], STATE_CLASS[j.state]), h("span", {}, `${j.provider}:${j.model}`), h("span", {}, `区分:${CLS[j.classification]}`));
    const body = h("div", { class: "body" });
    if (done) {
      const c = p.content, flagged = new Set(p.grounding.issues.filter((x) => x.section === "findings").map((x) => x.index));
      body.append(h("p", {}, c.summary || ""));
      (c.findings || []).forEach((f, i) => body.append(h("div", { class: `finding ${flagged.has(i) ? "flag" : ""}` }, f.text,
        h("div", { class: "cite" }, f.source_ids?.length ? `根拠: ${f.source_ids.join(", ")}` : "根拠なし — 要確認"),
        flagged.has(i) && f.source_ids?.length ? h("div", { class: "cite error" }, "提供されていない資料を引用 — 要確認") : null)));
      if ((c.unknowns || []).length) body.append(h("div", { class: "fine" }, "確認できない事項: " + c.unknowns.join(" / ")));
    } else if (j.error) body.append(h("div", { class: "error" }, j.error));
    el.replaceChildren(meta, steps, body, h("button", { class: "btn sm", onclick: () => openJob(j.id) }, "処理記録"));
  }

  // ------------------------------------------------------------ jobs
  async function renderJobs() {
    const jobs = await api("GET", "/api/jobs?limit=100");
    const isOp = me.roles.includes("operator") || me.roles.includes("admin");
    const act = (j, op, label) => h("button", { class: "btn sm", disabled: !isOp || null, onclick: async () => {
      try { await api("POST", `/api/jobs/${j.id}/${op}`, { reason: "UI操作" }); await refresh(); } catch (err) { toast(err.message, true); }
    } }, label);
    const rows = jobs.map((j) => h("tr", {},
      h("td", {}, pill(STATE[j.state] || j.state, STATE_CLASS[j.state])),
      h("td", { class: "num" }, j.function_id), h("td", { class: "mono" }, j.id.slice(0, 8)),
      h("td", {}, `${j.provider}:${j.model}`), h("td", {}, CLS[j.classification]),
      h("td", { class: "num" }, `${j.attempts}/${j.max_attempts}`),
      h("td", {}, j.hold_reason || j.error || ""), h("td", { class: "num" }, fmtTime(j.updated_at)),
      h("td", {}, h("div", { class: "actions" },
        ["queued", "running"].includes(j.state) ? act(j, "pause", "一時停止") : null,
        j.state === "paused" ? act(j, "resume", "再開") : null,
        j.state === "held" ? act(j, "release", "Hold解除") : null,
        !["succeeded", "failed", "cancelled"].includes(j.state) ? act(j, "cancel", "中止") : null,
        h("button", { class: "btn sm", onclick: () => openJob(j.id) }, "詳細")))));
    $("#view-jobs").replaceChildren(h("h2", {}, "ジョブ"),
      h("div", { class: "card table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, ["状態", "機能", "ID", "モデル", "区分", "試行", "理由", "更新 (JST)", "操作"].map((t) => h("th", {}, t)))),
        h("tbody", {}, rows.length ? rows : h("tr", {}, h("td", { colspan: 9, class: "muted" }, "ジョブはありません"))))));
  }
  async function openJob(id) {
    try {
      const j = await api("GET", `/api/jobs/${id}`);
      showDialog(`ジョブ ${id.slice(0, 8)}`, h("div", {},
        h("dl", { class: "kv" },
          h("dt", {}, "状態"), h("dd", {}, STATE[j.state]), h("dt", {}, "機能"), h("dd", {}, j.function_id),
          h("dt", {}, "モデル"), h("dd", {}, `${j.provider}:${j.model} (受付時に固定)`),
          h("dt", {}, "区分"), h("dd", {}, CLS[j.classification]), h("dt", {}, "試行"), h("dd", {}, `${j.attempts}/${j.max_attempts}`),
          h("dt", {}, "フェンシング"), h("dd", {}, `token ${j.lease_token} / 停止世代 ${j.stop_generation}`),
          h("dt", {}, "受付"), h("dd", {}, `${fmtTime(j.created_at)} by ${j.created_by}`)),
        h("h3", {}, "AIへの送信記録"),
        h("ul", { class: "list" }, j.model_calls.map((c) => h("li", {}, pill(c.status, c.status === "ok" ? "ok" : "bad"), `${c.provider}:${c.model} (${c.locality})`,
          h("span", { class: "grow fine mono" }, `sha256 ${c.prompt_sha256.slice(0, 16)}… / ${c.prompt_chars}字 / tokens≈${(c.input_tokens || 0) + (c.output_tokens || 0)}${c.tokens_estimated ? "(推定)" : ""} / 費用 ${c.cost_usd ?? "—"}`)))),
        h("h3", {}, "出力 (JSON)"), h("pre", { class: "mono" }, JSON.stringify(j.proposals.map((p) => ({ status: p.status, grounding: p.grounding, content: p.content })), null, 2))));
    } catch (err) { toast(err.message, true); }
  }

  // ------------------------------------------------------------ audit
  async function renderAudit() {
    const canRead = me.roles.includes("auditor") || me.roles.includes("admin");
    const res = h("div", {});
    const showRes = (r) => res.replaceChildren(h("p", {}, pill(r.ok ? "正常" : "異常", r.ok ? "ok" : "bad"), ` 記録 ${r.entries}件 / 末尾 seq ${r.last_seq} / 外部アンカー ${r.anchor_count}件`),
      r.problems?.length ? h("ul", {}, r.problems.map((p) => h("li", { class: "error" }, p))) : "");
    const last = overview.status.last_audit_verify; if (last) showRes(last);
    const verifyBtn = h("button", { class: "btn primary", onclick: async () => { try { showRes(await api("POST", "/api/audit/verify")); refresh(); } catch (err) { toast(err.message, true); } } }, "今すぐ検証");
    let table = h("p", { class: "muted" }, "監査ログの閲覧には auditor 権限が必要です。");
    if (canRead) {
      const rows = await api("GET", "/api/audit?after=0");
      table = h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, ["seq", "時刻 (JST)", "主体", "操作", "対象", "詳細", "hash"].map((t) => h("th", {}, t)))),
        h("tbody", {}, rows.slice(-100).reverse().map((r) => h("tr", {}, h("td", { class: "num" }, r.seq), h("td", { class: "num" }, fmtTime(r.ts)), h("td", {}, r.actor), h("td", { class: "mono" }, r.action),
          h("td", { class: "mono" }, (r.target || "").slice(0, 12)), h("td", { class: "mono" }, r.detail.slice(0, 120)), h("td", { class: "mono" }, r.hash.slice(0, 10)))))));
    }
    const resumeBtn = overview.status.halted && me.roles.includes("admin") ? h("button", { class: "btn", onclick: async () => {
      try { await api("POST", "/api/system/resume", { reason: "UIから再開" }); await refresh(); } catch (err) { toast(err.message, true); }
    } }, "システム再開 (監査検証が必要)") : null;
    $("#view-audit").replaceChildren(h("h2", {}, "監査・保全"),
      h("div", { class: "card" }, h("p", { class: "fine" }, "ハッシュ鎖・HMAC・外部アンカーで改変・欠落・切り詰めを検知します。異常時はシステムを自動停止します。"),
        h("div", { class: "actions" }, verifyBtn, resumeBtn), res),
      h("div", { class: "card" }, h("h3", {}, "監査ログ (新しい順・最大100件)"), table));
  }

  // ------------------------------------------------------------ boot
  async function boot() {
    if (!token) { logoutLocal(); return; }
    try { me = await api("GET", "/api/me"); } catch (_) { return; }
    $("#login").hidden = true; $("#app").hidden = false;
    buildNav(); await refresh(); go(view);
  }
  setInterval(() => { if (token && !$("#app").hidden && view !== "chat") refresh().catch(() => {}); }, 10000);
  boot();
})();
