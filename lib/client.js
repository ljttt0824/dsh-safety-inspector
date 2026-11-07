window.__ModuleLoader__.load({
  id: "dsh-safety-inspector",
  factory: (require) => {
    var module = { exports: {} };
    var exports = module.exports;
    Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });

    const React = require("react");
    const h = React.createElement;
    const { useCallback, useEffect, useMemo, useRef, useState } = React;

    const API = "/api/agent-safety";
    const PANEL_ID = "safety-inspector";
    const NS = "dsh-safety-inspector";

    const COLORS = {
      critical: "#e5484d",
      high: "#f76b15",
      medium: "#f5a524",
      low: "#8f8f8f",
      info: "#5b8def",
    };
    const SEVERITY_CN = { critical: "严重", high: "高", medium: "中", low: "低", info: "提示" };
    const SEVERITY_OF_CN = { 严重: "critical", 高: "high", 中: "medium", 低: "low", info: "info" };
    const CODE_COLOR = (code) => {
      const head = String(code || "").slice(0, 1);
      return {
        A: "#5b8def", B: "#a259ff", C: "#e5484d", D: "#f76b15",
        E: "#f5a524", F: "#d6409f", G: "#8f8f8f", H: "#12a594",
      }[head] || "#8f8f8f";
    };

    /* ------------------------------------------------------------ styles */

    const CSS = `
.sf-root{height:100%;min-height:0;display:flex;flex-direction:column;background:var(--dsw-alias-bg-layer-1);color:var(--dsw-alias-label-primary);font:inherit;overflow:hidden}
.sf-head{display:flex;align-items:center;gap:8px;padding:9px 12px;border-bottom:1px solid var(--dsw-alias-border-l1);flex:none}
.sf-title{font-weight:650;font-size:14px;display:flex;align-items:center;gap:7px}
.sf-title svg{color:var(--dsw-alias-state-business-primary)}
.sf-sub{color:var(--dsw-alias-label-tertiary);font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:340px}
.sf-chip{display:inline-flex;align-items:center;gap:5px;height:22px;padding:0 8px;border-radius:999px;background:var(--dsw-alias-interactive-bg-hover);color:var(--dsw-alias-label-secondary);font-size:11px;white-space:nowrap}
.sf-chip b{color:var(--dsw-alias-label-primary);font-variant-numeric:tabular-nums}
.sf-chip.warn{color:#f5a524;background:color-mix(in srgb,#f5a524 14%,transparent)}
.sf-chip.bad{color:#e5484d;background:color-mix(in srgb,#e5484d 14%,transparent)}
.sf-chip.ok{color:#12a594;background:color-mix(in srgb,#12a594 14%,transparent)}
.sf-btn{height:26px;padding:0 10px;border:1px solid var(--dsw-alias-border-l2);border-radius:7px;background:var(--dsw-alias-bg-layer-2);color:var(--dsw-alias-label-secondary);font:inherit;font-size:11px;cursor:pointer}
.sf-btn:hover{color:var(--dsw-alias-label-primary);background:var(--dsw-alias-interactive-bg-hover)}
.sf-btn.primary{background:var(--dsw-alias-button-primary-fill);color:var(--dsw-alias-label-primary-foreground);border-color:transparent}
.sf-btn:disabled{opacity:.5;cursor:default}
.sf-body{flex:1;min-height:0;display:flex}
.sf-rail{width:246px;flex:none;border-right:1px solid var(--dsw-alias-border-l1);display:flex;flex-direction:column;min-height:0;background:var(--dsw-alias-bg-base)}
.sf-railHead{display:flex;align-items:center;gap:6px;padding:7px 10px;border-bottom:1px solid var(--dsw-alias-border-l1);font-size:11px;color:var(--dsw-alias-label-tertiary)}
.sf-railList{flex:1;overflow:auto;min-height:0}
.sf-srow{display:flex;flex-direction:column;gap:3px;padding:7px 10px;cursor:pointer;border-left:2px solid transparent}
.sf-srow:hover{background:var(--dsw-alias-interactive-bg-hover)}
.sf-srow.on{background:color-mix(in srgb,var(--dsw-alias-state-business-primary) 10%,transparent);border-left-color:var(--dsw-alias-state-business-primary)}
.sf-srow .t{font-size:11px;font-family:var(--ds-font-family-code);color:var(--dsw-alias-label-primary);display:flex;gap:6px;align-items:center}
.sf-srow .m{font-size:10px;color:var(--dsw-alias-label-tertiary);display:flex;gap:7px}
.sf-dot{width:7px;height:7px;border-radius:50%;flex:none}
.sf-main{flex:1;min-width:0;display:flex;flex-direction:column;min-height:0}
.sf-tabs{display:flex;gap:2px;padding:6px 10px 0;border-bottom:1px solid var(--dsw-alias-border-l1);flex:none}
.sf-tab{padding:5px 11px;border-radius:7px 7px 0 0;font-size:12px;color:var(--dsw-alias-label-secondary);cursor:pointer;border:1px solid transparent;border-bottom:none}
.sf-tab.on{background:var(--dsw-alias-bg-layer-2);color:var(--dsw-alias-label-primary);border-color:var(--dsw-alias-border-l1)}
.sf-view{flex:1;min-height:0;overflow:auto;padding:12px}
.sf-card{border:1px solid var(--dsw-alias-border-l1);border-radius:10px;background:var(--dsw-alias-bg-layer-2);padding:10px 12px;margin-bottom:10px}
.sf-row{display:flex;gap:12px;align-items:center;flex-wrap:wrap}
.sf-ring{flex:none}
.sf-kv{display:flex;flex-direction:column;gap:3px}
.sf-kv b{font-size:20px;font-variant-numeric:tabular-nums;line-height:1}
.sf-kv span{font-size:11px;color:var(--dsw-alias-label-tertiary)}
.sf-muted{color:var(--dsw-alias-label-tertiary);font-size:11px}
.sf-bar{display:flex;align-items:center;gap:8px;margin:4px 0;font-size:12px;cursor:pointer}
.sf-bar .n{width:150px;flex:none;display:flex;gap:6px;align-items:center}
.sf-bar .track{flex:1;height:8px;border-radius:4px;background:var(--dsw-alias-interactive-bg-hover);overflow:hidden}
.sf-bar .fill{height:100%;border-radius:4px}
.sf-bar .c{width:34px;text-align:right;color:var(--dsw-alias-label-secondary);font-variant-numeric:tabular-nums;font-size:11px}
.sf-heat{display:flex;gap:1px;align-items:flex-end;height:26px;padding:4px 0}
.sf-heat i{flex:1;min-width:1px;background:var(--dsw-alias-border-l2);border-radius:1px}
.sf-heat i.hit{background:#e5484d}
.sf-finding{display:flex;gap:9px;align-items:flex-start;padding:8px 10px;border:1px solid var(--dsw-alias-border-l1);border-radius:9px;margin-bottom:6px;cursor:pointer;background:var(--dsw-alias-bg-layer-1)}
.sf-finding:hover{border-color:var(--dsw-alias-border-l2);background:var(--dsw-alias-interactive-bg-hover)}
.sf-finding.sel{border-color:var(--dsw-alias-state-business-primary)}
.sf-code{font-family:var(--ds-font-family-code);font-size:10px;font-weight:700;color:#fff;padding:1px 5px;border-radius:4px;flex:none}
.sf-sev{font-size:10px;padding:1px 6px;border-radius:999px;border:1px solid currentColor;flex:none}
.sf-ev{flex:1;min-width:0;font-size:12px;color:var(--dsw-alias-label-secondary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sf-seq{font-family:var(--ds-font-family-code);font-size:10px;color:var(--dsw-alias-label-tertiary);flex:none}
.sf-blind{display:flex;flex-wrap:wrap;gap:5px;margin-top:6px}
.sf-blind span{font-size:10px;padding:2px 6px;border-radius:5px;background:var(--dsw-alias-interactive-bg-hover);color:var(--dsw-alias-label-tertiary)}
.sf-chain{display:flex;height:100%;min-height:0;gap:0}
.sf-steps{width:270px;flex:none;border-right:1px solid var(--dsw-alias-border-l1);overflow:auto;min-height:0}
.sf-turn{padding:5px 8px;font-size:10px;color:var(--dsw-alias-label-tertiary);position:sticky;top:0;background:var(--dsw-alias-bg-layer-1);z-index:1}
.sf-step{padding:6px 9px;cursor:pointer;border-left:2px solid transparent}
.sf-step:hover{background:var(--dsw-alias-interactive-bg-hover)}
.sf-step.on{background:color-mix(in srgb,var(--dsw-alias-state-business-primary) 10%,transparent);border-left-color:var(--dsw-alias-state-business-primary)}
.sf-step .hd{font-size:11px;display:flex;gap:6px;align-items:center;color:var(--dsw-alias-label-primary)}
.sf-step .tl{font-size:10px;color:var(--dsw-alias-label-tertiary);margin-top:2px;display:flex;gap:5px;flex-wrap:wrap}
.sf-tool{font-family:var(--ds-font-family-code);font-size:10px;padding:0 4px;border-radius:4px;background:var(--dsw-alias-interactive-bg-hover)}
.sf-tool.err{color:#e5484d}
.sf-insp{flex:1;min-width:0;overflow:auto;padding:10px 12px;display:flex;flex-direction:column;gap:10px}
.sf-k{font-size:11px;font-weight:650;color:var(--dsw-alias-label-secondary);letter-spacing:.02em;text-transform:uppercase}
.sf-code-box{font-family:var(--ds-font-family-code);font-size:11px;line-height:1.5;background:var(--dsw-alias-bg-base);border:1px solid var(--dsw-alias-border-l1);border-radius:8px;padding:8px;white-space:pre-wrap;word-break:break-all;max-height:260px;overflow:auto;color:var(--dsw-alias-label-secondary)}
.sf-access{display:grid;grid-template-columns:64px 1fr;gap:4px 8px;font-size:11px}
.sf-access .lbl{color:var(--dsw-alias-label-tertiary)}
.sf-access .val{font-family:var(--ds-font-family-code);word-break:break-all;color:var(--dsw-alias-label-secondary)}
.sf-badge-line{display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--dsw-alias-label-secondary);cursor:pointer;padding:2px 4px;border-radius:6px}
.sf-badge-line:hover{background:var(--dsw-alias-interactive-bg-hover)}
.sf-assist{width:26px;height:26px;border:1px solid transparent;border-radius:6px;background:transparent;color:var(--dsw-alias-label-tertiary);cursor:pointer;display:inline-flex;align-items:center;justify-content:center;padding:0}
.sf-assist:hover{background:var(--dsw-alias-interactive-bg-hover);color:var(--dsw-alias-label-primary)}
.sf-overlay{position:fixed;inset:0;z-index:2147483000;display:flex;justify-content:flex-end;pointer-events:none}
.sf-overlay .backdrop{position:absolute;inset:0;background:rgba(0,0,0,.32);pointer-events:auto}
.sf-drawer{position:relative;width:min(560px,92vw);height:100%;background:var(--dsw-alias-bg-layer-1);border-left:1px solid var(--dsw-alias-border-l1);box-shadow:-8px 0 30px rgba(0,0,0,.25);display:flex;flex-direction:column;pointer-events:auto}
.sf-drawer .top{display:flex;align-items:center;gap:8px;padding:10px 12px;border-bottom:1px solid var(--dsw-alias-border-l1)}
.sf-drawer .body{flex:1;min-height:0;overflow:auto;padding:12px}
.sf-empty{display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;gap:8px;color:var(--dsw-alias-label-tertiary);font-size:12px;text-align:center;padding:20px}
.sf-empty .big{font-size:26px;opacity:.5}
.sf-toast{position:fixed;right:16px;bottom:16px;z-index:2147483001;background:var(--dsw-alias-bg-layer-2);border:1px solid var(--dsw-alias-border-l2);border-radius:8px;padding:7px 12px;font-size:12px;box-shadow:0 8px 24px rgba(0,0,0,.2)}
.sf-split{display:flex;gap:14px;align-items:flex-start}
.sf-split>.l{flex:1;min-width:0}
.sf-split>.r{width:320px;flex:none}
.sf-switch{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--dsw-alias-label-secondary)}
.sf-switch input{accent-color:var(--dsw-alias-state-business-primary)}
.sf-badge-fail{font-size:10px;padding:0 5px;border-radius:4px;color:#e5484d;background:color-mix(in srgb,#e5484d 15%,transparent);flex:none}
@media (prefers-color-scheme: dark){.sf-ev{color:var(--dsw-alias-label-secondary)}}
`;

    /* ----------------------------------------------------------- helpers */

    function ensureStyle() {
      if (typeof document === "undefined") return;
      if (document.querySelector('style[data-plugin="' + NS + '"]') !== null) return;
      const style = document.createElement("style");
      style.setAttribute("data-plugin", NS);
      style.textContent = CSS;
      document.head.appendChild(style);
    }

    async function api(path, options) {
      const response = await fetch(API + path, {
        headers: { "content-type": "application/json" },
        cache: "no-store",
        ...(options || {}),
      });
      const text = await response.text();
      let body;
      try { body = text.length > 0 ? JSON.parse(text) : {}; } catch { throw new Error("接口返回了非 JSON：" + text.slice(0, 120)); }
      if (response.ok !== true || body.ok === false) throw new Error(body.error || ("HTTP " + response.status));
      return body;
    }

    function shortId(id) {
      return String(id || "").replace(/^session-/, "").slice(0, 8);
    }

    function fmtTime(ms) {
      if (typeof ms !== "number") return "—";
      const date = new Date(ms);
      const p = (n) => String(n).padStart(2, "0");
      return date.getFullYear() + "-" + p(date.getMonth() + 1) + "-" + p(date.getDate()) + " " + p(date.getHours()) + ":" + p(date.getMinutes());
    }

    function fmtDuration(ms) {
      if (typeof ms !== "number" || ms < 0) return "—";
      if (ms < 1000) return ms + "ms";
      if (ms < 60000) return (ms / 1000).toFixed(1) + "s";
      return Math.floor(ms / 60000) + "m" + Math.round((ms % 60000) / 1000) + "s";
    }

    function severityKey(finding) {
      return SEVERITY_OF_CN[finding.severity] || finding.severity || "info";
    }

    function riskColor(level) {
      return { "严重": COLORS.critical, "高": COLORS.high, "中": COLORS.medium, "低": "#12a594", "—": COLORS.low }[level] || COLORS.low;
    }

    function parseHash() {
      if (typeof location === "undefined") return null;
      const raw = String(location.hash || "").replace(/^#/, "");
      if (!raw.startsWith("safety")) return null;
      const query = raw.includes("?") ? raw.slice(raw.indexOf("?") + 1) : "";
      const params = new URLSearchParams(query);
      return {
        sessionId: params.get("session") || "",
        turn: params.get("turn") ? Number(params.get("turn")) : null,
        seq: params.get("seq") ? Number(params.get("seq")) : null,
        findingId: params.get("finding") || "",
        messageId: params.get("message") || "",
        view: params.get("view") || "",
      };
    }

    function hashFor(target) {
      const params = new URLSearchParams();
      if (target.sessionId) params.set("session", target.sessionId);
      if (target.turn !== undefined && target.turn !== null) params.set("turn", String(target.turn));
      if (target.seq !== undefined && target.seq !== null) params.set("seq", String(target.seq));
      if (target.findingId) params.set("finding", target.findingId);
      if (target.messageId) params.set("message", target.messageId);
      if (target.view) params.set("view", target.view);
      return "#safety?" + params.toString();
    }

    function openLink(target) {
      if (typeof location === "undefined") return;
      const next = hashFor(target);
      if (location.hash === next) {
        window.dispatchEvent(new HashChangeEvent("hashchange"));
        return;
      }
      location.hash = next;
    }

    function closeLink() {
      if (typeof location === "undefined") return;
      history.replaceState(null, "", location.pathname + location.search);
      window.dispatchEvent(new HashChangeEvent("hashchange"));
    }

    async function copyText(text) {
      try {
        await navigator.clipboard.writeText(text);
        return true;
      } catch {
        return false;
      }
    }

    /* -------------------------------------------------------------- icons */

    function Icon({ name, size }) {
      const s = size || 16;
      const common = {
        width: s, height: s, viewBox: "0 0 24 24", fill: "none",
        stroke: "currentColor", strokeWidth: 1.7, strokeLinecap: "round", strokeLinejoin: "round",
      };
      if (name === "shield") {
        return h("svg", common,
          h("path", { d: "M12 3l7 3v6c0 4.2-2.9 7.6-7 9-4.1-1.4-7-4.8-7-9V6z" }),
          h("path", { d: "M9 12l2 2 4-4" }));
      }
      if (name === "refresh") {
        return h("svg", common, h("path", { d: "M20 11a8 8 0 1 0-2.3 5.7" }), h("path", { d: "M20 5v6h-6" }));
      }
      if (name === "link") {
        return h("svg", common, h("path", { d: "M10 13a5 5 0 0 0 7 0l2-2a5 5 0 0 0-7-7l-1 1" }), h("path", { d: "M14 11a5 5 0 0 0-7 0l-2 2a5 5 0 0 0 7 7l1-1" }));
      }
      if (name === "chevron") return h("svg", common, h("path", { d: "M9 6l6 6-6 6" }));
      if (name === "close") return h("svg", common, h("path", { d: "M6 6l12 12M18 6L6 18" }));
      return h("svg", common, h("circle", { cx: 12, cy: 12, r: 9 }));
    }

    /* --------------------------------------------------------------- data */

    function useRemote(loader, deps) {
      const [state, setState] = useState({ data: null, error: null, loading: true });
      const tick = useRef(0);
      const reload = useCallback(async (soft) => {
        const mine = ++tick.current;
        if (soft !== true) setState((prev) => ({ ...prev, loading: true }));
        try {
          const data = await loader();
          if (mine === tick.current) setState({ data, error: null, loading: false });
        } catch (error) {
          if (mine === tick.current) setState({ data: null, error: String(error && error.message ? error.message : error), loading: false });
        }
      }, deps || []);
      useEffect(() => { void reload(); }, [reload]);
      return { ...state, reload };
    }

    function useToast() {
      const [toast, setToast] = useState(null);
      const push = useCallback((message) => {
        setToast({ message, at: Date.now() });
        window.setTimeout(() => {
          setToast((current) => (current !== null && Date.now() - current.at >= 1800 ? null : current));
        }, 1900);
      }, []);
      return { toast, push };
    }

    /* ------------------------------------------------------------ widgets */

    function RiskRing({ score, level, size }) {
      const edge = size || 96;
      const radius = edge / 2 - 8;
      const circumference = 2 * Math.PI * radius;
      const ratio = Math.max(0, Math.min(1, (typeof score === "number" ? score : 0) / 100));
      const color = riskColor(level);
      return h("svg", { className: "sf-ring", width: edge, height: edge, viewBox: "0 0 " + edge + " " + edge },
        h("circle", { cx: edge / 2, cy: edge / 2, r: radius, fill: "none", stroke: "var(--dsw-alias-border-l2)", strokeWidth: 8 }),
        h("circle", {
          cx: edge / 2, cy: edge / 2, r: radius, fill: "none", stroke: color, strokeWidth: 8,
          strokeLinecap: "round", strokeDasharray: circumference, strokeDashoffset: circumference * (1 - ratio),
          transform: "rotate(-90 " + edge / 2 + " " + edge / 2 + ")",
        }),
        h("text", { x: "50%", y: "47%", textAnchor: "middle", fill: "var(--dsw-alias-label-primary)", fontSize: 20, fontWeight: 700 }, String(score ?? "—")),
        h("text", { x: "50%", y: "65%", textAnchor: "middle", fill: "var(--dsw-alias-label-tertiary)", fontSize: 10 }, "风险分"),
      );
    }

    function SepChip({ label, value, tone }) {
      return h("span", { className: "sf-chip" + (tone ? " " + tone : "") }, label, " ", h("b", null, value));
    }

    function CoverageChip({ coverage }) {
      if (coverage === null || coverage === undefined) return null;
      const state = coverage.state || "incomplete";
      const tone = state === "complete" ? "ok" : (state === "partial" ? "warn" : "bad");
      const text = state === "complete" ? "覆盖完整" : (state === "partial" ? "部分覆盖" : "不完整");
      return h("span", { className: "sf-chip " + tone, title: coverage.taxonomyPath || "" },
        text + " · " + (coverage.coveredSubcodes ?? 0) + "/" + (coverage.totalSubcodes ?? 0));
    }

    function FindingRow({ finding, selected, onClick, onCopy }) {
      const sev = severityKey(finding);
      return h("div", { className: "sf-finding" + (selected ? " sel" : ""), onClick, role: "button", tabIndex: 0 },
        h("span", { className: "sf-code", style: { background: CODE_COLOR(finding.code) } }, finding.code),
        h("span", { className: "sf-sev", style: { color: COLORS[sev] || COLORS.low } }, finding.state === "benign" ? "已标记可接受" : (SEVERITY_CN[sev] || sev)),
        h("span", { className: "sf-ev", title: finding.evidence }, finding.evidence),
        h("span", { className: "sf-seq" }, "#" + finding.seq),
        h("button", {
          className: "sf-btn", title: "复制深链",
          onClick: (event) => { event.stopPropagation(); onCopy(finding); },
        }, h(Icon, { name: "link", size: 12 })),
      );
    }

    /* ------------------------------------------------------------- panel */

    function Panel({ ctx, ...props }) {
      ensureStyle();
      const { toast, push } = useToast();
      const [selectedSession, setSelectedSession] = useState("");
      const [view, setView] = useState("overview");
      const [selectedFinding, setSelectedFinding] = useState(null);
      const [selectedStep, setSelectedStep] = useState(0);
      const [categoryFilter, setCategoryFilter] = useState("");
      const [severityFilter, setSeverityFilter] = useState("");
      const [showBlind, setShowBlind] = useState(false);

      const sessions = useRemote(() => api("/sessions?limit=100"), []);
      useEffect(() => {
        if (selectedSession.length > 0) return;
        const first = sessions.data?.sessions?.[0];
        if (first !== undefined) setSelectedSession(first.sessionId);
      }, [sessions.data, selectedSession]);

      const report = useRemote(
        () => (selectedSession.length === 0 ? Promise.resolve({ report: null }) : api("/session?sessionId=" + encodeURIComponent(selectedSession))),
        [selectedSession],
      );
      const chain = useRemote(
        () => (selectedSession.length === 0 ? Promise.resolve({ chain: null }) : api("/chain?sessionId=" + encodeURIComponent(selectedSession))),
        [selectedSession],
      );
      const catalog = useRemote(() => api("/rules"), []);

      const data = report.data?.report || null;
      const findings = useMemo(() => (data?.findings || []).filter((item) => {
        if (categoryFilter.length > 0 && item.category !== categoryFilter) return false;
        if (severityFilter.length > 0 && severityKey(item) !== severityFilter) return false;
        return true;
      }), [data, categoryFilter, severityFilter]);

      const copyLink = useCallback(async (finding) => {
        const link = location.origin + location.pathname + hashFor({ sessionId: selectedSession, seq: finding.seq, findingId: finding.id });
        const done = await copyText(link);
        push(done ? "已复制深链" : "复制失败");
      }, [selectedSession, push]);

      const rescan = useCallback(async () => {
        if (selectedSession.length === 0) return;
        try {
          await api("/session?sessionId=" + encodeURIComponent(selectedSession) + "&force=1");
          await report.reload();
          await chain.reload();
          await sessions.reload(true);
          push("已重新扫描");
        } catch (error) {
          push("重扫失败：" + (error.message || error));
        }
      }, [selectedSession, report, chain, sessions, push]);

      const exportJson = useCallback(async () => {
        if (data === null) return;
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement("a");
        anchor.href = url;
        anchor.download = "safety-" + shortId(selectedSession) + ".json";
        anchor.click();
        URL.revokeObjectURL(url);
        push("已导出 JSON");
      }, [data, selectedSession, push]);

      const labelFinding = useCallback(async (finding, mark) => {
        try {
          await api("/label", { method: "POST", body: JSON.stringify({ findingId: finding.id, mark }) });
          await report.reload(true);
          push(mark === "benign" ? "已标记为可接受" : "已确认违规");
        } catch (error) {
          push("标注失败：" + (error.message || error));
        }
      }, [report, push]);

      useEffect(() => {
        function onKey(event) {
          if (event.target instanceof HTMLElement && /input|textarea|select/i.test(event.target.tagName)) return;
          if (view !== "findings") return;
          const index = findings.findIndex((item) => item.id === selectedFinding?.id);
          if (event.key === "j" || event.key === "k") {
            const next = event.key === "j" ? Math.min(findings.length - 1, index + 1) : Math.max(0, index - 1);
            if (findings[next] !== undefined) setSelectedFinding(findings[next]);
            event.preventDefault();
          }
          if ((event.key === "Enter" || event.key === " ") && selectedFinding !== null) {
            openLink({ sessionId: selectedSession, seq: selectedFinding.seq, findingId: selectedFinding.id });
            event.preventDefault();
          }
          if (event.key === "Escape") setSelectedFinding(null);
        }
        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
      }, [view, findings, selectedFinding, selectedSession]);

      const meta = sessions.data?.sessions?.find((item) => item.sessionId === selectedSession) || null;
      const tabs = [
        { id: "overview", label: "总览" },
        { id: "findings", label: "风险清单" + (data !== null ? " " + (data.findings || []).filter((item) => item.state !== "benign").length : "") },
        { id: "settings", label: "设置" },
      ];

      return h("div", { className: "sf-root" },
        h("div", { className: "sf-head" },
          h("div", { className: "sf-title" }, h(Icon, { name: "shield", size: 17 }), "安全巡检"),
          h("span", { className: "sf-sub", title: selectedSession }, selectedSession ? shortId(selectedSession) : "选择会话"),
          data !== null ? h(CoverageChip, { coverage: data.coverage }) : null,
          h("div", { style: { flex: 1 } }),
          h("button", { className: "sf-btn", onClick: () => { void sessions.reload(); void report.reload(); void chain.reload(); }, title: "刷新" },
            h(Icon, { name: "refresh", size: 13 })),
          h("button", { className: "sf-btn", onClick: rescan, disabled: report.loading }, "重扫"),
        ),
        h("div", { className: "sf-body" },
          h("div", { className: "sf-rail" },
            h("div", { className: "sf-railHead" },
              "会话 ", h("b", null, sessions.data?.sessions?.length ?? "—"),
              h("div", { style: { flex: 1 } }),
              sessions.error !== null ? h("span", { style: { color: COLORS.critical } }, "加载失败") : null,
            ),
            h("div", { className: "sf-railList" },
              (sessions.data?.sessions || []).map((session) => h("div", {
                key: session.sessionId,
                className: "sf-srow" + (session.sessionId === selectedSession ? " on" : ""),
                onClick: () => { setSelectedSession(session.sessionId); setSelectedFinding(null); setSelectedStep(0); },
              },
                h("div", { className: "t" },
                  h("span", { className: "sf-dot", style: { background: riskColor(session.riskLevel) } }),
                  shortId(session.sessionId),
                  session.cwd ? h("span", { style: { color: "var(--dsw-alias-label-tertiary)", fontSize: 10, overflow: "hidden", textOverflow: "ellipsis" } },
                    String(session.cwd).split(/[\\/]/).filter(Boolean).slice(-1)[0]) : null,
                ),
                h("div", { className: "m" },
                  h("span", null, (session.events ?? "—") + " ev"),
                  h("span", null, (session.toolCalls ?? "—") + " calls"),
                  h("span", null, (session.findings ?? "—") + " 发现"),
                  h("span", { style: { color: riskColor(session.riskLevel) } }, session.riskLevel || "—"),
                ),
              )),
              (sessions.data?.sessions || []).length === 0 && sessions.loading !== true
                ? h("div", { className: "sf-empty" }, h("div", { className: "big" }, "🛡"), h("div", null, "没有找到可审计的会话"))
                : null,
            ),
          ),
          h("div", { className: "sf-main" },
            h("div", { className: "sf-tabs" }, tabs.map((tab) => h("div", {
              key: tab.id,
              className: "sf-tab" + (view === tab.id ? " on" : ""),
              onClick: () => setView(tab.id),
            }, tab.label))),
            h("div", { className: "sf-view" },
              report.error !== null ? h("div", { className: "sf-card", style: { borderColor: COLORS.critical } }, "读取失败：" + report.error) : null,
              data === null && report.loading === true ? h("div", { className: "sf-empty" }, "正在扫描…") : null,
              data === null && report.loading !== true ? h("div", { className: "sf-empty" }, h("div", { className: "big" }, "🛡"), h("div", null, "选择左侧的会话开始巡检")) : null,
              data !== null && view === "overview" ? h(Overview, {
                data, meta, onRescan: rescan, onExport: exportJson,
                chain: chain.data?.chain || null,
                onOpenTurn: (turn) => openLink({ sessionId: selectedSession, turn }),
                onCategory: (code) => { setCategoryFilter(code === categoryFilter ? "" : code); setView("findings"); },
                onSeverity: (key) => { setSeverityFilter(key === severityFilter ? "" : key); setCategoryFilter(""); setView("findings"); },
                onPick: (finding) => { setSelectedFinding(finding); openLink({ sessionId: selectedSession, seq: finding.seq, findingId: finding.id }); },
                showBlind, toggleBlind: () => setShowBlind((value) => !value),
              }) : null,
              data !== null && view === "findings" ? h(FindingsView, {
                data, findings, selected: selectedFinding,
                onSelect: setSelectedFinding,
                onOpen: (finding) => {
                  setSelectedFinding(finding);
                  openLink({ sessionId: selectedSession, seq: finding.seq, findingId: finding.id });
                },
                onCopy: copyLink, onLabel: labelFinding,
                categoryFilter, severityFilter,
                onCategory: setCategoryFilter, onSeverity: setSeverityFilter,
              }) : null,
              view === "settings" ? h(SettingsView, { push, onSaved: () => { void report.reload(); } }) : null,
            ),
          ),
        ),
        toast !== null ? h("div", { className: "sf-toast" }, toast.message) : null,
      );
    }

    /* ---------------------------------------------------------- overview */

    function Overview({ data, meta, onRescan, onExport, onCategory, onSeverity, onPick, onOpenTurn, chain, showBlind, toggleBlind }) {
      const maxCount = Math.max(1, ...(data.byCategory || []).map((row) => row.count));
      const findingSeqs = new Set((data.findings || []).filter((item) => item.state !== "benign").map((item) => item.seq));
      const total = data.stats?.events || 0;
      const ticks = Math.min(1200, Math.max(1, total));
      const heat = [];
      for (let index = 0; index < ticks; index += 1) {
        const seq = Math.round((index / ticks) * total);
        heat.push(h("i", { key: index, className: findingSeqs.has(seq) ? "hit" : "", title: "seq " + seq }));
      }
      const top = (data.findings || []).filter((item) => item.state !== "benign").slice(0, 10);
      const chip = (label, key, count, tone) => h("button", {
        type: "button",
        className: "sf-chip" + (tone ? " " + tone : ""),
        style: { border: "none", cursor: "pointer", font: "inherit" },
        title: "只看 " + label + " 的发现",
        onClick: () => onSeverity(key),
      }, label, " ", h("b", null, count));
      return h("div", null,
        h("div", { className: "sf-card" },
          h("div", { className: "sf-row" },
            h(RiskRing, { score: data.riskScore, level: data.riskLevel }),
            h("div", { className: "sf-kv" },
              h("b", { style: { color: riskColor(data.riskLevel) } }, data.riskLevel + " · " + (data.riskScore ?? "—")),
              h("span", null, "结论 " + ({ fail: "存在严重发现", warn: "需要关注", pass: "未发现违规" }[data.verdict] || data.verdict)),
            ),
            h("div", { style: { width: 1, height: 46, background: "var(--dsw-alias-border-l1)" } }),
            h("div", { className: "sf-row", style: { gap: 6 } },
              chip("严重", "critical", data.counts?.critical ?? 0, "bad"),
              chip("高", "high", data.counts?.high ?? 0, "warn"),
              chip("中", "medium", data.counts?.medium ?? 0, ""),
              chip("低", "low", data.counts?.low ?? 0, ""),
              h(SepChip, { label: "已标记", value: data.counts?.info ?? 0 }),
            ),
            h("div", { style: { flex: 1 } }),
            h("div", { className: "sf-kv", style: { alignItems: "flex-end" } },
              h("span", null, "事件 " + (data.stats?.events ?? 0) + " · 调用 " + (data.stats?.toolCalls ?? 0) + " · 失败 " + (data.stats?.errors ?? 0)),
              h("span", null, "扫描于 " + fmtTime(Date.parse(data.generatedAt))),
              h("span", { title: data.coverage?.taxonomyPath || "" },
                "分类体系 " + (data.coverage?.taxonomyFallback ? "缺失（内置兜底）" : "已加载") + " · 覆盖 " + (data.coverage?.coveredSubcodes ?? 0) + "/" + (data.coverage?.totalSubcodes ?? 0)),
            ),
            h("button", { className: "sf-btn", onClick: onExport }, "导出 JSON"),
          ),
        ),
        h("div", { className: "sf-card" },
          h("div", { className: "sf-k" }, "按类分布（点击筛选）"),
          (data.byCategory || []).map((row) => h("div", { key: row.code, className: "sf-bar", onClick: () => onCategory(row.code) },
            h("div", { className: "n" }),
            h("span", { className: "sf-dot", style: { background: CODE_COLOR(row.code) } }),
            h("span", { style: { width: "auto" } }, row.code + " " + row.name),
            h("div", { className: "track" }, h("div", { className: "fill", style: { width: (row.count / maxCount) * 100 + "%", background: CODE_COLOR(row.code) } })),
            h("span", { className: "c" }, row.count),
          )),
          h("div", { className: "sf-k", style: { marginTop: 10 } }, "事件时间轴（红色为发现位置）"),
          h("div", { className: "sf-heat" }, heat),
        ),
        h("div", { className: "sf-card" },
          h("div", { className: "sf-k" }, "Top 发现"),
          top.length === 0
            ? h("div", { className: "sf-muted" }, "本次未发现。已覆盖 " + (data.coverage?.coveredSubcodes ?? 0) + "/" + (data.coverage?.totalSubcodes ?? 0) + " 子类，未覆盖项见下方盲区。")
            : top.map((finding) => h("div", { key: finding.id, className: "sf-finding", onClick: () => onPick(finding) },
                h("span", { className: "sf-code", style: { background: CODE_COLOR(finding.code) } }, finding.code),
                h("span", { className: "sf-sev", style: { color: COLORS[severityKey(finding)] } }, SEVERITY_CN[severityKey(finding)]),
                h("span", { className: "sf-ev", title: finding.evidence }, finding.evidence),
                h("span", { className: "sf-seq" }, "#" + finding.seq),
              )),
        ),
        h("div", { className: "sf-card" },
          h("div", { className: "sf-row", style: { justifyContent: "space-between" } },
            h("div", { className: "sf-k" }, "整体判断"),
            (() => {
              const findings = (data.findings || []).filter((item) => item.state !== "benign");
              const byCode = new Map();
              for (const item of findings) {
                const entry = byCode.get(item.code) || { code: item.code, name: item.codeName, count: 0, severity: item.severity };
                entry.count += 1;
                if ((SEVERITY_RANK[item.severity] ?? 0) > (SEVERITY_RANK[entry.severity] ?? 0)) entry.severity = item.severity;
                byCode.set(item.code, entry);
              }
              const worst = [...byCode.values()].sort((a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0) || b.count - a.count);
              const top = worst.slice(0, 4);
              const turns = new Map();
              for (const item of findings) {
                const turn = turnOfSeq(chain, item.seq);
                if (turn === null) continue;
                turns.set(turn, (turns.get(turn) || 0) + 1);
              }
              const hotTurns = [...turns.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
              return h("div", null,
                h("div", { style: { fontSize: 13, lineHeight: 1.7, marginTop: 4 } },
                  "本会话共 " + (data.stats?.toolCalls ?? 0) + " 次工具调用，检出 " + findings.length + " 条风险：严重 " +
                  (data.counts?.critical ?? 0) + "、高 " + (data.counts?.high ?? 0) + "、中 " + (data.counts?.medium ?? 0) + "。",
                  top.length === 0 ? "未命中任何规则，但未覆盖的子类仍属盲区。" :
                    "主要集中在 " + top.map((item) => item.code + " " + item.name + "（" + item.count + "）").join("、") + "。",
                  hotTurns.length === 0 ? "" : "风险最集中的轮次是 " + hotTurns.slice(0, 3).map(([turn, count]) => "T" + turn + "（" + count + " 条）").join("、") + "。",
                ),
                hotTurns.length === 0 ? null : h("div", { className: "sf-row", style: { gap: 6, marginTop: 8, flexWrap: "wrap" } },
                  hotTurns.map(([turn, count]) => h("button", {
                    key: turn, className: "sf-btn", onClick: () => onOpenTurn(turn),
                  }, "T" + turn + " · " + count + " 条风险")),
                ),
              );
            })(),
          ),
        ),
        h("div", { className: "sf-card" },
          h("div", { className: "sf-row", style: { justifyContent: "space-between" } },
            h("div", { className: "sf-k" }, "盲区（未覆盖 " + (data.blindSpots || []).length + " 个子类）"),
            h("button", { className: "sf-btn", onClick: toggleBlind }, showBlind ? "收起" : "展开"),
          ),
          h("div", { className: "sf-muted", style: { marginTop: 4 } }, "未覆盖不等于安全。以下是本次规则无法判定的子类，需要 judge / 环境侧证据 / 人工。"),
          showBlind ? h("div", { className: "sf-blind" }, (data.blindSpots || []).map((item) => h("span", {
            key: item.code, title: (item.detect || []).join(" / "),
          }, item.code + " " + item.name + " · " + ((item.detect || []).join("/") || "?")))) : null,
        ),
      );
    }

    /* ---------------------------------------------------------- findings */


    function FindingsView({ data, findings, selected, onSelect, onOpen, onCopy, onLabel, categoryFilter, severityFilter, onCategory, onSeverity }) {
      const categories = useMemo(() => {
        const codes = new Map();
        for (const finding of data.findings || []) codes.set(finding.category, finding.categoryName || finding.category);
        return [...codes.entries()];
      }, [data]);
      const groups = useMemo(() => {
        const order = ["critical", "high", "medium", "low", "info"];
        const buckets = new Map(order.map((key) => [key, []]));
        for (const finding of findings) {
          const key = severityKey(finding);
          if (!buckets.has(key)) buckets.set(key, []);
          buckets.get(key).push(finding);
        }
        return order.map((key) => ({ key, label: SEVERITY_CN[key] || key, items: buckets.get(key) })).filter((group) => group.items.length > 0);
      }, [findings]);
      return h("div", null,
        h("div", { className: "sf-row", style: { marginBottom: 8 } },
          h("select", { className: "sf-btn", value: categoryFilter, onChange: (event) => onCategory(event.target.value) },
            h("option", { value: "" }, "全部类别"),
            categories.map(([code, name]) => h("option", { key: code, value: code }, code + " " + name)),
          ),
          h("select", { className: "sf-btn", value: severityFilter, onChange: (event) => onSeverity(event.target.value) },
            h("option", { value: "" }, "全部严重度"),
            Object.keys(SEVERITY_CN).map((key) => h("option", { key, value: key }, SEVERITY_CN[key])),
          ),
          h("span", { className: "sf-muted" }, findings.length + " 条"),
          h("div", { style: { flex: 1 } }),
          h("span", { className: "sf-muted" }, "点任意一条看证据与所属风险类型"),
        ),
        selected !== null && selected !== undefined
          ? h(FindingDetail, { finding: selected, data, onOpen, onCopy, onLabel, onClose: () => onSelect(null) })
          : null,
        groups.map((group) => h("div", { key: group.key, style: { marginBottom: 12 } },
          h("div", { className: "sf-row", style: { gap: 6, marginBottom: 4 } },
            h("span", { className: "sf-dot", style: { background: COLORS[group.key] || COLORS.low } }),
            h("b", { style: { fontSize: 12 } }, group.label),
            h("span", { className: "sf-muted" }, group.items.length + " 条"),
            h("div", { style: { flex: 1, height: 1, background: "var(--dsw-alias-border-l1)" } }),
          ),
          group.items.map((finding) => h(FindingRow, {
            key: finding.id, finding, selected: selected?.id === finding.id,
            onClick: () => { onSelect(finding); onOpen(finding); }, onCopy,
          })),
        )),
        findings.length === 0 ? h("div", { className: "sf-empty" }, h("div", { className: "big" }, "✓"), h("div", null, "当前筛选下没有发现")) : null,
      );
    }

    function FindingDetail({ finding, data, onOpen, onCopy, onLabel, onClose }) {
      const sev = severityKey(finding);
      const related = (data.stats?.turns || []).flatMap((turn) => turn.callIds || []);
      return h("div", { className: "sf-card", style: { borderColor: COLORS[sev] } },
        h("div", { className: "sf-row", style: { justifyContent: "space-between" } },
          h("div", { className: "sf-row" },
            h("span", { className: "sf-code", style: { background: CODE_COLOR(finding.code) } }, finding.code),
            h("b", null, finding.codeName || finding.name || finding.code),
            h("span", { className: "sf-sev", style: { color: COLORS[sev] } }, SEVERITY_CN[sev] + " · " + (finding.reversible || "?")),
            h("span", { className: "sf-seq" }, "seq #" + finding.seq),
          ),
          h("button", { className: "sf-btn", onClick: onClose }, h(Icon, { name: "close", size: 12 })),
        ),
        h("div", { className: "sf-muted", style: { margin: "6px 0" } }, finding.definition || "（taxonomy 未给出定义）"),
        h("div", { className: "sf-code-box" }, finding.evidence),
        h("div", { className: "sf-row", style: { marginTop: 8 } },
          h("span", { className: "sf-muted" }, "规则 " + finding.ruleId + " · 置信度 " + finding.confidence + " · 工具 " + (finding.callId || "—")),
          h("div", { style: { flex: 1 } }),
          h("button", { className: "sf-btn", onClick: () => onCopy(finding) }, h(Icon, { name: "link", size: 12 }), " 复制深链"),
          h("button", { className: "sf-btn", onClick: () => onOpen(finding) }, "在时间轴打开"),
          h("button", { className: "sf-btn", onClick: () => onLabel(finding, "benign") }, "标记误报"),
          h("button", { className: "sf-btn primary", onClick: () => onLabel(finding, "confirmed") }, "确认违规"),
        ),
        related.length === 0 ? null : h("div", { className: "sf-muted", style: { marginTop: 6 } }, "该会话共 " + related.length + " 次工具调用，可在「执行链」中按 seq 定位。"),
      );
    }

    /* ------------------------------------------------------------- chain */


    /* ----------------------------------------------------- plain language */

    const RISK_COLOR = { none: "#8f8f8f", 无: "#8f8f8f", 低: "#12a594", 中: "#f5a524", 高: "#f76b15", 严重: "#e5484d" };
    const SEVERITY_RANK = { info: 0, 低: 1, 中: 2, 高: 3, 严重: 4 };

    /** Which turn does this event seq belong to? Falls back to the seq range. */
    function turnOfSeq(chain, seq) {
      const turns = (chain && chain.turns) || [];
      if (turns.length === 0) return null;
      const hit = turns.find((turn) => (turn.calls || []).some((call) => call.callSeq === seq || call.resultSeq === seq));
      if (hit !== undefined) return hit.turn ?? null;
      const group = (chain.turnGroups || []).find((item) => seq >= (item.firstSeq ?? 0) && seq <= (item.lastSeq ?? 0));
      return group === undefined ? null : (group.turn ?? null);
    }

    function riskChip(level) {
      const key = level && level !== "none" ? level : "无";
      return h("span", {
        className: "sf-sev",
        style: { color: RISK_COLOR[key] || RISK_COLOR["无"], borderColor: RISK_COLOR[key] || RISK_COLOR["无"] },
      }, key);
    }

    function findingsOfCalls(findings, calls) {
      const ids = new Set((calls || []).map((call) => call.callId));
      return (findings || []).filter((item) => ids.has(item.callId));
    }

    function worstLevel(list) {
      const order = { 无: 0, 低: 1, 中: 2, 高: 3, 严重: 4 };
      let level = "无";
      for (const item of list) {
        const mapped = SEVERITY_CN[severityKey(item)] || "无";
        if ((order[mapped] ?? 0) > (order[level] ?? 0)) level = mapped;
      }
      return level;
    }

    /** One call, described for a non-technical reader. */
    function CallCard({ call, findings, showRaw, onToggleRaw }) {
      const narration = call.narration || null;
      const own = findingsOfCalls(findings, [call]);
      const level = narration ? narration.risk.level : worstLevel(own);
      const shownLevel = level === "none" ? "无" : level;
      const access = narration ? narration.access : { reads: [], writes: [], domains: [], queries: [], command: "" };
      return h("div", { className: "sf-card", style: { marginBottom: 8, borderColor: call.isError === true ? COLORS.critical : undefined } },
        h("div", { className: "sf-row", style: { justifyContent: "space-between" } },
          h("div", { className: "sf-row", style: { gap: 6 } },
            h("b", null, call.name),
            h("span", { className: "sf-muted" }, narration ? narration.toolLabel : ""),
            call.isError === true ? h("span", { className: "sf-chip bad" }, "这一步失败了") : null,
            riskChip(shownLevel),
          ),
          h("button", { className: "sf-btn", onClick: onToggleRaw }, showRaw ? "看通俗版" : "看原始数据"),
        ),
        h("div", { className: "sf-k", style: { marginTop: 6 } }, "请求"),
        h("div", null, narration ? narration.request : "（无摘要）"),
        h("div", { className: "sf-k", style: { marginTop: 6 } }, "结果"),
        h("div", { style: { color: call.isError === true ? COLORS.critical : undefined } },
          narration ? (narration.result.kind + (narration.result.detail ? "，" + narration.result.detail : "")) : ""),
        h("div", { className: "sf-k", style: { marginTop: 6 } }, "访问的数据"),
        h("div", { className: "sf-row", style: { gap: 4, flexWrap: "wrap" } },
          (access.reads || []).map((value) => h("span", { key: "r" + value, className: "sf-tool", title: value }, "读 " + String(value).split(/[\\/]/).pop())),
          (access.writes || []).map((value) => h("span", { key: "w" + value, className: "sf-tool", title: value }, "写 " + String(value).split(/[\\/]/).pop())),
          (access.domains || []).map((value) => h("span", { key: "d" + value, className: "sf-tool" }, "域名 " + value)),
          (access.queries || []).map((value) => h("span", { key: "q" + value, className: "sf-tool" }, "检索 " + value)),
          (access.reads || []).length + (access.writes || []).length + (access.domains || []).length + (access.queries || []).length === 0
            ? h("span", { className: "sf-muted" }, access.command ? "命令内部访问，日志里看不到具体文件" : "没有记录到明显的文件或网络访问")
            : null,
        ),
        h("div", { className: "sf-k", style: { marginTop: 6 } }, "风险判定"),
        h("div", { className: "sf-row", style: { gap: 6, flexWrap: "wrap" } },
          narration ? h("span", { className: "sf-sev", style: { color: RISK_COLOR[shownLevel] } }, narration.risk.verdict) : null,
          narration && narration.risk.sensitive ? h("span", { className: "sf-chip bad" }, "涉及敏感数据") : null,
          narration ? h("span", { className: "sf-chip" + (narration.risk.compliant ? " ok" : " bad") }, narration.risk.compliant ? "合规" : "不合规") : null,
          (narration ? narration.risk.codes : own.map((item) => item.code)).map((code) => h("span", {
            key: code, className: "sf-code", style: { background: CODE_COLOR(code) },
          }, code)),
        ),
        narration && narration.risk.reasons.length > 0
          ? h("div", { className: "sf-muted", style: { marginTop: 4 } }, narration.risk.reasons.join("；"))
          : null,
        showRaw
          ? h("div", null,
              h("div", { className: "sf-k", style: { marginTop: 8 } }, "原始请求"),
              h("div", { className: "sf-code-box" }, call.args),
              h("div", { className: "sf-k", style: { marginTop: 6 } }, "原始结果"),
              h("div", { className: "sf-code-box" }, call.result || "（无结果记录）"),
            )
          : null,
      );
    }

    /** A turn's AI analysis, rendered only after the user asks for it. */
    function AnalysisBlock({ analysis, onRun, onRerun, busy, error, cached }) {
      if (analysis === null) {
        return h("div", { className: "sf-card" },
          h("div", { className: "sf-row", style: { justifyContent: "space-between" } },
            h("div", null,
              h("div", { className: "sf-k" }, "AI 详细分析"),
              h("div", { className: "sf-muted", style: { marginTop: 3 } },
                "默认不消耗 token：上面的说明由本地规则生成。需要逐条点评时可以点右侧按钮，本次会调用一次模型。"),
            ),
            h("button", { className: "sf-btn primary", onClick: onRun, disabled: busy === true },
              busy === true ? "分析中…" : "AI 详细分析（消耗 token）"),
          ),
          error !== null ? h("div", { className: "sf-muted", style: { color: COLORS.critical, marginTop: 6 } }, "分析失败：" + error) : null,
        );
      }
      return h("div", { className: "sf-card" },
        h("div", { className: "sf-row", style: { justifyContent: "space-between" } },
          h("div", { className: "sf-k" }, "AI 详细分析"),
          h("div", { className: "sf-row", style: { gap: 6 } },
            h("span", { className: "sf-chip" + (cached ? " ok" : "") }, cached ? "已缓存" : "本次调用"),
            h("button", { className: "sf-btn", onClick: onRerun, disabled: busy === true }, busy === true ? "分析中…" : "重新分析（再消耗一次）"),
          ),
        ),
        h("div", { className: "sf-muted", style: { marginTop: 4 } }, analysis.verdict || ""),
        (analysis.steps || []).map((step) => h("div", { key: step.callId, style: { marginTop: 8, paddingTop: 6, borderTop: "1px solid var(--dsw-alias-border-l1)" } },
          h("div", { className: "sf-row", style: { gap: 6 } },
            h("span", { className: "sf-tool" }, step.callId.slice(-6)),
            riskChip(step.risk.level),
            step.risk.sensitive ? h("span", { className: "sf-chip bad" }, "敏感") : null,
            step.risk.category !== "无" ? h("span", { className: "sf-code", style: { background: CODE_COLOR(step.risk.category) } }, step.risk.category) : null,
          ),
          h("div", { style: { marginTop: 3 } }, step.what),
          h("div", { className: "sf-muted" }, "请求：" + step.request + " · 结果：" + step.result + " · 数据：" + step.data),
          h("div", { className: "sf-muted" }, "判断：" + step.risk.reason),
        )),
        analysis.usage === null || analysis.usage === undefined
          ? h("div", { className: "sf-muted", style: { marginTop: 8 } }, "这一轮没有工具调用，无需分析（0 token）")
          : h("div", { className: "sf-muted", style: { marginTop: 8 } },
              "本次消耗：提示词约 " + (analysis.usage.promptTokens ?? 0) + " token（" + (analysis.usage.promptChars ?? 0) + " 字符）"
              + " · 输出 " + analysis.usage.outputTokens + " token"
              + (analysis.usage.exactOutput ? "（服务端上报）" : "（按字数估算）")
              + (analysis.ms ? " · " + analysis.ms + "ms" : "")),
      );
    }

    function ChainView({ chain, selected, onSelect, findings, sessionId }) {
      const [pickedCall, setPickedCall] = useState(null);
      const [showAllCalls, setShowAllCalls] = useState(false);
      const [showRaw, setShowRaw] = useState(false);
      const [onlyFailed, setOnlyFailed] = useState(false);
      const [analysis, setAnalysis] = useState(null);
      const [analysisBusy, setAnalysisBusy] = useState(false);
      const [analysisError, setAnalysisError] = useState(null);
      const jumped = useRef(false);
      useEffect(() => {
        if (jumped.current === true) return;
        const rows = chain?.turns || [];
        if (rows.length === 0) return;
        jumped.current = true;
        const hasFailure = rows.findIndex((step) => (step.calls || []).some((call) => call.isError === true));
        const firstWithCalls = rows.findIndex((step) => (step.calls || []).length > 0);
        if (hasFailure >= 0) { onSelect(hasFailure); return; }
        if (firstWithCalls >= 0) { onSelect(firstWithCalls); }
      }, [chain]);
      if (chain === null) return h("div", { className: "sf-empty" }, "正在读取事件流…");
      const steps = chain.turns || [];
      const current = steps[selected] || steps[0] || null;
      const currentCalls = current !== null ? (current.calls || []) : [];
      const turnSteps = steps.filter((item) => (item.turn ?? null) === (current?.turn ?? null));
      const turnCalls = turnSteps.flatMap((item) => item.calls || []);
      const failures = turnCalls.filter((call) => call.isError === true);
      const failingCall = failures[0] || null;
      const failingStepIndex = failingCall === null ? -1 : steps.findIndex((step) => (step.calls || []).some((call) => call.callId === failingCall.callId));
      const effectiveCalls = currentCalls.length > 0 ? currentCalls : turnCalls;

      const runAnalysis = async (force) => {
        setAnalysisBusy(true);
        setAnalysisError(null);
        try {
          const body = await api("/analyze", {
            method: "POST",
            body: JSON.stringify({ sessionId, turn: current?.turn ?? null, force: force === true }),
          });
          setAnalysis(body.analysis);
        } catch (error) {
          setAnalysisError(String(error && error.message ? error.message : error));
        } finally {
          setAnalysisBusy(false);
        }
      };

      return h("div", { className: "sf-chain" },
        h("div", { className: "sf-steps" },
          failures.length > 0 ? h("div", { className: "sf-row", style: { padding: "6px 8px", gap: 6 } },
            h("button", {
              className: "sf-btn" + (onlyFailed ? " primary" : ""),
              onClick: () => { setOnlyFailed((value) => !value); if (failingStepIndex >= 0) { onSelect(failingStepIndex); setPickedCall(failingCall.callId); } },
            }, "只看失败（" + failures.length + "）"),
          ) : null,
          steps.map((step, index) => {
            const own = findingsOfCalls(findings, step.calls || []);
            const level = worstLevel(own);
            const failed = (step.calls || []).some((call) => call.isError === true);
            if (onlyFailed && !failed) return null;
            return h("div", {
              key: index,
              className: "sf-step" + (index === selected ? " on" : ""),
              style: failed ? { borderLeftColor: COLORS.critical } : undefined,
              onClick: () => { onSelect(index); setPickedCall(null); },
            },
              h("div", { className: "hd" },
                h("span", null, (step.turn === null ? "系统" : "T" + step.turn) + " · S" + (step.step ?? "—")),
                failed ? h("span", { className: "sf-badge-fail" }, "失败") : null,
                level !== "无" ? riskChip(level) : null,
              ),
              h("div", { className: "tl" },
                h("span", { className: "sf-muted" }, step.narration ? step.narration.headline : (step.calls || []).map((call) => call.name).join(" ")),
              ),
            );
          }),
          steps.length === 0 ? h("div", { className: "sf-muted", style: { padding: 12 } }, "这条会话没有可展开的调用") : null,
        ),
        h("div", { className: "sf-insp" },
          current === null ? null : h(React.Fragment, null,
            h("div", { className: "sf-row", style: { justifyContent: "space-between" } },
              h("div", null,
                h("div", { className: "sf-k" }, "这一步做了什么"),
                h("div", null, current.narration ? current.narration.headline : ""),
                h("div", { className: "sf-muted" }, "共 " + (current.calls || []).length + " 个调用" + (currentCalls.length === 0 ? "（本步是纯文本回复，下面展开整轮）" : "")),
              ),
              current.narration ? riskChip(current.narration.level === "none" ? "无" : current.narration.level) : null,
            ),
            h("div", { className: "sf-row", style: { gap: 6, flexWrap: "wrap", marginTop: 6 } },
              effectiveCalls.map((call) => h("button", {
                key: call.callId,
                className: "sf-btn" + (pickedCall === call.callId || (pickedCall === null && effectiveCalls[0] === call) ? " primary" : ""),
                style: call.isError === true ? { borderColor: COLORS.critical, color: COLORS.critical } : undefined,
                onClick: () => setPickedCall(call.callId),
                title: call.narration ? call.narration.request : "",
              }, "S" + (current.step ?? "—") + " " + call.name + (call.isError === true ? " ✕" : ""))),
            ),
            effectiveCalls.length === 0
              ? h("div", { className: "sf-muted", style: { marginTop: 6 } }, "这一轮没有工具调用（纯回答）。")
              : null,
            (() => {
              const chosen = pickedCall !== null
                ? (effectiveCalls.find((call) => call.callId === pickedCall) || effectiveCalls[0])
                : effectiveCalls[0];
              return chosen ? h("div", { style: { marginTop: 8 } },
                h(CallCard, { call: chosen, findings, showRaw, onToggleRaw: () => setShowRaw((value) => !value) }),
              ) : null;
            })(),
            h(AnalysisBlock, {
              analysis,
              busy: analysisBusy,
              error: analysisError,
              cached: analysis?.cached === true,
              onRun: () => runAnalysis(false),
              onRerun: () => runAnalysis(true),
            }),
          ),
        ),
      );
    }

    /* ---------------------------------------------------------- settings */


    function CostPanel() {
      const cost = useRemote(() => api("/cost"), []);
      if (cost.data === null) return h("div", { className: "sf-muted", style: { marginTop: 6 } }, cost.error ?? "读取中…");
      const data = cost.data;
      return h("div", { style: { marginTop: 6, fontSize: 12, color: "var(--dsw-alias-label-secondary)" } },
        h("div", null, "· 扫描 / 渲染 / 查看调用链：", h("b", null, "0 token"), "（全部本地解析）"),
        h("div", null, "· 全局规则：" + (data.promptSection?.enabled ? "已启用，" : "已关闭，") +
          "约 " + (data.promptSection?.estimatedTokens ?? 0) + " token / 轮（" + (data.promptSection?.chars ?? 0) + " 字符）"),
        h("div", null, "· AI 详细分析：只在点按钮时调用，已用 " + (data.totals?.analyses ?? 0) + " 次，累计 提示词约 " +
          (data.totals?.promptTokens ?? 0) + " / 输出 " + (data.totals?.outputTokens ?? 0) + " token"),
        (data.analyses || []).length === 0 ? null : h("div", { style: { marginTop: 6 } },
          (data.analyses || []).slice(0, 5).map((row) => h("div", { key: (row.sessionId ?? "") + row.turn + row.at, className: "sf-muted" },
            "T" + row.turn + " · " + (row.calls ?? 0) + " 个调用 · 提示词约 " + (row.usage?.promptTokens ?? "?") +
            " / 输出 " + (row.usage?.outputTokens ?? "?"))),
        ),
      );
    }

    function SettingsView({ push, onSaved }) {
      const settings = useRemote(() => api("/settings"), []);
      const [draft, setDraft] = useState(null);
      useEffect(() => {
        if (settings.data?.settings !== undefined && draft === null) setDraft(settings.data.settings);
      }, [settings.data, draft]);
      if (draft === null) return h("div", { className: "sf-muted" }, "读取设置…");
      const update = (patch) => setDraft({ ...draft, ...patch });
      const save = async () => {
        try {
          await api("/settings", { method: "POST", body: JSON.stringify(draft) });
          push("设置已保存");
          onSaved();
        } catch (error) {
          push("保存失败：" + (error.message || error));
        }
      };
      return h("div", { className: "sf-card" },
        h("div", { className: "sf-k" }, "设置"),
        h("label", { className: "sf-switch", style: { marginTop: 8 } },
          h("input", { type: "checkbox", checked: draft.autoScan === true, onChange: (event) => update({ autoScan: event.target.checked }) }),
          "自动扫描新会话（打开面板时）"),
        h("label", { className: "sf-switch", style: { marginTop: 6 } },
          h("input", { type: "checkbox", checked: draft.judge === true, onChange: (event) => update({ judge: event.target.checked }) }),
          "启用 judge（默认关；开启后每会话最多调用 1 次模型）"),
        h("label", { className: "sf-switch", style: { marginTop: 6 } },
          h("input", { type: "checkbox", checked: draft.labelBenefits === true, onChange: (event) => update({ labelBenefits: event.target.checked }) }),
          "把已标记的可接受项降级为 info（不隐藏）"),
        h("div", { className: "sf-switch", style: { marginTop: 10 } },
          "保留天数",
          h("input", {
            type: "number", value: draft.retentionDays, min: 1, max: 3650,
            style: { width: 80, background: "transparent", color: "inherit", border: "1px solid var(--dsw-alias-border-l2)", borderRadius: 6, padding: "2px 6px" },
            onChange: (event) => update({ retentionDays: Number(event.target.value) || 90 }),
          }),
          "最多会话",
          h("input", {
            type: "number", value: draft.maxSessions, min: 1, max: 2000,
            style: { width: 80, background: "transparent", color: "inherit", border: "1px solid var(--dsw-alias-border-l2)", borderRadius: 6, padding: "2px 6px" },
            onChange: (event) => update({ maxSessions: Number(event.target.value) || 200 }),
          }),
        ),
        h("div", { className: "sf-muted", style: { marginTop: 10 } }, "分类体系文件：" + (draft.taxonomyPath || "—")),
        h("div", { className: "sf-k", style: { marginTop: 14 } }, "Token 与费用"),
        h("label", { className: "sf-switch", style: { marginTop: 6 } },
          h("input", { type: "checkbox", checked: draft.injectPrompt !== false, onChange: (event) => update({ injectPrompt: event.target.checked }) }),
          "启用全局规则（约 24 token/轮，实时生效；关掉后模型不会主动巡检）"),
        h(CostPanel, null),
        h("div", { className: "sf-row", style: { marginTop: 10 } },
          h("button", { className: "sf-btn primary", onClick: save }, "保存"),
        ),
      );
    }

    /* ----------------------------------------------------------- overlay */


    function Overlay() {
      ensureStyle();
      const [hashKey, setHashKey] = useState(() => (typeof location === "undefined" ? "" : location.hash));
      const state = useMemo(() => parseHash(), [hashKey]);
      const [detail, setDetail] = useState(null);
      const [chain, setChain] = useState(null);
      const [report, setReport] = useState(null);
      const [error, setError] = useState(null);
      const [pickedCall, setPickedCall] = useState(null);
      const [showAllCalls, setShowAllCalls] = useState(false);
      const [showRaw, setShowRaw] = useState(false);
      const [analysis, setAnalysis] = useState(null);
      const [analysisBusy, setAnalysisBusy] = useState(false);
      const [analysisError, setAnalysisError] = useState(null);

      useEffect(() => { setPickedCall(null); setShowRaw(false); setAnalysis(null); setAnalysisError(null); }, [hashKey]);

      // Poll the hash for external navigation, but only re-render when it really
      // changed — a fresh object every 800ms used to reset the picked call.
      useEffect(() => {
        const sync = () => setHashKey((previous) => (typeof location === "undefined" || location.hash === previous ? previous : location.hash));
        window.addEventListener("hashchange", sync);
        const timer = window.setInterval(sync, 800);
        return () => { window.removeEventListener("hashchange", sync); window.clearInterval(timer); };
      }, []);

      useEffect(() => {
        let alive = true;
        if (state === null || !state.sessionId) { setDetail(null); setChain(null); setReport(null); return; }
        setError(null);
        (async () => {
          try {
            const [session, chainData] = await Promise.all([
              api("/session?sessionId=" + encodeURIComponent(state.sessionId)),
              api("/chain?sessionId=" + encodeURIComponent(state.sessionId) + "&resultChars=2000"),
            ]);
            if (!alive) return;
            setReport(session.report);
            setChain(chainData.chain);
            if (state.findingId) {
              setDetail((session.report.findings || []).find((item) => item.id === state.findingId) || null);
            } else if (state.seq !== null) {
              setDetail((session.report.findings || []).find((item) => item.seq === state.seq) || null);
            } else {
              setDetail(null);
            }
          } catch (err) {
            if (alive) setError(String(err && err.message ? err.message : err));
          }
        })();
        return () => { alive = false; };
      }, [state]);

      if (state === null || !state.sessionId) return null;
      const focused = detail;
      const turns = chain?.turns || [];
      const message = state.messageId
        ? turns.flatMap((item) => item.assistants || []).find((item) => item.id === state.messageId) || null
        : null;
      let focusTurn = state.turn !== null ? state.turn : null;
      if (message !== null) {
        focusTurn = message.turn ?? null;
        const group = (chain?.turnGroups || []).find((item) => message.seq >= (item.firstSeq ?? 0) && message.seq <= (item.lastSeq ?? 0));
        if (group !== undefined && (group.calls ?? 0) > 0) focusTurn = group.turn ?? focusTurn;
      }
      if (focusTurn === null && focused !== null) {
        const hit = turns.find((item) => (item.calls || []).some((call) => call.callSeq === focused.seq || call.resultSeq === focused.seq));
        if (hit !== undefined) focusTurn = hit.turn ?? null;
        if (focusTurn === null) {
          const group = (chain?.turnGroups || []).find((item) => focused.seq >= (item.firstSeq ?? 0) && focused.seq <= (item.lastSeq ?? 0));
          if (group !== undefined) focusTurn = group.turn ?? null;
        }
      }
      if (focusTurn === null && turns.length > 0) focusTurn = turns[0].turn ?? null;
      const turnSteps = turns.filter((item) => (item.turn ?? null) === focusTurn);
      const turnCalls = turnSteps.flatMap((step) => (step.calls || []).map((call) => ({ ...call, step: step.step })));
      const turnGroup = (chain?.turnGroups || []).find((group) => (group.turn ?? null) === focusTurn) || null;
      const failures = turnCalls.filter((call) => call.isError === true);
      const auto = turnCalls.find((item) => item.callSeq === state.seq || item.resultSeq === state.seq) || turnCalls[0] || null;
      const shown = pickedCall !== null ? (turnCalls.find((item) => item.callId === pickedCall) || auto) : auto;
      const title = chain === null ? "读取中…" : (focusTurn === null ? "系统与收件" : "T" + focusTurn);
      const findings = report?.findings || [];

      const runAnalysis = async (force) => {
        setAnalysisBusy(true);
        setAnalysisError(null);
        try {
          const body = await api("/analyze", {
            method: "POST",
            body: JSON.stringify({ sessionId: state.sessionId, turn: focusTurn, force: force === true }),
          });
          setAnalysis(body.analysis);
        } catch (err) {
          setAnalysisError(String(err && err.message ? err.message : err));
        } finally {
          setAnalysisBusy(false);
        }
      };

      return h("div", { className: "sf-overlay" },
        h("div", { className: "backdrop", onClick: closeLink }),
        h("div", { className: "sf-drawer" },
          h("div", { className: "top" },
            h(Icon, { name: "shield", size: 16 }),
            h("b", null, "安全巡检"),
            h("span", { className: "sf-sub" }, shortId(state.sessionId)),
            focused !== null ? h("span", { className: "sf-code", style: { background: CODE_COLOR(focused.code) } }, focused.code) : null,
            h("div", { style: { flex: 1 } }),
            h("button", { className: "sf-btn", onClick: () => copyText(location.href) }, "复制链接"),
            h("button", { className: "sf-btn", onClick: closeLink }, h(Icon, { name: "close", size: 12 })),
          ),
          h("div", { className: "body" },
            error !== null ? h("div", { className: "sf-card", style: { borderColor: COLORS.critical } }, "读取失败：" + error) : null,
            report !== null ? h("div", { className: "sf-card" },
              h("div", { className: "sf-row" },
                h(RiskRing, { score: report.riskScore, level: report.riskLevel, size: 72 }),
                h("div", { className: "sf-kv" },
                  h("b", { style: { color: riskColor(report.riskLevel) } }, report.riskLevel + " · " + report.riskScore),
                  h("span", null, "严重 " + (report.counts?.critical ?? 0) + " / 高 " + (report.counts?.high ?? 0) + " / 中 " + (report.counts?.medium ?? 0)),
                  h("span", null, "覆盖 " + (report.coverage?.coveredSubcodes ?? 0) + "/" + (report.coverage?.totalSubcodes ?? 0) + " · " + (report.coverage?.state ?? "")),
                ),
              ),
            ) : null,
            focused !== null ? h("div", { className: "sf-card", style: { borderColor: COLORS[severityKey(focused)] } },
              h("div", { className: "sf-row", style: { justifyContent: "space-between" } },
                h("b", null, focused.codeName + " · " + SEVERITY_CN[severityKey(focused)]),
                h("span", { className: "sf-seq" }, "#" + focused.seq),
              ),
              h("div", { className: "sf-muted", style: { margin: "4px 0" } }, focused.definition || ""),
              h("div", { className: "sf-code-box" }, focused.evidence),
            ) : null,
            h("div", { className: "sf-card" },
              h("div", { className: "sf-row", style: { justifyContent: "space-between" } },
                h("div", { className: "sf-k" }, "这条回答的执行链 · " + title),
                h("div", { className: "sf-row", style: { gap: 6 } },
                  h("span", { className: "sf-muted" },
                    chain === null ? "正在加载事件流"
                      : ((turnGroup?.calls ?? turnCalls.length) + " 次调用 · " + turnSteps.length + " 步" + (failures.length > 0 ? " · " + failures.length + " 失败" : ""))),
                ),
              ),
              message !== null && message.text.trim().length > 0
                ? h("div", { className: "sf-code-box", style: { marginTop: 6, maxHeight: 110 } }, message.text.slice(0, 500))
                : null,
              turnCalls.length === 0
                ? (chain === null
                    ? h("div", { className: "sf-muted", style: { marginTop: 6 } }, "正在读取这条会话的事件流…")
                    : h("div", { className: "sf-muted", style: { marginTop: 6 } }, "这一轮没有工具调用（纯回答）。"))
                : h("div", null,
                    h("div", { className: "sf-row", style: { gap: 5, flexWrap: "wrap", marginTop: 6 } },
                      (showAllCalls ? turnCalls : turnCalls.slice(0, 40)).map((item, index, list) => {
                        const level = worstLevel(findingsOfCalls(findings, [item]));
                        const siblings = list.filter((other) => other.step === item.step && other.name === item.name);
                        const order = siblings.length > 1 ? " ·" + (siblings.indexOf(item) + 1) : "";
                        const tone = level === "无" ? null : RISK_COLOR[level];
                        return h("button", {
                        key: item.callId,
                        className: "sf-btn" + (shown !== null && shown.callId === item.callId ? " primary" : ""),
                        style: item.isError === true
                          ? { borderColor: COLORS.critical, color: COLORS.critical }
                          : (tone !== null ? { borderColor: tone, color: tone } : undefined),
                        title: item.narration ? item.narration.request : "",
                        onClick: () => setPickedCall(item.callId),
                      }, "S" + (item.step ?? "—") + " " + item.name + order + (item.isError === true ? " ✕" : ""));
                      }),
                      turnCalls.length > 40
                        ? h("button", {
                            className: "sf-btn",
                            onClick: () => setShowAllCalls((value) => !value),
                          }, showAllCalls ? "收起" : "+" + (turnCalls.length - 40) + " 个后续调用")
                        : null,
                    ),
                    shown !== null
                      ? h("div", { style: { marginTop: 8 } },
                          h(CallCard, { call: shown, findings, showRaw, onToggleRaw: () => setShowRaw((value) => !value) }),
                        )
                      : null,
                    failures.length > 0
                      ? h("div", { className: "sf-row", style: { gap: 6, marginTop: 4 } },
                          h("span", { className: "sf-chip bad" }, "失败的那一步"),
                          h("button", { className: "sf-btn", onClick: () => setPickedCall(failures[0].callId) },
                            "S" + (failures[0].step ?? "—") + " " + failures[0].name + " · " + (failures[0].narration ? failures[0].narration.request : "")),
                        )
                      : null,
                    h("div", { className: "sf-k", style: { marginTop: 10 } }, "策略上下文"),
                    h("div", { className: "sf-access" },
                      h("span", { className: "lbl" }, "sandbox"), h("span", { className: "val" }, String(chain?.policy?.sandbox ?? "未记录")),
                      h("span", { className: "lbl" }, "approval"), h("span", { className: "val" }, String(chain?.policy?.approval ?? "未记录")),
                      h("span", { className: "lbl" }, "审批"), h("span", { className: "val" },
                        (chain?.approvals || []).length === 0 ? "无审批记录" : (chain.approvals || []).map((item) => item.tool + ":" + (item.outcome || "pending")).join(", ")),
                    ),
                    h(AnalysisBlock, {
                      analysis,
                      busy: analysisBusy,
                      error: analysisError,
                      cached: analysis?.cached === true,
                      onRun: () => runAnalysis(false),
                      onRerun: () => runAnalysis(true),
                    }),
                  ),
            ),
          ),
        ),
      );
    }

    /* --------------------------------------------------------- dock badge */

    function DockBadge({ sessionId, session }) {
      const id = sessionId || session?.sessionId || "";
      const [summary, setSummary] = useState(null);
      const [error, setError] = useState(null);
      useEffect(() => {
        if (!id) return undefined;
        let alive = true;
        const load = async () => {
          try {
            const body = await api("/session?sessionId=" + encodeURIComponent(id));
            if (!alive) return;
            const report = body.report;
            setSummary({
              findings: (report.findings || []).filter((item) => item.state !== "benign").length,
              riskLevel: report.riskLevel,
              covered: report.coverage?.coveredSubcodes ?? 0,
              total: report.coverage?.totalSubcodes ?? 0,
              worst: (report.findings || []).filter((item) => item.state !== "benign")[0]?.severity || "",
            });
            setError(null);
          } catch (err) {
            if (alive) setError(String(err && err.message ? err.message : err));
          }
        };
        void load();
        const timer = window.setInterval(load, 15000);
        return () => { alive = false; window.clearInterval(timer); };
      }, [id]);
      if (!id) return null;
      const worst = summary?.worst || "";
      const tone = worst === "严重" ? "bad" : (worst === "高" ? "warn" : (summary?.findings ? "" : "ok"));
      const text = summary === null
        ? "🛡 巡检…"
        : (summary.findings === 0
            ? "🛡 未发现 · 已覆盖 " + summary.covered + "/" + summary.total
            : "🛡 " + summary.findings + " 项 · 风险 " + (summary.riskLevel || "—"));
      return h("div", { style: { padding: "2px 0 4px", display: "flex", justifyContent: "flex-end" } },
        h("span", {
          className: "sf-badge-line" + (tone ? " " + tone : ""),
          title: error || "点击查看会话安全巡检",
          onClick: () => openLink({ sessionId: id }),
        }, text),
      );
    }

    function AssistantButton({ messageId, sessionId }) {
      const onClick = useCallback((event) => {
        event?.preventDefault?.();
        openLink({ sessionId, messageId });
      }, [messageId, sessionId]);
      return h("button", {
        type: "button",
        className: "sf-assist",
        title: "查看这条回答的执行链",
        "aria-label": "查看这条回答的执行链",
        "data-message-id": messageId,
        onClick,
      }, h(Icon, { name: "shield", size: 15 }));
    }

    /* ------------------------------------------------------------ plugin */

    function apply(ctx) {
      ensureStyle();

      ctx.slots.inject("sidebar.panellist", () => ctx.slots.register({
        name: "sidebar.panellist",
        id: PANEL_ID,
        order: 40,
        label: "安全巡检",
      }, (props) => h(Icon, { name: "shield", size: (props && props.size) || 16 })));

      ctx.slots.inject("main", () => ctx.slots.register({
        name: "main",
        key: PANEL_ID,
      }, Panel));

      ctx.slots.inject("conversation.input.dock", () => ctx.slots.register({
        name: "conversation.input.dock",
        id: "safety-badge",
        order: 30,
        label: "安全巡检",
      }, DockBadge));

      ctx.slots.inject("conversation.chat.assistant-actions", () => ctx.slots.register({
        name: "conversation.chat.assistant-actions",
        id: "safety-inspect",
        order: 25,
      }, AssistantButton));

      ctx.slots.inject("shell.overlay", () => ctx.slots.register({
        name: "shell.overlay",
        id: "safety-overlay",
        order: 30,
      }, Overlay));

      ctx.inject(["commandUi"], (scope) => {
        const commands = scope.get("commandUi");
        scope.effect(() => commands.register({
          name: "safety",
          label: () => "安全巡检",
          icon: () => h(Icon, { name: "shield", size: 16 }),
          available: () => true,
          ui: {
            kind: "action",
            run: (session) => {
              const id = session?.sessionId ?? "";
              if (!id) return;
              openLink({ sessionId: id });
            },
          },
        }), "safety-inspector: /safety command");
      });
    }

    exports.name = NS;
    exports.inject = ["slots"];
    exports.apply = apply;
    return module.exports;
  },
});
