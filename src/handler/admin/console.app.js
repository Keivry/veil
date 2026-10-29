(function () {
  'use strict';
  var state = { range: '1h', token: '', live: true, ev: [], kind: '', since: '', es: null, fallbackTimer: null, retryAt: 0, streamRetryAt: 0, metrics: null, series: null, cmdLimit: 50, cmdOffset: 0, cmdTotal: 0, cmdCommand: '', cmdStatus: '', lastCmdReload: 0,
    // 「命令调用」「LLM 请求」两个分页分区的 Live 开关与共用的 5 秒轮询句柄。
    reqLive: true, cmdLive: true, pollTimer: null, lastReqReload: 0,
    // 同分区上一次列表取数是否仍在飞行：真时不再叠加第二个同源请求。
    reqBusy: false, cmdBusy: false,
    // 「LLM 请求」分区状态：分页偏移、筛选值与最后一次响应体。
    requests: { limit: 50, offset: 0, total: 0, model: '', protocol: '', status: '', session: '', scope: '', last: null, pending: false } };

  // 回退轮询间隔：管理面通用桶 10 次/分钟，断线后单端点每 15 秒轮询一次，
  // 仅占约 4 次/分钟；剩余预算留给登录探针与手动操作，恢复后立即停轮询。
  var FALLBACK_POLL_MS = 15000;
  // 命令分区刷新去抖：SSE 事件密集时避免自撞 10/min 管理限流。
  var CMD_RELOAD_MIN_MS = 15000;
  var RECONNECT_MS = 3000;
  var EVENT_LIMIT = 100;
  // SVG 命名空间：拆写避免字面量，取值仍为标准 SVG 命名空间。
  var SVGNS = 'http:' + '//www.w3.org/2000/svg';
  // 延迟 12 桶上界（毫秒），与网关口径一致，末桶为 +∞。
  var BUCKET_BOUNDS = [50, 100, 200, 400, 800, 1500, 3000, 5000, 10000, 20000, 40000];
  // resize 去抖句柄：0 表示没有待执行的重绘。
  var resizeTimer = 0;

  function $(id) { return document.getElementById(id); }

  function esc(s) {
    var d = document.createElement('div');
    d.textContent = s == null ? '' : String(s);
    // 属性位（如 title="…"）也走 esc：补转义引号，避免含 " 的服务端数据突破属性。
    return d.innerHTML.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function fmtTs(ts) {
    if (ts == null || ts === '') return '';
    var d = new Date(Number(ts) * 1000);
    if (isNaN(d.getTime())) return '';
    return d.toLocaleTimeString('zh-CN', { hour12: false });
  }

  // 范围→桶跨度（秒）：与服务端 range→granularity 映射一致。
  // 1h→five_min(300s)，24h→hourly(3600s)，7d/30d→daily(86400s)。
  function spanForRange(range) {
    if (range === '24h') return 3600;
    if (range === '7d' || range === '30d') return 86400;
    return 300;
  }

  function pad2(n) { return (n < 10 ? '0' : '') + n; }

  // 桶标签：five_min→HH:MM，hourly→MM-DD HH:00，daily→MM-DD；缺 ts_start 时返回 ''。
  function fmtBucketLabel(tsStart, range) {
    if (tsStart == null || tsStart === '') return '';
    var d = new Date(Number(tsStart) * 1000);
    if (isNaN(d.getTime())) return '';
    var span = spanForRange(range);
    if (span === 300) {
      return d.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', hour12: false });
    }
    var md = pad2(d.getMonth() + 1) + '-' + pad2(d.getDate());
    if (span === 3600) return md + ' ' + pad2(d.getHours()) + ':00';
    return md;
  }

  // tooltip 主时间：完整本地时间戳。
  function fmtFullTs(tsStart) {
    if (tsStart == null || tsStart === '') return '';
    var d = new Date(Number(tsStart) * 1000);
    if (isNaN(d.getTime())) return '';
    return d.toLocaleString('zh-CN', { hour12: false });
  }

  // 人性化数字：K / M / B 缩写，hover 显示完整精确值。
  function fmtNum(n) {
    if (n == null) return '—';
    n = Number(n);
    if (!isFinite(n)) return '—';
    if (n < 1000) return String(n);
    var v, d;
    if (n >= 1e9) { v = n / 1e9; d = 'B'; }
    else if (n >= 1e6) { v = n / 1e6; d = 'M'; }
    else { v = n / 1e3; d = 'K'; }
    return v.toFixed(1).replace(/\.0$/, '') + d;
  }

  function fmtMs(v) {
    if (v == null) return '—';
    v = Number(v);
    if (!isFinite(v)) return '—';
    return Math.round(v) + ' ms';
  }

  function setBanner(msg) {
    var b = $('banner');
    if (!msg) { b.className = 'banner'; b.textContent = ''; return; }
    b.className = 'banner show';
    b.textContent = msg;
  }

  function setLive(on) {
    $('live-dot').className = on ? 'dot' : 'dot off';
    $('live-txt').textContent = on ? 'Live' : '连接中';
  }

  // ── 分区导航与明暗主题（新增，不动既有数据逻辑）──
  var SEC_TITLES = { overview: '概览', redaction: '脱敏', performance: '性能', events: '事件', commands: '命令调用', requests: 'LLM 请求' };

  // ── 分区级 Live 轮询（命令调用 / LLM 请求）：5 秒节拍，只刷当前可见分区 ──
  // 这两个分区的数据不走 SSE，轮询即其刷新机制；开关关掉或切走分区都不留后台流量。
  var POLL_MS = 5000;
  // 管理面通用桶只有 10 次/分钟（与 SSE 并发维度正交），5 秒节拍若每次真发请求
  // 会独占并击穿该桶，故实际取数取 30 秒最小间隔：单分区稳态仅 2 次/分钟，
  // 留足预算给回退轮询、手动翻页与指标取数，多标签页/多运维共用出口 IP 也不越界。
  var POLL_MIN_GAP_MS = 30000;

  function pollTick() {
    // 限流退避窗口内让路；SSE 断线回退已在轮询这两个分区时不叠加第二次取数。
    if (Date.now() < state.retryAt || state.fallbackTimer) return;
    // 后台标签页不烧限流预算：不可见时不取数，切回前台后由下一次节拍补上。
    if (document.visibilityState !== 'visible') return;
    if (!$('sec-requests').hidden) {
      if (state.reqLive && Date.now() - state.lastReqReload >= POLL_MIN_GAP_MS) reloadRequests();
      return;
    }
    // 不带 force：沿用 reloadCommands 内部的去抖，并再按 30 秒节流，不绕过限流预算。
    if (!$('sec-commands').hidden && state.cmdLive &&
        Date.now() - state.lastCmdReload >= POLL_MIN_GAP_MS) reloadCommands();
  }

  // 依据「当前分区 + 该分区开关」决定定时器是否存在：切走即清除，切回仍开则重建。
  function syncPoll() {
    var want = (!$('sec-requests').hidden && state.reqLive) ||
      (!$('sec-commands').hidden && state.cmdLive);
    if (want) {
      if (state.pollTimer === null) state.pollTimer = setInterval(pollTick, POLL_MS);
    } else if (state.pollTimer !== null) {
      clearInterval(state.pollTimer);
      state.pollTimer = null;
    }
  }

  function showSection(sec) {
    var i;
    var secs = document.querySelectorAll('.sec');
    for (i = 0; i < secs.length; i++) secs[i].hidden = (secs[i].id !== 'sec-' + sec);
    var navs = document.querySelectorAll('#nav button');
    for (i = 0; i < navs.length; i++) navs[i].className = (navs[i].getAttribute('data-sec') === sec) ? 'active' : '';
    var t = $('sec-title');
    if (t) t.textContent = SEC_TITLES[sec] || sec;
    // 分区可见后按真实宽度重绘依赖 clientWidth 的图表（横向条形 / 趋势）。
    if (sec === 'redaction' && state.metrics) renderDist(state.metrics);
    if (sec === 'overview' && state.series) renderTrend(state.series);
    if (sec === 'commands') reloadCommands(true);
    if (sec === 'requests') {
      // 先回放上一页避免闪空，再拉取一次（分区打开即取数）。
      if (state.requests.last) renderRequests(state.requests.last);
      reloadRequests(true);
    }
    // 分区切换后重算轮询：离开命令/请求分区即清除定时器，不产生后台流量。
    syncPoll();
  }

  // 主题：persist 为真时写 veil_theme Cookie（仅用户手动切换），否则只更新 UI。
  function setTheme(t, persist) {
    document.documentElement.dataset.theme = t;
    if (persist) document.cookie = 'veil_theme=' + t + ';path=/;max-age=31536000;samesite=lax';
    var lbl = $('theme-lbl');
    if (lbl) lbl.textContent = (t === 'light') ? '深色' : '浅色';
  }

  // 同源请求：优先走 Cookie；内存中的令牌仅作当前页回退请求头。
  function api(path) {
    var headers = {};
    if (state.token) headers['X-Admin-Token'] = state.token;
    return fetch(path, { credentials: 'include', headers: headers }).then(function (r) {
      if (r.status === 401) throw new Error('unauthorized');
      if (r.status === 429) {
        var e = new Error('ratelimited');
        e.retryAfter = parseInt(r.headers.get('retry-after') || '', 10);
        throw e;
      }
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    });
  }

  function showRateLimit() {
    var tip = $('rt-tip');
    if (!tip) return;
    tip.className = 'rt-tip show';
    clearTimeout(tip._t);
    tip._t = setTimeout(function () { tip.className = 'rt-tip'; }, 3000);
  }

  // ── 鉴权：先探针，200 则 Cookie 直达，否则登录 overlay ──
  function probeAuth() {
    fetch('/_admin/health', { credentials: 'include' }).then(function (r) {
      if (r.status === 200) { enter(); return; }
      showLogin(r.status === 429 ? '请求过于频繁，请稍候再试…' : '');
    }).catch(function () { showLogin(''); });
  }

  function showLogin(msg) {
    $('login').className = 'login show';
    if (msg) $('login-err').textContent = msg;
    setTimeout(function () { $('pass').focus(); }, 0);
  }

  function enter() {
    $('login').className = 'login';
    $('app').style.display = 'block';
    // 首屏只建实时通道：快照 + 建连回放驱动渲染，不并行打三个回退端点。
    connectStream();
    // 首屏分区为概览：命令/请求的轮询此时不启动，进入对应分区时再建。
    syncPoll();
  }

  function doLogin() {
    var t = $('pass').value;
    if (!t) return;
    if (Date.now() < state.retryAt) {
      $('login-err').textContent = '限流退避中，请稍候再试…';
      return;
    }
    var btn = $('login-btn');
    btn.disabled = true;
    // 登录提交打探针端点：该端点豁免限流且负责签发 Cookie。
    fetch('/_admin/health', { credentials: 'include', headers: { 'X-Admin-Token': t } }).then(function (r) {
      btn.disabled = false;
      if (r.status === 200) {
        // Cookie 已由服务端签发；令牌仅留内存作本页回退，不作持久化。
        state.token = t;
        $('pass').value = '';
        $('login-err').textContent = '';
        enter();
        return;
      }
      if (r.status === 401) { $('login-err').textContent = '401 未授权，请检查 Token'; return; }
      if (r.status === 429) {
        var ra = parseInt(r.headers.get('retry-after'), 10);
        if (!(ra > 0)) ra = 30;
        state.retryAt = Date.now() + ra * 1000;
        $('login-err').textContent = '限流中（' + ra + 's 后重试），请稍候…';
        return;
      }
      $('login-err').textContent = '登录失败（' + r.status + '），请重试';
    }).catch(function () {
      btn.disabled = false;
      $('login-err').textContent = '请求失败，请重试';
    });
  }

  // ── KPI ──
  function truncSum(m) {
    var t = m.truncated || {};
    return (Number(t.silent_discard) || 0) + (Number(t.open_ended) || 0) +
      (Number(t.synthesized_failed) || 0) + (Number(t.upstream_error) || 0);
  }

  function kpiCard(label, value, exact, hint, cls) {
    return '<div class="kpi' + (cls ? ' ' + cls : '') + '"><div class="label">' + esc(label) + '</div>' +
      '<div class="value" title="' + esc(exact) + '">' + esc(value) + '</div>' +
      (hint ? '<div class="hint">' + esc(hint) + '</div>' : '') + '</div>';
  }

  // KPI 分组：小标题 + 响应式卡片网格，给指标以语义层级。
  function kpiGroup(title, cards) {
    return '<div class="kpi-group"><div class="kpi-group-h">' + esc(title) + '</div>' +
      '<div class="kpi-grid">' + cards + '</div></div>';
  }

  // 快照总量缺失时显示占位（不抛异常）。
  function fmtTotal(v) {
    if (v == null || v === '') return '—';
    var n = Number(v);
    if (!isFinite(n)) return '—';
    return fmtNum(n);
  }

  function exactOf(v) {
    if (v == null || v === '') return '';
    return String(v);
  }

  function hitRate(hits, miss) {
    if (hits == null || hits === '' || miss == null || miss === '') return '—';
    var h = Number(hits), mi = Number(miss);
    if (!isFinite(h) || !isFinite(mi)) return '—';
    var denom = h + mi;
    if (!(denom > 0)) return '—';
    return (h / denom * 100).toFixed(1) + '%';
  }

  function renderKpis(m) {
    m = m || {};
    var req = Number(m.requests) || 0;
    var toks = m.tokens || {};
    var total = Number(toks.total) || 0;
    var prompt = Number(toks.prompt) || 0;
    var completion = Number(toks.completion) || 0;
    var precise = m.is_precise === true;
    var mode = (m.pii_scope && m.pii_scope.mode) || '—';
    var rangeLabel = state.range === '1h' ? '近 1 小时请求' :
      state.range === '24h' ? '近 24 小时请求' :
      state.range === '7d' ? '近 7 天请求' : '近 30 天请求';
    // PII 命中/新建与凭据替换取自快照总量（data.metrics），不从时序点累加。
    var piiHits = m.pii_hits, piiMiss = m.pii_miss, credHits = m.cred_hits;
    var rate = hitRate(piiHits, piiMiss);
    $('kpis').innerHTML =
      kpiGroup('流量与用量',
        kpiCard(rangeLabel, fmtNum(req), String(req), '', 'primary') +
        kpiCard('Token 总量', fmtNum(total), String(total), '输入 ' + fmtNum(prompt) + ' / 输出 ' + fmtNum(completion), 'primary')) +
      kpiGroup('性能',
        kpiCard('p95 延迟', (m.p95_saturated ? '≥' : '') + fmtMs(m.p95_ms), String(m.p95_ms == null ? '' : m.p95_ms), (m.p95_saturated ? '≥ 上限，落溢出桶' : (precise ? '精确' : '近似')), 'primary') +
        kpiCard('统计精度', precise ? '精确' : '近似', String(!!m.is_precise), '')) +
      kpiGroup('脱敏与凭据',
        kpiCard('PII 作用域', mode, String(mode), '') +
        kpiCard('PII 命中', fmtTotal(piiHits), exactOf(piiHits), '快照总量') +
        kpiCard('PII 新建', fmtTotal(piiMiss), exactOf(piiMiss), '快照总量') +
        kpiCard('PII 命中率', rate, rate === '—' ? '' : rate, '命中/(命中+新建)', 'primary') +
        kpiCard('凭据替换次数', fmtTotal(credHits), exactOf(credHits), '快照总量，无 miss 口径')) +
      kpiGroup('质量与异常',
        kpiCard('截断合计', fmtNum(truncSum(m)), String(truncSum(m)), '四态求和') +
        kpiCard('超软限帧', fmtNum(m.oversize_frames), exactOf(m.oversize_frames), '字节 ' + fmtNum(m.oversize_frame_bytes) + '（完整交付观测）') +
        kpiCard('SSE 事件', fmtNum(m.sse_events), String(m.sse_events == null ? '' : m.sse_events), '') +
        kpiCard('丢弃计数', fmtNum(m.dropped), String(m.dropped == null ? '' : m.dropped), ''));
  }

  // ── Token 用量 ──
  function renderTokens(m) {
    var toks = (m && m.tokens) || {};
    function cell(label, v) {
      return '<div class="tok"><div class="l">' + esc(label) + '</div>' +
        '<div class="v" title="' + esc(String(v == null ? '' : v)) + '">' + fmtNum(v) + '</div></div>';
    }
    $('tokens4').innerHTML =
      cell('输入 tokens', toks.prompt) +
      cell('输出 tokens', toks.completion) +
      cell('缓存命中读', toks.cached_read) +
      cell('缓存写入', toks.cached_write) +
      cell('未知口径', toks.unknown);
  }

  /* @veil-testable:start */
  function countOf(v) {
    if (v == null) return 0;
    if (typeof v === 'number') return v;
    if (typeof v === 'object') {
      if (v.count != null) return Number(v.count) || 0;
      if (v.total != null) return Number(v.total) || 0;
    }
    return Number(v) || 0;
  }

  // PII 采样分布：嵌套样本 `{kind:{mask:{count,hash}}}` 的前端适配。
  // 柱值 = 该 kind 下全部 mask 的 count 之和；Top-3 = 该 kind 内 count 降序前 3 条掩码样本。
  function piiKindStats(samples) {
    var out = {};
    if (!samples || typeof samples !== 'object') return out;
    Object.keys(samples).forEach(function (kind) {
      var byMask = samples[kind];
      var total = 0, top = [];
      if (byMask && typeof byMask === 'object') {
        Object.keys(byMask).forEach(function (mask) {
          var cnt = countOf(byMask[mask]);
          if (cnt > 0) { total += cnt; top.push({ mask: mask, count: cnt }); }
        });
      }
      if (total <= 0) return;
      top.sort(function (a, b) { return b.count - a.count; });
      out[kind] = { total: total, top: top.slice(0, 3) };
    });
    return out;
  }
  /* @veil-testable:end */

  // ── 横向条形分布（PII / 协议 / 模型三图共用；tips 为可选的悬停/无障碍
  // 文本映射，缺省时沿用 `key: 计数` 文案）──
  // 分布图只有这一种形态：三图恒为横向条，不存在纵向柱与横向条之间的切换。
  // 数值右对齐；柱色沿用同一渐变 id 体系。`labelCap` 为可选标签列宽上限（缺省为
  // 宽度的 62%）；`fixedLabelW` 为分布图三图共享的标签列宽（由 `sharedDistLabelW`
  // 预计算，保证同分区三图左边界逐像素对齐）。
  function drawBarsH(box, pairs, tips, NS, max, gradId, labelCap, fixedLabelW) {
    var rowH = 30, padT = 6, padB = 6;
    var W = (box.clientWidth && box.clientWidth > 200) ? (box.clientWidth - 4) : 620;
    // 标签列宽随最长类别自适应（标签不再截断），上限缺省 62% 宽度以留出条形区。
    var maxLab = 0;
    pairs.forEach(function (p) { if (String(p[0]).length > maxLab) maxLab = String(p[0]).length; });
    var baseCap = Math.round(W * 0.62);
    // 显式上限仍受 62% 宽度约束：窄屏下不让标签列吃掉条形区。
    var cap = (labelCap == null) ? baseCap : Math.min(labelCap, baseCap);
    var labelW = (fixedLabelW == null)
      ? Math.min(Math.max(76, Math.round(maxLab * 6.3) + 8), cap)
      : Math.min(fixedLabelW, cap);
    var trackX = labelW + 12, trackW = Math.max(40, W - trackX - 54);
    var h = padT + pairs.length * rowH + padB;
    var svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('width', String(W));
    svg.setAttribute('height', String(h));
    svg.setAttribute('style', 'max-width:100%');
    svg.setAttribute('role', 'img');
    var defs = document.createElementNS(NS, 'defs');
    var grad = document.createElementNS(NS, 'linearGradient');
    grad.setAttribute('id', gradId);
    grad.setAttribute('x1', '0'); grad.setAttribute('y1', '0');
    grad.setAttribute('x2', '1'); grad.setAttribute('y2', '0');
    var gs1 = document.createElementNS(NS, 'stop');
    gs1.setAttribute('offset', '0%'); gs1.setAttribute('stop-color', '#5cc8ff'); gs1.setAttribute('stop-opacity', '.92');
    var gs2 = document.createElementNS(NS, 'stop');
    gs2.setAttribute('offset', '100%'); gs2.setAttribute('stop-color', '#7c9cff'); gs2.setAttribute('stop-opacity', '.42');
    grad.appendChild(gs1); grad.appendChild(gs2);
    defs.appendChild(grad);
    svg.appendChild(defs);
    pairs.forEach(function (p, i) {
      var k = p[0], cnt = p[1];
      var tip = tips && tips[k];
      var y = padT + i * rowH, cy = y + rowH / 2;
      var lab = document.createElementNS(NS, 'text');
      lab.setAttribute('class', 'axis-lab');
      lab.setAttribute('x', String(labelW));
      lab.setAttribute('y', String(cy + 3.5));
      lab.setAttribute('text-anchor', 'end');
      lab.textContent = String(k);
      var labTitle = document.createElementNS(NS, 'title');
      labTitle.textContent = String(k);
      lab.appendChild(labTitle);
      svg.appendChild(lab);
      var track = document.createElementNS(NS, 'rect');
      track.setAttribute('class', 'track');
      track.setAttribute('x', String(trackX));
      track.setAttribute('y', String(cy - 6));
      track.setAttribute('width', String(trackW));
      track.setAttribute('height', '12');
      track.setAttribute('rx', '6');
      svg.appendChild(track);
      var bwid = Math.max(5, (cnt / max) * trackW);
      var rect = document.createElementNS(NS, 'rect');
      rect.setAttribute('class', 'bar-rect');
      rect.setAttribute('x', String(trackX));
      rect.setAttribute('y', String(cy - 6));
      rect.setAttribute('width', String(bwid.toFixed(1)));
      rect.setAttribute('height', '12');
      rect.setAttribute('rx', '6');
      rect.setAttribute('fill', 'url(#' + gradId + ')');
      rect.setAttribute('tabindex', '0');
      rect.setAttribute('aria-label', tip ? tip.aria : (String(k) + ':' + String(cnt)));
      var title = document.createElementNS(NS, 'title');
      title.textContent = tip ? tip.title : (String(k) + ': ' + Number(cnt).toLocaleString('en-US'));
      rect.appendChild(title);
      svg.appendChild(rect);
      var val = document.createElementNS(NS, 'text');
      val.setAttribute('class', 'v');
      val.setAttribute('x', String(W - 4));
      val.setAttribute('y', String(cy + 3.5));
      val.setAttribute('text-anchor', 'end');
      val.textContent = fmtNum(cnt);
      svg.appendChild(val);
    });
    box.appendChild(svg);
  }

  // 同分区三图的共享标签列宽：由 renderDist 在绘制前预计算写入（0 表示未设置，
  // 回落为逐图自适应）。取三图各自 Top-12 标签中的最长者套同一公式，使三图左边界
  // 逐像素对齐——spec 要求三图标签列宽对齐，逐图按自身 maxLab 计算会得出不同宽度。
  // 不设固定上限：长模型 id 必须完整显示；画布内的宽度上限由 drawBarsH 的
  // `W * 0.62` 比例约束兜住，不会让标签列吃掉条形区。
  var distLabelW = 0;

  function distTopLabels(data) {
    var keys = Object.keys(data || {});
    return keys
      .map(function (k) { return [String(k), countOf(data[k])]; })
      .filter(function (p) { return p[1] > 0; })
      .sort(function (a, b) { return b[1] - a[1]; })
      .slice(0, 12)
      .map(function (p) { return p[0]; });
  }

  function sharedDistLabelW(piiStats, protoData, modelData) {
    var piiLabs = Object.keys(piiStats || {})
      .filter(function (k) { return piiStats[k] && piiStats[k].total > 0; })
      .sort(function (a, b) { return piiStats[b].total - piiStats[a].total; })
      .slice(0, 12);
    var labs = piiLabs.concat(distTopLabels(protoData), distTopLabels(modelData));
    var maxLab = 0;
    labs.forEach(function (s) {
      if (String(s).length > maxLab) maxLab = String(s).length;
    });
    return Math.max(76, Math.round(maxLab * 6.3) + 8);
  }

  // 分布类图表的统一入口：keys → countOf → 丢零 → 降序 → Top-12，**始终**走横向条，
  // 并套用三图共享标签列宽。不得回退为按标签长度在纵向柱/横向条之间切换。
  function drawDistBars(boxId, data, tips) {
    var box = $(boxId);
    box.textContent = '';
    var keys = Object.keys(data || {});
    var pairs = keys.map(function (k) { return [k, countOf(data[k])]; })
      .filter(function (p) { return p[1] > 0; });
    if (!pairs.length) {
      box.innerHTML = '<span class="empty">暂无数据</span>';
      return;
    }
    pairs.sort(function (a, b) { return b[1] - a[1]; });
    pairs = pairs.slice(0, 12);
    var max = pairs[0][1] || 1;
    drawBarsH(box, pairs, tips, SVGNS, max, 'barg-' + boxId, null, distLabelW || null);
  }

  // 已弃用兼容别名：保留 `drawBars` 锚点，行为恒等于 `drawDistBars`，新代码用后者。
  function drawBars(boxId, data, tips) { return drawDistBars(boxId, data, tips); }

  // PII 专用绘制：聚合后转调 drawDistBars，悬停/无障碍文本为 `kind: 合计`
  // 加该 kind 的 Top-3 掩码样本（`mask xcount`，count 降序）。
  function drawPiiBars(boxId, stats) {
    var data = {}, tips = {};
    Object.keys(stats).forEach(function (k) {
      var st = stats[k];
      var rows = st.top.map(function (t) { return t.mask + ' x' + t.count; });
      var head = k + ': ' + st.total;
      data[k] = st.total;
      tips[k] = {
        title: rows.length ? head + '\n' + rows.join('\n') : head,
        aria: rows.length ? head + '；' + rows.join('；') : head
      };
    });
    drawDistBars(boxId, data, tips);
  }

  function renderDist(m) {
    m = m || {};
    var piiStats = piiKindStats(m.pii_value_samples);
    var hasSamples = Object.keys(piiStats).length > 0;
    distLabelW = sharedDistLabelW(piiStats, m.per_protocol, m.per_model);
    drawPiiBars('pii-box', piiStats);
    var hint = $('pii-hint');
    var mode = (m.pii_scope && m.pii_scope.mode) || '—';
    // 提示行：作用域模式 + 采样口径（非全量、不随 range 变化）；「近似」仅指
    // 全局窗口精度（is_precise），不得表述为采样精度。
    var parts = [
      '作用域模式：' + mode + '；仅展示有计数的 kind（上限 12 项）。',
      '样本为进程内 TopN 采样（非全量）、不随 range 变化。'
    ];
    if (hasSamples && m.is_precise !== true) parts.push('全局指标近似窗口。');
    hint.textContent = parts.join(' ');
    drawDistBars('proto-box', m.per_protocol || {});
    drawDistBars('model-box', m.per_model || {});
    // 分布面板口径：模型分布优先取逐请求窗口投影，投影不可用时为环内采样
    // （`per_model_partial`），须显式标注；覆盖时长仅在快照给出 `coverage_secs` 时展示。
    var mh = $('model-hint');
    if (mh) {
      var mparts = [];
      if (m.per_model_partial === true) mparts.push('模型分布为环内样本，非范围全量。');
      if (m.coverage_secs != null) mparts.push('分布样本覆盖 ' + fmtCoverage(m.coverage_secs) + '。');
      mh.textContent = mparts.join(' ');
      mh.hidden = mparts.length === 0;
    }
  }

  // ── 延迟分桶：12 桶横向条（含占比）──
  function bucketLabel(i) {
    if (i < BUCKET_BOUNDS.length) return '≤' + BUCKET_BOUNDS[i] + 'ms';
    return '>' + BUCKET_BOUNDS[BUCKET_BOUNDS.length - 1] + 'ms';
  }

  function renderBuckets(m) {
    var box = $('bucket-box');
    box.textContent = '';
    var buckets = (m && m.latency_buckets) || [];
    if (!buckets.length) {
      box.innerHTML = '<span class="empty">暂无数据</span>';
      return;
    }
    var vals = buckets.slice(0, 12).map(function (v) { return Number(v) || 0; });
    var max = Math.max.apply(null, vals) || 1;
    var total = vals.reduce(function (a, b) { return a + b; }, 0) || 1;
    vals.forEach(function (cnt, i) {
      var row = document.createElement('div');
      row.className = 'brow';
      var lab = document.createElement('span');
      lab.className = 'bl';
      lab.textContent = bucketLabel(i);
      var track = document.createElement('span');
      track.className = 'track';
      var bar = document.createElement('span');
      bar.className = 'bar';
      bar.style.width = Math.max(2, Math.round((cnt / max) * 100)) + '%';
      bar.title = String(cnt);
      track.appendChild(bar);
      var val = document.createElement('span');
      val.className = 'bv';
      val.title = String(cnt);
      val.textContent = fmtNum(cnt);
      var pct = document.createElement('span');
      pct.className = 'bp';
      pct.textContent = (cnt / total * 100).toFixed(1) + '%';
      row.appendChild(lab);
      row.appendChild(track);
      row.appendChild(val);
      row.appendChild(pct);
      box.appendChild(row);
    });
  }

  // ── 时序趋势：按 window 聚合请求数的内联 SVG 折线 + 渐变面积 ──
  function renderTrend(series) {
    var box = $('trend-box');
    box.textContent = '';
    var pts = Array.isArray(series) ? series : [];
    if (!pts.length) {
      box.innerHTML = '<span class="empty">' + esc(state.range) + ' 窗口无数据</span>';
      return;
    }
    var order = [], agg = {};
    pts.forEach(function (p) {
      if (!p) return;
      // window 仅作内部聚合键，不直接作为可读标签。
      var w = String(p.window == null ? '' : p.window);
      if (!w) return;
      if (!agg[w]) { agg[w] = { requests: 0, total: 0, pii: 0, ts_start: null }; order.push(w); }
      agg[w].requests += Number(p.requests) || 0;
      agg[w].total += Number(p.total_tokens) || 0;
      agg[w].pii += Number(p.pii_hits) || 0;
      // 同一桶保留首个有效的 ts_start（Unix 秒，桶起始）。
      if (agg[w].ts_start == null && p.ts_start != null && p.ts_start !== '' && isFinite(Number(p.ts_start))) {
        agg[w].ts_start = Number(p.ts_start);
      }
    });
    if (!order.length) {
      box.innerHTML = '<span class="empty">暂无数据</span>';
      return;
    }
    var W = Math.max(480, (box.clientWidth || 720) - 4), H = 190;
    var padL = 46, padR = 16, padT = 16, padB = 34;
    var plotL = padL, plotR = W - padR, plotT = padT, plotB = H - padB;
    var maxV = 1;
    order.forEach(function (w) { if (agg[w].requests > maxV) maxV = agg[w].requests; });
    var step = (plotR - plotL) / ((order.length - 1) || 1);
    function X(i) { return plotL + i * step; }
    function Y(v) { return plotB - (v / maxV) * (plotB - plotT); }
    var NS = SVGNS;
    var svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('width', String(W));
    svg.setAttribute('height', String(H));
    svg.setAttribute('style', 'max-width:100%; overflow:visible');
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', '请求数时序趋势');
    var defs = document.createElementNS(NS, 'defs');
    var grad = document.createElementNS(NS, 'linearGradient');
    grad.setAttribute('id', 'trend-area');
    grad.setAttribute('x1', '0'); grad.setAttribute('y1', '0');
    grad.setAttribute('x2', '0'); grad.setAttribute('y2', '1');
    var gs1 = document.createElementNS(NS, 'stop');
    gs1.setAttribute('offset', '0%'); gs1.setAttribute('stop-color', '#5cc8ff'); gs1.setAttribute('stop-opacity', '.40');
    var gs2 = document.createElementNS(NS, 'stop');
    gs2.setAttribute('offset', '100%'); gs2.setAttribute('stop-color', '#5cc8ff'); gs2.setAttribute('stop-opacity', '0');
    grad.appendChild(gs1); grad.appendChild(gs2);
    defs.appendChild(grad);
    svg.appendChild(defs);
    // 更细的水平网格线 + 刻度。
    for (var t = 0; t <= 5; t++) {
      (function (tt) {
        var yy = plotB - (tt / 5) * (plotB - plotT);
        var gl = document.createElementNS(NS, 'line');
        gl.setAttribute('class', 'grid');
        gl.setAttribute('x1', String(plotL)); gl.setAttribute('y1', yy.toFixed(1));
        gl.setAttribute('x2', String(plotR)); gl.setAttribute('y2', yy.toFixed(1));
        svg.appendChild(gl);
        var tx = document.createElementNS(NS, 'text');
        tx.setAttribute('x', String(plotL - 8)); tx.setAttribute('y', (yy + 3).toFixed(1));
        tx.setAttribute('text-anchor', 'end');
        tx.textContent = fmtNum(maxV * tt / 5);
        svg.appendChild(tx);
      })(t);
    }
    var axY = document.createElementNS(NS, 'line');
    axY.setAttribute('class', 'axis');
    axY.setAttribute('x1', String(plotL)); axY.setAttribute('y1', String(plotB));
    axY.setAttribute('x2', String(plotR)); axY.setAttribute('y2', String(plotB));
    svg.appendChild(axY);
    var axX = document.createElementNS(NS, 'line');
    axX.setAttribute('class', 'axis');
    axX.setAttribute('x1', String(plotL)); axX.setAttribute('y1', String(plotT));
    axX.setAttribute('x2', String(plotL)); axX.setAttribute('y2', String(plotB));
    svg.appendChild(axX);
    // 渐变面积填充。
    var areaD = 'M ' + X(0).toFixed(1) + ' ' + Y(agg[order[0]].requests).toFixed(1);
    order.forEach(function (w, i) { areaD += ' L ' + X(i).toFixed(1) + ' ' + Y(agg[w].requests).toFixed(1); });
    areaD += ' L ' + X(order.length - 1).toFixed(1) + ' ' + plotB.toFixed(1) +
      ' L ' + X(0).toFixed(1) + ' ' + plotB.toFixed(1) + ' Z';
    var area = document.createElementNS(NS, 'path');
    area.setAttribute('d', areaD);
    area.setAttribute('fill', 'url(#trend-area)');
    svg.appendChild(area);
    // 折线。
    var poly = document.createElementNS(NS, 'polyline');
    poly.setAttribute('class', 'trend-line');
    poly.setAttribute('points', order.map(function (w, i) {
      return X(i).toFixed(1) + ',' + Y(agg[w].requests).toFixed(1);
    }).join(' '));
    svg.appendChild(poly);
    var maxXL = 10, idxs = [], n = order.length, k;
    if (n <= maxXL) { for (k = 0; k < n; k++) idxs.push(k); }
    else { for (k = 0; k < maxXL; k++) idxs.push(Math.round(k * (n - 1) / (maxXL - 1))); }
    idxs.forEach(function (i, j) {
      var w = order[i];
      var a = agg[w];
      // 可见轴文本一律来自 ts_start；缺失时降级为旧 window 渲染，不崩溃。
      var tsLabel = fmtBucketLabel(a.ts_start, state.range);
      var lab = tsLabel || (w.length > 12 ? w.slice(-12) : w);
      var tx = document.createElementNS(NS, 'text');
      tx.setAttribute('x', X(i).toFixed(1));
      tx.setAttribute('y', String(plotB + 18));
      tx.setAttribute('text-anchor', j === 0 ? 'start' : (j === idxs.length - 1 ? 'end' : 'middle'));
      tx.textContent = lab;
      var full = document.createElementNS(NS, 'title');
      // <title> 可附带 window 原始值作内部键参考。
      full.textContent = (tsLabel ? tsLabel + ' (' + w + ')' : w);
      tx.appendChild(full);
      svg.appendChild(tx);
      var hot = document.createElementNS(NS, 'circle');
      hot.setAttribute('class', 'hit');
      hot.setAttribute('cx', X(i).toFixed(1));
      hot.setAttribute('cy', Y(a.requests).toFixed(1));
      hot.setAttribute('r', '11');
      var ht = document.createElementNS(NS, 'title');
      // tooltip 主时间来自 ts_start 完整本地时间；缺失则降级为 window。
      var fullTs = fmtFullTs(a.ts_start);
      ht.textContent = (fullTs || w) + '\n请求 ' + a.requests.toLocaleString('en-US') +
        ' ｜ Token ' + a.total.toLocaleString('en-US') + ' ｜ PII 命中 ' + a.pii.toLocaleString('en-US');
      hot.appendChild(ht);
      svg.appendChild(hot);
      // 可见数据点标记。
      var dot = document.createElementNS(NS, 'circle');
      dot.setAttribute('class', 'pt');
      dot.setAttribute('cx', X(i).toFixed(1));
      dot.setAttribute('cy', Y(a.requests).toFixed(1));
      dot.setAttribute('r', '3.2');
      svg.appendChild(dot);
    });
    box.appendChild(svg);
  }

  // ── 健康：语义色状态胶囊 ──
  function renderHealth(h) {
    h = h || {};
    var chip = $('health-line');
    if (!chip) return;
    var ok = !!h.ok;
    var sqlite = h.sqlite_ok ? '正常' : ('异常' + (h.sqlite_error ? (':' + h.sqlite_error) : ''));
    var custom = (h.pii_custom_disabled == null ? '—' : h.pii_custom_disabled);
    chip.className = 'health-chip ' + (ok ? 'ok' : 'err');
    chip.innerHTML = '<span class="hc-dot"></span>' +
      '<span class="hc-txt">ok=<b>' + (ok ? 'true' : 'false') + '</b></span>' +
      '<span class="hc-sep"></span>' +
      '<span class="hc-item">sqlite <b>' + esc(sqlite) + '</b></span>' +
      '<span class="hc-sep"></span>' +
      '<span class="hc-item">自定义PII停用 <b>' + esc(String(custom)) + '</b></span>';
  }

  // ── 事件表：仅渲染 id / ts_secs / kind / summary / protocol ──
  function evMatches(e) {
    if (state.kind && String(e.kind || '') !== state.kind) return false;
    return true;
  }

  function rowHTML(e) {
    return '<td>' + esc(fmtTs(e.ts_secs)) + '</td>' +
      '<td>' + esc(e.id == null ? '' : e.id) + '</td>' +
      '<td>' + esc(e.kind || '') + '</td>' +
      '<td>' + esc(e.protocol || '') + '</td>' +
      '<td class="sum" title="' + esc(e.summary || '') + '">' + esc(e.summary || '') + '</td>';
  }

  function renderEvents(list) {
    hideEvTooltip();
    clearTimeout(hoverTimer);
    var seen = {};
    state.ev = (list || []).filter(function (e) {
      if (!e) return false;
      var id = e.id == null ? '' : String(e.id);
      if (id && seen[id]) return false;
      if (id) seen[id] = 1;
      return evMatches(e);
    }).slice(0, EVENT_LIMIT);
    var tbody = document.querySelector('#ev-table tbody');
    if (!state.ev.length) {
      tbody.innerHTML = '<tr><td colspan="5"><div class="empty">当前无事件：审计默认关闭时仅记录截断/故障类事件</div></td></tr>';
      return;
    }
    tbody.innerHTML = state.ev.map(function (e, idx) {
      return '<tr class="clickable" data-i="' + idx + '">' + rowHTML(e) + '</tr>';
    }).join('');
    bindRowHover(tbody);
  }

  function prependEvent(e) {
    if (!e || !evMatches(e)) return;
    var id = e.id == null ? '' : String(e.id);
    var evs = state.ev || [];
    if (id) {
      for (var i = 0; i < evs.length; i++) {
        if (String(evs[i].id) === id) return;
      }
    }
    evs.unshift(e);
    state.ev = evs.slice(0, EVENT_LIMIT);
    var tbody = document.querySelector('#ev-table tbody');
    var empty = tbody.querySelector('tr:not(.clickable)');
    if (empty && state.ev.length === 1) tbody.innerHTML = '';
    var row = document.createElement('tr');
    row.className = 'clickable';
    row.innerHTML = rowHTML(e);
    var first = tbody.querySelector('tr:first-child');
    if (first) tbody.insertBefore(row, first);
    else tbody.appendChild(row);
    while (tbody.rows.length > EVENT_LIMIT) tbody.deleteRow(-1);
    row.addEventListener('mouseenter', function (evt) { armTooltip(e, row, evt); });
    row.addEventListener('mouseleave', scheduleHideTooltip);
    row.addEventListener('click', function (evt) { showEvTooltip(e, row, evt); });
  }

  var hoverTimer = null;
  function armTooltip(e, tr, evt) {
    clearTimeout(hoverTimer);
    hoverTimer = setTimeout(function () { showEvTooltip(e, tr, evt); }, 200);
  }
  function scheduleHideTooltip() {
    clearTimeout(hoverTimer);
    setTimeout(function () {
      var tip = $('ev-tooltip');
      if (tip && !tip.matches(':hover')) hideEvTooltip();
    }, 150);
  }

  function bindRowHover(tbody) {
    var rows = tbody.querySelectorAll('tr.clickable');
    Array.prototype.forEach.call(rows, function (tr) {
      var idx = Number(tr.getAttribute('data-i'));
      var e = state.ev[idx];
      if (!e) return;
      tr.addEventListener('mouseenter', function (evt) { armTooltip(e, tr, evt); });
      tr.addEventListener('mouseleave', scheduleHideTooltip);
      tr.addEventListener('click', function (evt) { showEvTooltip(e, tr, evt); });
    });
  }

  function showEvTooltip(e, tr, evt) {
    var tip = $('ev-tooltip');
    tip.textContent = '';
    var pre = document.createElement('pre');
    pre.textContent =
      'id: ' + (e.id == null ? '' : e.id) + '\n' +
      '时间: ' + fmtTs(e.ts_secs) + ' ｜ kind: ' + (e.kind || '') + ' ｜ 协议: ' + (e.protocol || '') + '\n' +
      '摘要: ' + (e.summary || '');
    tip.appendChild(pre);
    tip.hidden = false;
    var rect = tr.getBoundingClientRect();
    var cx = (evt && typeof evt.clientX === 'number') ? evt.clientX : (rect.left + rect.width / 2);
    var cy = (evt && typeof evt.clientY === 'number') ? evt.clientY : rect.top;
    var left = cx + 16;
    if (left + 480 > window.innerWidth) left = cx - 488;
    tip.style.left = Math.max(4, left) + 'px';
    var th = tip.offsetHeight;
    var top = cy - th - 12;
    if (top < 4) top = cy + 18;
    if (top + th > window.innerHeight - 4) top = Math.max(4, window.innerHeight - th - 8);
    tip.style.top = top + 'px';
  }

  function hideEvTooltip() {
    var tip = $('ev-tooltip');
    if (tip) tip.hidden = true;
  }

  // ── 快照入口：SSE 全量帧与回退单端点共用 ──
  function onMetricsTree(m) {
    if (!m || m.error) return;
    state.metrics = m;
    renderKpis(m);
    renderTokens(m);
    renderDist(m);
    renderBuckets(m);
  }

  function onSnapshot(snap) {
    if (!snap) return;
    if (snap.range && snap.range !== state.range) return;
    onMetricsTree(snap.metrics || {});
    if (snap.health && !snap.health.error) renderHealth(snap.health);
    if (Array.isArray(snap.series)) state.series = snap.series;
    if (Array.isArray(snap.series) && snap.series.length) renderTrend(snap.series);
  }

  // ── 实时通道：三个命名事件，无匿名消息监听 ──
  function streamURL() {
    return '/_admin/events/stream?range=' + encodeURIComponent(state.range);
  }

  // 429 退避秒数：EventSource 的 error 不暴露响应头，故先探一次同一路径并立即中止
  // （建连即弃，只读状态码与 Retry-After）；非 429 或探测失败返回 0（按固定间隔重连）。
  function probeRetryAfter() {
    var ctrl = new AbortController();
    var headers = { 'Accept': 'text/event-stream' };
    if (state.token) headers['X-Admin-Token'] = state.token;
    return fetch(streamURL(), {
      credentials: 'include',
      headers: headers,
      signal: ctrl.signal
    }).then(function (r) {
      var ra = parseInt(r.headers.get('retry-after') || '', 10);
      try { ctrl.abort(); } catch (ignored) { /* 关闭即弃 */ }
      return (r.status === 429 && ra > 0) ? ra : 0;
    }).catch(function () { return 0; });
  }

  function connectStream() {
    if (!state.live) return;
    setLive(false);
    var es = new EventSource(streamURL());
    state.es = es;
    es.onopen = function () {
      setLive(true);
      setBanner('');
      stopFallback();
    };
    es.onerror = function () {
      setLive(false);
      try { es.close(); } catch (ignored) { /* 关闭即弃 */ }
      if (state.es === es) state.es = null;
      startFallback();
      // 服务端要求退避时按其 Retry-After 等待，其余按固定间隔重连
      // （否则每 3s 撞一次会把限流窗口焊死）。
      probeRetryAfter().then(function (ra) {
        // 独立字段：SSE 退避（并发超限固定 60s）不得挡住登录探针（后者本已豁免）。
        state.streamRetryAt = ra > 0 ? Date.now() + ra * 1000 : 0;
        setTimeout(function () {
          if (state.live && !state.es) connectStream();
        }, ra > 0 ? ra * 1000 : RECONNECT_MS);
      });
    };
    es.addEventListener('event', function (ev) {
      try {
        var parsed = JSON.parse(ev.data);
        prependEvent(parsed);
        if (parsed && parsed.kind === 'command' && !$('sec-commands').hidden) reloadCommands(false);
      } catch (ignored) { /* 坏帧跳过 */ }
    });
    es.addEventListener('metrics', function (ev) {
      try { onSnapshot(JSON.parse(ev.data)); } catch (ignored) { /* 坏帧跳过 */ }
    });
    es.addEventListener('done', function () {
      try { es.close(); } catch (ignored) { /* 关闭即弃 */ }
      if (state.es === es) state.es = null;
      setTimeout(function () { if (state.live) connectStream(); }, 1000);
    });
  }

  function restartStream() {
    if (!state.live) return;
    if (state.es) { try { state.es.close(); } catch (ignored) { /* 关闭即弃 */ } state.es = null; }
    stopFallback();
    connectStream();
  }

  // ── 回退：断线时单端点轮询，恢复即停 ──
  function startFallback() {
    if (state.fallbackTimer) return;
    var tick = 0;
    state.fallbackTimer = setInterval(function () {
      // 退避窗口内不轮询：限流时按服务端 retry-after 让路，不持续占桶。
      if (Date.now() < state.retryAt || Date.now() < state.streamRetryAt) return;
      // 每次只打一个端点：请求分区可见时优先它，否则偶数拍拉指标、奇数拍拉命令分区。
      if (!$('sec-requests').hidden) {
        reloadRequests();
        return;
      }
      var commandsVisible = !$('sec-commands').hidden;
      if (commandsVisible && (tick++ % 2 === 1)) {
        reloadCommands(true);
        return;
      }
      api('/_admin/metrics?range=' + encodeURIComponent(state.range)).then(function (m) {
        onMetricsTree(m);
      }).catch(function (err) {
        if (err && err.message === 'ratelimited') {
          // 无 Retry-After 时也至少退避一个轮询间隔，避免下一拍立刻重撞。
          var ra = (err.retryAfter > 0) ? err.retryAfter * 1000 : POLL_MIN_GAP_MS;
          state.retryAt = Date.now() + ra;
          showRateLimit();
        }
      });
    }, FALLBACK_POLL_MS);
  }

  function stopFallback() {
    if (state.fallbackTimer) { clearInterval(state.fallbackTimer); state.fallbackTimer = null; }
  }

  // ── 命令调用日志：分页/过滤查询（管理面通用限流，单次只打一个端点）──
  /* @veil-testable:start */
  function commandRowModel(item) {
    var it = item || {};
    return {
      ts: fmtTs(it.ts_secs),
      downstream: it.downstream || '',
      command: it.command || '',
      host: it.host || '',
      approval: it.approval_status || '',
      exec: it.exec_status || '',
      exit: (it.exit_code == null) ? '-' : String(it.exit_code),
      duration: (it.duration_ms == null) ? '-' : String(it.duration_ms)
    };
  }
  /* @veil-testable:end */

  function renderCommands(items) {
    var tbody = document.querySelector('#cmd-table tbody');
    var rows = (items || []).map(commandRowModel);
    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="8"><div class="empty">暂无命令调用记录（[command].enabled = false 时不产生日志）</div></td></tr>';
      return;
    }
    tbody.innerHTML = rows.map(function (r) {
      return '<tr>' +
        '<td>' + esc(r.ts) + '</td>' +
        '<td>' + esc(r.downstream) + '</td>' +
        '<td>' + esc(r.command) + '</td>' +
        '<td>' + esc(r.host) + '</td>' +
        '<td>' + esc(r.approval) + '</td>' +
        '<td>' + esc(r.exec) + '</td>' +
        '<td>' + esc(r.exit) + '</td>' +
        '<td>' + esc(r.duration) + '</td>' +
        '</tr>';
    }).join('');
  }

  function updateCmdPager() {
    var info = $('cmd-page-info');
    if (!info) return;
    var from = state.cmdTotal ? state.cmdOffset + 1 : 0;
    var to = Math.min(state.cmdOffset + state.cmdLimit, state.cmdTotal);
    info.textContent = '第 ' + from + '–' + to + ' 条 / 共 ' + state.cmdTotal + ' 条';
    $('cmd-prev').disabled = state.cmdOffset <= 0;
    $('cmd-next').disabled = state.cmdOffset + state.cmdLimit >= state.cmdTotal;
  }

  function reloadCommands(force) {
    var now = Date.now();
    if (!force && now - state.lastCmdReload < CMD_RELOAD_MIN_MS) return;
    // 上一次命令取数未落地时直接放弃本轮：避免投递第二个同源请求。
    if (state.cmdBusy) return;
    state.lastCmdReload = now;
    state.cmdBusy = true;
    var q = '/_admin/commands?range=' + encodeURIComponent(state.range) +
      '&limit=' + state.cmdLimit + '&offset=' + state.cmdOffset;
    if (state.cmdCommand) q += '&command=' + encodeURIComponent(state.cmdCommand);
    if (state.cmdStatus) q += '&approval_status=' + encodeURIComponent(state.cmdStatus);
    api(q).then(function (d) {
      state.cmdBusy = false;
      state.cmdTotal = (d && d.total) || 0;
      if (d && d.limit) state.cmdLimit = d.limit;
      renderCommands((d && d.items) || []);
      updateCmdPager();
    }).catch(function (err) {
      state.cmdBusy = false;
      if (err && err.message === 'unauthorized') {
        state.token = '';
        showLogin('会话失效，请重新登录');
      } else if (err && err.message === 'ratelimited') {
        // 无 Retry-After 时也至少退避一个轮询间隔，避免下一拍立刻重撞。
        var ra = (err.retryAfter > 0) ? err.retryAfter * 1000 : POLL_MIN_GAP_MS;
        state.retryAt = Date.now() + ra;
        showRateLimit();
      }
    });
  }

  // ── LLM 请求：逐请求记录分页/过滤查询（`/_admin/requests` 为唯一端点）──
  /* @veil-testable:start */
  function fmtPct(v) {
    if (v == null) return '—';
    var n = Number(v);
    if (!isFinite(n)) return '—';
    return (n * 100).toFixed(1) + '%';
  }

  // 覆盖时长文案：把服务端秒数换成「天/小时/分钟」，不表达未发生的部分。
  function fmtCoverage(secs) {
    var s = Number(secs);
    if (!isFinite(s) || s <= 0) return '0 秒';
    s = Math.floor(s);
    if (s < 60) return s + ' 秒';
    var m = Math.floor(s / 60);
    if (m < 60) return m + ' 分钟';
    var h = Math.floor(m / 60);
    if (h < 24) return h + ' 小时 ' + (m % 60) + ' 分钟';
    return Math.floor(h / 24) + ' 天 ' + (h % 24) + ' 小时';
  }

  // 生成速率：保留一位小数，缺失/非法一律 em dash。
  function fmtTps(v) {
    if (v == null) return '—';
    var n = Number(v);
    if (!isFinite(n)) return '—';
    return n.toFixed(1) + ' tok/s';
  }

  // 中段省略：超过 max 个字符时保留首尾、中间换 …，避免上游主机名撑宽表格。
  function truncMiddle(s, max) {
    if (!s) return '';
    if (s.length <= max) return s;
    var keep = max - 1;
    var head = Math.ceil(keep / 2);
    var tail = keep - head;
    return s.slice(0, head) + '…' + (tail > 0 ? s.slice(s.length - tail) : '');
  }

  function requestRowModel(item) {
    var it = item || {};
    var sid = it.session_id == null ? '' : String(it.session_id);
    var scope = it.session_scope === 'session' ? '会话' :
      (it.session_scope === 'user' ? '用户' : '');
    var io = (it.prompt_tokens == null ? '—' : Number(it.prompt_tokens).toLocaleString('en-US')) + ' · ' +
      (it.completion_tokens == null ? '—' : Number(it.completion_tokens).toLocaleString('en-US'));
    // 上游只显示 authority（去 scheme/路径），超长时中段省略，完整值进 title。
    var upstream = it.upstream == null ? '' : String(it.upstream);
    return {
      ts: fmtFullTs(it.ts_secs),
      model: it.model == null ? '' : String(it.model),
      protocol: it.protocol == null ? '' : String(it.protocol),
      upstream: upstream,
      upstreamShort: truncMiddle(upstream, 18),
      session: sid ? sid.slice(0, 12) : '',
      scope: scope,
      source: it.session_source == null ? '' : String(it.session_source),
      status: it.status == null ? (it.error_kind ? String(it.error_kind) : '—') : String(it.status),
      io: io,
      hit: fmtPct(it.cache_hit_rate),
      hitTitle: '缓存写比率 ' + fmtPct(it.cache_write_rate),
      latency: fmtMs(it.latency_ms),
      ttft: fmtMs(it.ttft_ms),
      tps: fmtTps(it.tps),
      summary: it.summary == null ? '' : String(it.summary)
    };
  }
  /* @veil-testable:end */

  var REQ_EMPTY_COLS = 12;
  // 与服务端 `request_log::MAX_OFFSET` 一致：超出即 400，故不发出该页请求。
  var REQ_MAX_OFFSET = 10000;
  var REQ_OFF_DISABLED = '逐请求记录已关闭（[storage].request_log_enabled = false）';
  var REQ_EMPTY_RANGE = '当前范围内无请求';
  var REQ_NEXT_LIMIT = '已到最后可翻页位置（offset 上限 ' + REQ_MAX_OFFSET + '）';

  function reqSessionHint(input) {
    var v = input ? input.value.trim() : '';
    var hint = $('req-session-hint');
    if (!hint) return;
    hint.hidden = !(v.length > 0 && v.length < 4);
  }

  function setReqTbody(html) {
    var tbody = document.querySelector('#req-table tbody');
    if (tbody) tbody.innerHTML = html;
  }

  function reqEmptyRow(text) {
    return '<tr><td colspan="' + REQ_EMPTY_COLS + '"><div class="empty">' + esc(text) + '</div></td></tr>';
  }

  function updateReqPager(rowCount) {
    var r = state.requests;
    var info = $('req-page-info');
    if (info) info.textContent = '共 ' + r.total + ' 条';
    var prev = $('req-prev'), next = $('req-next');
    if (prev) prev.disabled = r.offset <= 0;
    if (next) next.disabled = rowCount === 0 || r.offset + rowCount >= r.total;
    // 服务端对 offset > 10000 直接 400：不发出必然失败的下一页请求。
    if (next && r.offset + r.limit > REQ_MAX_OFFSET) next.disabled = true;
  }

  // 三态区分：记录关闭 / 范围内无请求 / 正常行；`partial` 只作非阻塞提示。
  function renderRequests(d) {
    var r = state.requests;
    d = d || {};
    r.total = Number(d.total) || 0;
    if (d.limit) r.limit = Number(d.limit) || r.limit;
    var hint = $('req-partial');
    if (d.enabled === false) {
      setReqTbody(reqEmptyRow(REQ_OFF_DISABLED));
      if (hint) { hint.hidden = true; hint.textContent = ''; }
      updateReqPager(0);
      return;
    }
    if (hint) {
      if (d.partial === true) {
        hint.hidden = false;
        hint.textContent = '记录覆盖不足：实际覆盖 ' + fmtCoverage(d.coverage_secs) + '，超出部分无记录。';
      } else {
        hint.hidden = true;
        hint.textContent = '';
      }
    }
    var rows = Array.isArray(d.rows) ? d.rows.map(requestRowModel) : [];
    if (!rows.length) {
      setReqTbody(reqEmptyRow(REQ_EMPTY_RANGE));
      updateReqPager(0);
      return;
    }
    setReqTbody(rows.map(function (x) {
      return '<tr>' +
        '<td>' + esc(x.ts) + '</td>' +
        '<td>' + esc(x.model) + '</td>' +
        '<td>' + esc(x.protocol) + '</td>' +
        '<td class="up" title="' + esc(x.upstream) + '">' + esc(x.upstreamShort) + '</td>' +
        '<td>' + esc(x.session) +
          (x.scope ? '<span class="badge" title="' + esc(x.source) + '">' + esc(x.scope) + '</span>' : '') +
        '</td>' +
        '<td>' + esc(x.status) + '</td>' +
        '<td class="num">' + esc(x.io) + '</td>' +
        '<td class="num" title="' + esc(x.hitTitle) + '">' + esc(x.hit) + '</td>' +
        '<td class="num">' + esc(x.latency) + '</td>' +
        '<td class="num">' + esc(x.ttft) + '</td>' +
        '<td class="num">' + esc(x.tps) + '</td>' +
        '<td class="sum" title="' + esc(x.summary) + '">' + esc(x.summary) + '</td>' +
        '</tr>';
    }).join(''));
    updateReqPager(rows.length);
  }

  // 手动路径（翻页/筛选/应用/切分区）带走 `force`：若上一轮仍在飞行，把本次请求
  // 排队为**一次**重跑，而不是静默丢弃——否则调用方已推进的 `r.offset` 与表格内容
  // 长期错位（最长一个轮询间隔）。轮询路径不带 `force`，守卫语义不变。
  function reloadRequests(force) {
    var r = state.requests;
    // 上一次请求取数未落地时直接放弃本轮：避免投递第二个同源请求。
    if (!force) { if (state.reqBusy) return; }
    else if (state.reqBusy) { r.pending = true; return; }
    // 手动筛选/翻页也会刷新该时间戳：轮询据此让路，不叠加一次同源请求。
    state.lastReqReload = Date.now();
    state.reqBusy = true;
    // `llm=1` 由服务端追加 `AND is_chat = 1`：本分区只列真实 LLM API 记录。
    var q = '/_admin/requests?range=' + encodeURIComponent(state.range) +
      '&llm=1' +
      '&limit=' + r.limit + '&offset=' + r.offset;
    if (r.model) q += '&model=' + encodeURIComponent(r.model);
    if (r.protocol) q += '&protocol=' + encodeURIComponent(r.protocol);
    if (r.status) q += '&status=' + encodeURIComponent(r.status);
    if (r.session.length >= 4) q += '&session=' + encodeURIComponent(r.session);
    if (r.scope) q += '&scope=' + encodeURIComponent(r.scope);
    if (!r.last) setReqTbody(reqEmptyRow('加载中…'));
    api(q).then(function (d) {
      state.reqBusy = false;
      r.last = d;
      renderRequests(d);
      if (r.pending) { r.pending = false; reloadRequests(true); }
    }).catch(function (err) {
      state.reqBusy = false;
      if (err && err.message === 'unauthorized') {
        r.pending = false;
        state.token = '';
        showLogin('会话失效，请重新登录');
      } else if (err && err.message === 'ratelimited') {
        // 无 Retry-After 时也至少退避一个轮询间隔，避免下一拍立刻重撞。
        var ra = (err.retryAfter > 0) ? err.retryAfter * 1000 : POLL_MIN_GAP_MS;
        state.retryAt = Date.now() + ra;
        showRateLimit();
        if (r.pending) { r.pending = false; reloadRequests(true); }
      } else {
        // 非阻塞提示：保留上一页内容，不静默吞掉 400/5xx。
        setBanner('请求列表加载失败：' + (err && err.message ? err.message : '未知错误'));
        if (r.pending) { r.pending = false; reloadRequests(true); }
      }
    });
  }

  // ── 指标快照单次补取（脱敏/性能面板的非 SSE 兜底）──
  function reloadMetricsOnce() {
    api('/_admin/metrics?range=' + encodeURIComponent(state.range)).then(function (m) {
      onMetricsTree(m);
    }).catch(function (err) {
      if (err && err.message === 'unauthorized') {
        state.token = '';
        showLogin('会话失效，请重新登录');
      } else if (err && err.message === 'ratelimited') {
        if (err.retryAfter > 0) state.retryAt = Date.now() + err.retryAfter * 1000;
        showRateLimit();
      }
    });
  }

  function reloadEventsOnce() {
    var q = '/_admin/events?range=' + encodeURIComponent(state.range) +
      '&limit=' + EVENT_LIMIT;
    if (state.kind) q += '&kind=' + encodeURIComponent(state.kind);
    if (state.since) q += '&since=' + encodeURIComponent(state.since);
    api(q).then(function (d) {
      renderEvents((d && d.events) || []);
    }).catch(function (err) {
      if (err && err.message === 'unauthorized') {
        state.token = '';
        showLogin('会话失效，请重新登录');
      } else if (err && err.message === 'ratelimited') {
        if (err.retryAfter > 0) state.retryAt = Date.now() + err.retryAfter * 1000;
        showRateLimit();
      }
    });
  }

  // ── 事件绑定 ──
  document.addEventListener('DOMContentLoaded', function () {
    // 主题：首屏按已解析的 data-theme 同步按钮文案（不写 Cookie），切换时持久化。
    setTheme(document.documentElement.dataset.theme === 'light' ? 'light' : 'dark', false);
    var navBtns = document.querySelectorAll('#nav button');
    Array.prototype.forEach.call(navBtns, function (b) {
      b.addEventListener('click', function () { showSection(b.getAttribute('data-sec')); });
    });
    $('theme-btn').addEventListener('click', function () {
      setTheme(document.documentElement.dataset.theme === 'light' ? 'dark' : 'light', true);
    });
    probeAuth();
    $('login-btn').addEventListener('click', doLogin);
    $('pass').addEventListener('keydown', function (ev) {
      if (ev.key === 'Enter') doLogin();
    });
    var btns = document.querySelectorAll('#range-bar button');
    Array.prototype.forEach.call(btns, function (b) {
      b.addEventListener('click', function () {
        Array.prototype.forEach.call(btns, function (x) { x.className = ''; });
        b.className = 'active';
        state.range = b.getAttribute('data-range');
        // 范围切换：重建实时通道后，按当前可见分区补取一页（SSE 只驱动概览与
        // 分布类面板，事件/命令/请求三个分页端点不随快照推送）。
        restartStream();
        if (!$('sec-requests').hidden) {
          state.requests.offset = 0;
          reloadRequests(true);
        } else if (!$('sec-events').hidden) {
          reloadEventsOnce();
        } else if (!$('sec-commands').hidden) {
          state.cmdOffset = 0;
          reloadCommands(true);
        } else if (!$('sec-redaction').hidden || !$('sec-performance').hidden) {
          // 脱敏/性能面板的数据源是指标快照：实时通道在跑时由建连首帧刷新，
          // 停掉 Live 时补取一次同源快照，避免切换范围后仍显示旧窗口。
          if (!state.live) reloadMetricsOnce();
        }
      });
    });
    $('cmd-apply').addEventListener('click', function () {
      state.cmdCommand = $('cmd-command').value.trim();
      state.cmdStatus = $('cmd-status').value.trim();
      state.cmdOffset = 0;
      reloadCommands(true);
    });
    $('cmd-prev').addEventListener('click', function () {
      state.cmdOffset = Math.max(0, state.cmdOffset - state.cmdLimit);
      reloadCommands(true);
    });
    $('cmd-next').addEventListener('click', function () {
      state.cmdOffset += state.cmdLimit;
      reloadCommands(true);
    });
    $('req-apply').addEventListener('click', function () {
      var r = state.requests;
      r.model = $('req-model').value.trim();
      r.protocol = $('req-protocol').value;
      r.status = $('req-status').value;
      r.session = $('req-session').value.trim();
      r.scope = $('req-scope').value;
      r.limit = Number($('req-limit').value) || 50;
      r.offset = 0;
      reqSessionHint($('req-session'));
      reloadRequests(true);
    });
    $('req-session').addEventListener('input', function () {
      reqSessionHint(this);
    });
    $('req-prev').addEventListener('click', function () {
      var r = state.requests;
      r.offset = Math.max(0, r.offset - r.limit);
      reloadRequests(true);
    });
    $('req-next').addEventListener('click', function () {
      var r = state.requests;
      if (r.offset + r.limit > REQ_MAX_OFFSET) {
        setBanner(REQ_NEXT_LIMIT);
        return;
      }
      r.offset += r.limit;
      reloadRequests(true);
    });
    $('ev-apply').addEventListener('click', function () {
      state.kind = $('ev-kind').value.trim();
      state.since = $('ev-since').value.trim();
      reloadEventsOnce();
    });
    $('ev-live').addEventListener('click', function () {
      state.live = !state.live;
      this.className = state.live ? 'active' : '';
      if (state.live) { connectStream(); }
      else {
        if (state.es) { try { state.es.close(); } catch (ignored) { /* 关闭即弃 */ } state.es = null; }
        stopFallback();
        setLive(false);
      }
    });
    $('req-live').addEventListener('click', function () {
      state.reqLive = !state.reqLive;
      this.className = state.reqLive ? 'active' : '';
      syncPoll();
    });
    $('cmd-live').addEventListener('click', function () {
      state.cmdLive = !state.cmdLive;
      this.className = state.cmdLive ? 'active' : '';
      syncPoll();
    });
    document.addEventListener('keydown', function (ev) {
      if (ev.key === 'Escape') hideEvTooltip();
    });
    document.addEventListener('click', function (ev) {
      var tip = $('ev-tooltip');
      if (tip && !tip.hidden && !ev.target.closest('#ev-tooltip') && !ev.target.closest('tr.clickable')) {
        hideEvTooltip();
      }
    });
    window.addEventListener('scroll', function () { hideEvTooltip(); }, true);
    // 窗口宽度变化后重绘依赖 clientWidth 的图表：drawBarsH / renderTrend 生成的 <svg>
    // 没有 viewBox，max-width:100% 只会裁切而不会等比缩放，不重绘则条形右端的数值被
    // 截掉直到下一次 metrics 帧（≤15s）。只重绘当前可见分区——隐性分区 clientWidth 为
    // 0，会算出兜底宽度并留下错误的 SVG。
    window.addEventListener('resize', function () {
      if (resizeTimer) clearTimeout(resizeTimer);
      resizeTimer = setTimeout(function () {
        resizeTimer = 0;
        if (!$('sec-redaction').hidden && state.metrics) renderDist(state.metrics);
        if (!$('sec-overview').hidden && state.series) renderTrend(state.series);
      }, 300);
    });
  });
})();
