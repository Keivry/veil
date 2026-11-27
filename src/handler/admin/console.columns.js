// 记录表列宽引擎：事件/命令/LLM 请求三表共用一套列轨道、拖动、键盘与 Cookie 记忆。
// 独立 IIFE，经 window.VEIL_COLUMNS 暴露 init；主脚本只负责在分区可见时调用。
(function () {
  'use strict';

  // 默认列宽比例（%）：每表合计 100，1280×900 下填满滚动容器且不横向溢出。
  var COLUMN_DEFAULTS = {
    ev: [12, 14, 20, 14, 40],
    cmd: [9, 11, 17, 17, 12, 12, 8, 14],
    req: [8, 11, 6.5, 10.5, 10.5, 6.5, 10.5, 6.5, 6.5, 6.5, 6.5, 10.5]
  };
  var COLUMN_COUNT = { ev: 5, cmd: 8, req: 12 };
  var COOKIE_NAME = 'veil_cols';
  var states = {};

  function tableEl(tableId) {
    return document.getElementById(tableId + '-table');
  }

  function containerWidth(st) {
    var box = st.table.parentNode;
    var w = box ? box.clientWidth : st.table.clientWidth;
    if (!w) w = Math.round(st.table.getBoundingClientRect().width);
    return w > 0 ? w : 0;
  }

  function defaultWidthFor(tableId, idx, container) {
    var pct = (COLUMN_DEFAULTS[tableId] || [])[idx] || 0;
    if (!container || container <= 0) return MIN_WIDTH;
    return Math.max(1, Math.round(container * pct / 100));
  }

  // 窄视口下默认宽度本身可能小于 56px：下限取 min(56, 默认宽度)，拖动不得把列强制跳大。
  function floorFor(st, idx) {
    return columnFloor(defaultWidthFor(st.tableId, idx, containerWidth(st)));
  }

  function setTableWidth(st) {
    var total = 0;
    for (var i = 0; i < st.widths.length; i++) total += st.widths[i];
    st.table.style.width = total + 'px';
  }

  function applyFixed(st, widths, useFloor) {
    var total = 0;
    for (var i = 0; i < st.ths.length; i++) {
      var raw = Math.max(1, Math.round(Number(widths[i]) || 0));
      var w = useFloor ? clampColWidth(raw, floorFor(st, i)) : clampColWidth(raw, 1);
      st.widths[i] = w;
      st.cols[i].style.width = w + 'px';
      total += w;
    }
    st.table.style.width = total + 'px';
    st.fixed = true;
  }

  function freezeColumns(st) {
    if (st.fixed) return;
    var widths = [];
    for (var i = 0; i < st.ths.length; i++) {
      widths.push(st.ths[i].getBoundingClientRect().width);
    }
    applyFixed(st, widths, false);
  }

  function resetColumnWidth(st, idx) {
    freezeColumns(st);
    var w = defaultWidthFor(st.tableId, idx, containerWidth(st));
    st.widths[idx] = w;
    st.cols[idx].style.width = w + 'px';
    setTableWidth(st);
    saveColWidths();
  }

  function onKey(ev, st, idx) {
    if (ev.key !== 'ArrowLeft' && ev.key !== 'ArrowRight' && ev.key !== 'Home') return;
    ev.preventDefault();
    if (ev.key === 'Home') {
      resetColumnWidth(st, idx);
      return;
    }
    var floor = floorFor(st, idx);
    freezeColumns(st);
    var delta = ev.key === 'ArrowRight' ? 8 : -8;
    var w = clampColWidth(st.widths[idx] + delta, floor);
    st.widths[idx] = w;
    st.cols[idx].style.width = w + 'px';
    setTableWidth(st);
    saveColWidths();
  }

  function startDrag(ev, st, idx, handle) {
    if (ev.button != null && ev.button !== 0) return;
    ev.preventDefault();
    ev.stopPropagation();
    if (handle.focus) handle.focus({ preventScroll: true });
    var startX = ev.clientX;
    var startWidth = st.ths[idx].getBoundingClientRect().width;
    var floor = floorFor(st, idx);
    var moved = false;

    function onMove(e) {
      var dx = e.clientX - startX;
      if (!moved && dx === 0) return;
      if (!moved) {
        freezeColumns(st);
        moved = true;
        document.body.classList.add('col-resizing');
      }
      var w = clampColWidth(startWidth + dx, floor);
      st.widths[idx] = w;
      st.cols[idx].style.width = w + 'px';
      setTableWidth(st);
    }

    function finish() {
      handle.removeEventListener('pointermove', onMove);
      handle.removeEventListener('pointerup', finish);
      handle.removeEventListener('pointercancel', finish);
      try {
        if (handle.hasPointerCapture && handle.hasPointerCapture(ev.pointerId)) {
          handle.releasePointerCapture(ev.pointerId);
        }
      } catch (e) { /* 捕获已释放 */ }
      document.body.classList.remove('col-resizing');
      if (moved) saveColWidths();
    }

    if (handle.setPointerCapture) {
      try { handle.setPointerCapture(ev.pointerId); } catch (e) { /* 不支持捕获时退化为冒泡 */ }
    }
    handle.addEventListener('pointermove', onMove);
    handle.addEventListener('pointerup', finish);
    handle.addEventListener('pointercancel', finish);
  }

  function addHandle(st, idx) {
    var th = st.ths[idx];
    var handle = document.createElement('span');
    var label = (th.textContent || '').replace(/\s+/g, ' ').trim();
    handle.className = 'col-resizer';
    handle.setAttribute('role', 'separator');
    handle.setAttribute('aria-orientation', 'vertical');
    handle.setAttribute('tabindex', '0');
    handle.setAttribute('aria-label', '调整' + (label || '该列') + '列宽');
    handle.addEventListener('pointerdown', function (ev) { startDrag(ev, st, idx, handle); });
    handle.addEventListener('dblclick', function (ev) {
      ev.preventDefault();
      resetColumnWidth(st, idx);
    });
    handle.addEventListener('keydown', function (ev) { onKey(ev, st, idx); });
    th.appendChild(handle);
  }

  function initTableColumns(tableId) {
    var defaults = COLUMN_DEFAULTS[tableId];
    var table = tableEl(tableId);
    if (!defaults || !table) return;
    var ths = table.querySelectorAll('thead th');
    if (ths.length !== defaults.length) return;
    var st = states[tableId];
    if (st) return;
    st = states[tableId] = {
      tableId: tableId,
      table: table,
      ths: ths,
      cols: [],
      widths: [],
      fixed: false
    };
    var group = document.createElement('colgroup');
    for (var i = 0; i < ths.length; i++) {
      var col = document.createElement('col');
      col.style.width = defaults[i] + '%';
      group.appendChild(col);
      st.cols.push(col);
    }
    table.insertBefore(group, table.firstChild);
    for (i = 0; i < ths.length; i++) addHandle(st, i);
    var saved = loadColWidths();
    if (saved[tableId] && saved[tableId].length === ths.length) {
      applyFixed(st, saved[tableId], true);
    }
  }

  function cookieValue(name) {
    var m = document.cookie.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]*)'));
    return m ? decodeURIComponent(m[1]) : '';
  }

  function loadColWidths() {
    try {
      return parseColWidths(cookieValue(COOKIE_NAME), COLUMN_COUNT);
    } catch (e) {
      return {};
    }
  }

  function saveColWidths() {
    var fixed = {};
    Object.keys(states).forEach(function (k) {
      var st = states[k];
      if (st && st.fixed) fixed[k] = st.widths.slice();
    });
    var map = mergeColWidths(loadColWidths(), fixed);
    try {
      var value = encodeColWidths(map);
      if (value) {
        document.cookie = COOKIE_NAME + '=' + value + ';path=/;max-age=31536000;samesite=lax';
      }
    } catch (e) { /* Cookie 不可用时仅保留内存状态 */ }
  }

  /* @veil-testable:start */
  var MIN_WIDTH = 56;
  var MAX_WIDTH = 2000;

  function columnFloor(defaultWidth) {
    var d = Number(defaultWidth);
    if (!isFinite(d) || d <= 0) return MIN_WIDTH;
    return Math.min(MIN_WIDTH, d);
  }

  function clampColWidth(v, floor) {
    var f = isFinite(Number(floor)) ? Number(floor) : 1;
    if (f < 1) f = 1;
    var n = Number(v);
    if (!isFinite(n)) return f;
    n = Math.round(n);
    if (n < f) return f;
    if (n > MAX_WIDTH) return MAX_WIDTH;
    return n;
  }

  function encodeColWidths(map) {
    var keys = ['ev', 'cmd', 'req'];
    var parts = [];
    for (var i = 0; i < keys.length; i++) {
      var arr = map && map[keys[i]];
      if (!arr || !arr.length) continue;
      parts.push(keys[i] + ':' + arr.join('-'));
    }
    return parts.length ? 'v1.' + parts.join('~') : '';
  }

  function mergeColWidths(saved, current) {
    var out = {};
    var keys = ['ev', 'cmd', 'req'];
    for (var i = 0; i < keys.length; i++) {
      var k = keys[i];
      var old = saved && saved[k];
      if (old && old.length) out[k] = old.slice();
    }
    for (i = 0; i < keys.length; i++) {
      k = keys[i];
      var next = current && current[k];
      if (next && next.length) out[k] = next.slice();
    }
    return out;
  }

  function parseColWidths(raw, expected) {
    var out = {};
    if (!raw || typeof raw !== 'string') return out;
    var s = raw.trim();
    if (s.indexOf('v1.') !== 0) return out;
    s = s.slice(3);
    if (!s) return out;
    var chunks = s.split('~');
    for (var c = 0; c < chunks.length; c++) {
      var chunk = chunks[c];
      var pos = chunk.indexOf(':');
      if (pos <= 0) continue;
      var key = chunk.slice(0, pos);
      if (!expected || !Object.prototype.hasOwnProperty.call(expected, key)) continue;
      var parts = chunk.slice(pos + 1).split('-');
      if (parts.length !== expected[key]) continue;
      var arr = [];
      var bad = false;
      for (var i = 0; i < parts.length; i++) {
        if (!/^\d{1,4}$/.test(parts[i])) { bad = true; break; }
        var n = Number(parts[i]);
        if (!isFinite(n) || n < 1 || n > MAX_WIDTH) { bad = true; break; }
        arr.push(n);
      }
      if (!bad) out[key] = arr;
    }
    return out;
  }
  /* @veil-testable:end */

  window.VEIL_COLUMNS = { init: initTableColumns };
})();
