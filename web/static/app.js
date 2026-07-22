(function () {
  "use strict";

  var TOKEN_KEY = "ecloud_webui_token";

  var state = {
    accounts: [],
    currentId: null,
    loginType: "device_trust",
    mobile: "", // login 接口返回的手机号（对齐 CLI result.mobile）
    selectedDesktop: null, // {instance_id, machine_id, name}
    startingIds: {}, // #75fixaf: id -> true while start in-flight (prevent double-click)
    stoppingIds: {}, // #75fixag: id -> true while stop in-flight
    globalSince: 0,
    /* shared #log-full-modal: "global" | "card" | null — softPoll 不得用卡日志盖运行日志 */
    logModalSource: null,
    logModalAccountId: null,
    pollTimer: null,
    tokenRequired: false,
    setupRequired: false,
    authEnabled: false,
    authSource: "",
    gateMode: ""
  };

  function $(id) { return document.getElementById(id); }

  function getToken() {
    try { return localStorage.getItem(TOKEN_KEY) || ""; } catch (_) { return ""; }
  }
  function setToken(v) {
    try {
      if (v) localStorage.setItem(TOKEN_KEY, v);
      else localStorage.removeItem(TOKEN_KEY);
    } catch (_) {}
  }

  function api(method, path, body) {
    var opts = {
      method: method,
      headers: { "Content-Type": "application/json", "Accept": "application/json" }
    };
    var tok = getToken();
    if (tok) {
      opts.headers["Authorization"] = "Bearer " + tok;
      opts.headers["X-API-Token"] = tok;
    }
    if (body !== undefined && body !== null) opts.body = JSON.stringify(body);
    return fetch(path, opts).then(function (r) {
      return r.json().catch(function () {
        return { ok: false, error: "非 JSON 响应 HTTP " + r.status, status: r.status };
      }).then(function (data) {
        if (data && typeof data === "object") {
          data._http = r.status;
          if (r.status === 401 && data.code !== "TOKEN_INVALID") {
            // normalize
          }
          if (r.status === 401) data.ok = false;
        }
        return data;
      });
    });
  }

  function showCErr(msg) {
    var el = $("c-err");
    var ok = $("c-ok");
    ok.hidden = true;
    if (!msg) { el.hidden = true; el.textContent = ""; return; }
    el.hidden = false;
    el.textContent = msg;
  }
  function showCOk(msg) {
    var el = $("c-ok");
    var er = $("c-err");
    er.hidden = true;
    if (!msg) { el.hidden = true; el.textContent = ""; return; }
    el.hidden = false;
    el.textContent = msg;
  }

  // #75fixr: 爱家式底部 toast 气泡（发码/关键提示用，客户一眼可见）
  function toast(msg, isError) {
    var el = $("toast");
    if (!el) return;
    el.textContent = msg || "";
    el.classList.toggle("error", !!isError);
    el.classList.remove("hidden");
    el.hidden = false;
    clearTimeout(toast._t);
    toast._t = setTimeout(function () {
      el.classList.add("hidden");
      el.hidden = true;
    }, 2800);
  }

  function fmtKa(ka, defaultMode) {
    if (!ka) {
      return {
        running: false, text: "未运行", heart: "-", rounds: "-", mode: defaultMode || "-",
        error: "", health: "", uptime: "-"
      };
    }
    var running = !!(ka.running || ka.is_running);
    var heartVal = ka.heart != null ? ka.heart : ka.last_heart_ok;
    var heartText = heartVal === true ? "True" : (heartVal === false ? "False" : "-");
    var health = ka.health || "";
    var err = ka.last_error || ka.error || "";
    /* #75fixak: health=error 优先于 running，保证异常文案/红卡及时 */
    var text = err || health === "error"
      ? "异常"
      : (running
        ? (health === "ok" ? "运行中" : (health === "starting" ? "启动中" : "运行中"))
        : (ka.status || "已停止"));
    return {
      running: running,
      text: text,
      heart: heartText,
      rounds: ka.rounds != null ? String(ka.rounds) : (ka.round != null ? String(ka.round) : "-"),
      mode: ka.mode || defaultMode || "-",
      uptime: ka.last_uptime || ka.desktop_uptime || ka.uptime || "-",
      error: err,
      health: health
    };
  }

  function updateTopStats() {
    var total = state.accounts.length;
    var running = 0, err = 0;
    state.accounts.forEach(function (a) {
      var k = fmtKa(a.keepalive, "path_b");
      var ak = fmtKa(a.account_keepalive, "account");
      if (k.running || ak.running) running++;
      if (k.error || ak.error || a.last_error) err++;
    });
    var idle = Math.max(0, total - running);
    $("top-stats").querySelector('[data-k="total"]').textContent = "账号 " + total;
    $("top-stats").querySelector('[data-k="running"]').textContent = "保活 " + running;
    $("top-stats").querySelector('[data-k="idle"]').textContent = "空闲 " + idle;
    $("top-stats").querySelector('[data-k="error"]').textContent = "异常 " + err;
  }


  // ---- aijia-style card helpers ----
  if (!state.cardLogs) state.cardLogs = {};
  if (typeof state.configPid === "undefined") state.configPid = null;

  function refreshAccountLogs(id, toast) {
    if (!id) return Promise.resolve();
    return api("GET", "/api/accounts/" + encodeURIComponent(id) + "/logs?limit=40")
      .then(function (res) {
        var entries = (res && (res.logs || res.entries || res.items)) || [];
        if (!Array.isArray(entries) && res && Array.isArray(res)) entries = res;
        state.cardLogs[id] = entries;
        applyLogsToDom(id, !!toast);
        if (toast) showCOk("日志已刷新");
      })
      .catch(function (e) {
        if (toast) showCErr("刷新日志失败: " + e.message);
      });
  }

  function openAccountLogFull(id) {
    /* HARD: never fall back to openLogFull (that resets source=global) */
    state.currentId = id;
    state.logModalSource = "card";
    state.logModalAccountId = id;
    var fullBody = $("log-full-body");
    var modal = $("log-full-modal");
    var title = $("log-full-title");
    if (title) title.textContent = "账号日志";
    if (modal) {
      modal.classList.remove("hidden", "is-hidden");
      modal.classList.add("open", "is-open");
      modal.removeAttribute("hidden");
      modal.setAttribute("aria-hidden", "false");
      modal.style.display = "flex";
      modal.style.visibility = "visible";
      modal.style.opacity = "1";
      modal.style.pointerEvents = "auto";
      modal.style.zIndex = "1200";
      document.body.classList.add("modal-open", "log-modal-open");
    }
    /* paint cached ring immediately so title/body match card, not bottom 运行日志 */
    if (fullBody) renderLogFullBody(id);
    refreshAccountLogs(id).then(function () {
      if (state.logModalSource !== "card" || state.logModalAccountId !== id) return;
      if (title) title.textContent = "账号日志";
      renderLogFullBody(id);
    });
  }

  function openConfigModal(id) {
    var acc = state.accounts.find(function (a) { return a.id === id; });
    if (!acc) { showCErr("账号不存在"); return; }
    state.configPid = id;
    state.currentId = id;
    var modal = $("config-modal");
    var body = $("config-modal-body");
    var err = $("config-modal-err");
    if (err) { err.hidden = true; err.textContent = ""; }
    if (!modal || !body) { showCErr("配置弹层缺失"); return; }
    var intervalSec = acc.keepalive_interval || 300;
    body.innerHTML =
      '<label class="field span-2"><span>显示名</span>' +
        '<input type="text" id="cfg-label" value="' + esc(acc.label || "") + '" /></label>' +
      '<label class="field"><span>账号</span>' +
        '<input type="text" id="cfg-username" value="' + esc(acc.username || "") + '" readonly /></label>' +
      '<label class="field"><span>密码</span>' +
        '<input type="password" id="cfg-password" autocomplete="new-password" placeholder="' +
        (acc.has_password ? "已保存，不改请留空" : "请输入密码") + '" value="" /></label>' +
      '<label class="field span-2"><span>保活间隔（秒，≥30）</span>' +
        '<input type="number" id="cfg-interval" min="30" max="3600" value="' + esc(String(intervalSec)) + '" /></label>' +
      '<div class="field span-2"><span>云桌面</span>' +
        '<div class="field-row">' +
          '<select id="cfg-desktop" class="cfg-desktop-select"><option value="">加载中…</option></select>' +
          '<button type="button" class="btn btn-ghost btn-sm" id="cfg-refresh-desktops">刷新</button>' +
        "</div>" +
        '<p class="field-hint">未登录时请先点底部「登录」；need_sms 时用下方验证码</p>' +
      "</div>" +
      '<div class="field span-2 cfg-sms-block" id="cfg-sms-block">' +
        '<span>短信验证（need_sms 时）</span>' +
        '<div class="field-row">' +
          '<input type="text" id="cfg-code" placeholder="短信验证码" autocomplete="one-time-code" style="flex:1" />' +
          '<button type="button" class="btn btn-ghost btn-sm" id="cfg-send-sms">重发</button>' +
          '<button type="button" class="btn btn-primary btn-sm" id="cfg-verify-sms">验证</button>' +
        "</div>" +
        '<p class="field-hint" id="cfg-sms-hint">手机号由登录接口返回，不占输入位；重发=再次 send</p>' +
      "</div>";
    modal.hidden = false;
    modal.classList.remove("hidden");
    modal.setAttribute("aria-hidden", "false");
    function fillDesktops(list) {
      var sel = $("cfg-desktop");
      if (!sel) return;
      var cur = acc.instance_id || "";
      sel.innerHTML = "";
      if (!list || !list.length) {
        sel.innerHTML = '<option value="">（无桌面 / 未登录）</option>';
        return;
      }
      list.forEach(function (d) {
        var opt = document.createElement("option");
        opt.value = d.instance_id || "";
        opt.textContent = (d.machine_name || d.instance_id || "?") +
          (d.status ? " [" + d.status + "]" : "") +
          (d.vendor ? " · " + d.vendor : "");
        opt.setAttribute("data-machine-id", d.machine_id || "");
        opt.setAttribute("data-machine-name", d.machine_name || "");
        if (d.instance_id === cur) opt.selected = true;
        sel.appendChild(opt);
      });
    }
    function loadDesks() {
      return api("GET", "/api/accounts/" + encodeURIComponent(id) + "/desktops")
        .then(function (res) {
          var list = (res && (res.desktops || res.items)) || [];
          fillDesktops(list);
        })
        .catch(function () { fillDesktops([]); });
    }
    loadDesks();
    var refBtn = $("cfg-refresh-desktops");
    if (refBtn) refBtn.onclick = function () { loadDesks(); };
    /* config modal SMS: align composer / CLI send + verify */
    var sendBtn = $("cfg-send-sms");
    var verifyBtn = $("cfg-verify-sms");
    var hint = $("cfg-sms-hint");
    function cfgMobile() {
      var a = state.accounts.find(function (x) { return x.id === id; });
      return (state.mobile && String(state.mobile)) || (a && (a.mobile || a.phone)) || "";
    }
    if (sendBtn) sendBtn.onclick = function () {
      sendBtn.disabled = true;
      api("POST", "/api/accounts/" + encodeURIComponent(id) + "/send-sms", {})
        .then(function (res) {
          if (res && res.ok === false) throw new Error(res.error || res.message || "发码失败");
          if (res && res.mobile) state.mobile = res.mobile;
          if (hint) hint.textContent = "已发码" + (res && res.mobile ? (" → " + res.mobile) : "") + "，请填验证码";
          showCOk("验证码已发送");
          var left = 60;
          sendBtn.textContent = left + "s";
          var timer = setInterval(function () {
            left--;
            if (left <= 0) {
              clearInterval(timer);
              sendBtn.disabled = false;
              sendBtn.textContent = "重发";
            } else {
              sendBtn.textContent = left + "s";
            }
          }, 1000);
        })
        .catch(function (e) {
          sendBtn.disabled = false;
          showCErr(e.message || "发码失败");
          if (err) { err.hidden = false; err.textContent = e.message; }
        });
    };
    if (verifyBtn) verifyBtn.onclick = function () {
      var codeEl = $("cfg-code");
      var code = (codeEl && codeEl.value || "").trim();
      if (!code) {
        showCErr("请输入验证码");
        if (err) { err.hidden = false; err.textContent = "请输入验证码"; }
        return;
      }
      verifyBtn.disabled = true;
      api("POST", "/api/accounts/" + encodeURIComponent(id) + "/verify-sms", { code: code, mobile: cfgMobile() })
        .then(function (res) {
          verifyBtn.disabled = false;
          if (res && res.ok === false) throw new Error(res.error || res.message || "验证失败");
          showCOk("短信验证成功");
          if (hint) hint.textContent = "验证成功，可刷新桌面或保存";
          return loadDesks();
        })
        .catch(function (e) {
          verifyBtn.disabled = false;
          showCErr(e.message || "验证失败");
          if (err) { err.hidden = false; err.textContent = e.message; }
        });
    };
  }

  function closeConfigModal() {
    state.configPid = null;
    var modal = $("config-modal");
    if (!modal) return;
    modal.hidden = true;
    modal.classList.add("hidden");
    modal.setAttribute("aria-hidden", "true");
  }

  /** 二次确认（对齐爱家 confirmModal） */
  function confirmModal(title, body, okText) {
    return new Promise(function (resolve) {
      var modal = $("confirm-modal");
      var tEl = $("confirm-modal-title");
      var bEl = $("confirm-modal-body");
      var ok = $("confirm-modal-ok");
      var cancel = $("confirm-modal-cancel");
      if (!modal || !ok || !cancel) {
        resolve(window.confirm((title || "") + "\n" + (body || "")));
        return;
      }
      if (tEl) tEl.textContent = title || "确认";
      if (bEl) bEl.textContent = body || "确定？";
      ok.textContent = okText || "确定删除";
      modal.hidden = false;
      modal.classList.remove("hidden");
      modal.setAttribute("aria-hidden", "false");
      var done = function (v) {
        modal.hidden = true;
        modal.classList.add("hidden");
        modal.setAttribute("aria-hidden", "true");
        ok.onclick = null;
        cancel.onclick = null;
        modal.onclick = null;
        resolve(v);
      };
      ok.onclick = function () { done(true); };
      cancel.onclick = function () { done(false); };
      modal.onclick = function (ev) {
        if (ev.target === modal) done(false);
      };
    });
  }

  function onDeleteAccount(id) {
    if (!id) return Promise.resolve();
    var acc = state.accounts.find(function (a) { return a.id === id; }) || {};
    var label = acc.label || acc.username || id;
    return confirmModal(
      "删除账号",
      "确定删除「" + label + "」？删除后无法恢复，进行中的保活也会停止。",
      "确定删除"
    ).then(function (ok) {
      if (!ok) return null;
      return api("DELETE", "/api/accounts/" + encodeURIComponent(id))
        .then(function (res) {
          if (res && res.ok === false) {
            showCErr(res.error || res.message || "删除失败");
            return;
          }
          showCOk("已删除 " + label);
          if (state.configPid === id) closeConfigModal();
          if (state.currentId === id) state.currentId = null;
          return loadAccounts();
        })
        .catch(function (e) {
          showCErr((e && e.message) || "删除失败");
        });
    });
  }

  function saveConfigModal() {
    var id = state.configPid || state.currentId;
    if (!id) return;
    var body = {};
    var labelEl = $("cfg-label");
    var passEl = $("cfg-password");
    var ivEl = $("cfg-interval");
    var deskEl = $("cfg-desktop");
    if (labelEl) body.label = labelEl.value.trim();
    if (passEl && passEl.value) body.password = passEl.value;
    if (ivEl && ivEl.value) body.keepalive_interval = parseInt(ivEl.value, 10);
    if (deskEl && deskEl.value) {
      body.instance_id = deskEl.value;
      var opt = deskEl.options[deskEl.selectedIndex];
      if (opt) {
        body.machine_id = opt.getAttribute("data-machine-id") || "";
        body.machine_name = opt.getAttribute("data-machine-name") || opt.textContent || "";
      }
    }
    var err = $("config-modal-err");
    api("PATCH", "/api/accounts/" + encodeURIComponent(id), body)
      .then(function (res) {
        if (res && res.ok === false) {
          if (err) { err.hidden = false; err.textContent = res.error || "保存失败"; }
          else showCErr(res.error || "保存失败");
          return;
        }
        showCOk("配置已保存");
        closeConfigModal();
        loadAccounts();
      })
      .catch(function (e) {
        if (err) { err.hidden = false; err.textContent = e.message; }
        else showCErr(e.message);
      });
  }

  function loginFromConfigModal() {
    var id = state.configPid || state.currentId;
    if (!id) return;
    var passEl = $("cfg-password");
    var body = {};
    if (passEl && passEl.value) body.password = passEl.value;
    var err = $("config-modal-err");
    api("POST", "/api/accounts/" + encodeURIComponent(id) + "/login", body)
      .then(function (res) {
        /* #75fixal: status=failed / error must NOT fall through as success */
        if (res && (res.ok === false || res.status === "failed" || res.status === "error")) {
          var msg = res.error || res.message || "登录失败";
          if (err) { err.hidden = false; err.textContent = msg; }
          else showCErr(msg);
          return;
        }
        if (res && (res.need_sms || res.needSms || res.status === "need_sms" || (res.data && res.data.need_sms))) {
          if (res.mobile) state.mobile = res.mobile;
          var hint = $("cfg-sms-hint");
          if (hint) hint.textContent = "需要短信验证" + (res.mobile ? (" → " + res.mobile) : "") + "，请填验证码后点验证";
          if (err) { err.hidden = false; err.textContent = "需要短信验证码，请使用下方「重发/验证」"; }
          showCOk("需要短信验证码");
          return;
        }
        if (res && res.mobile) state.mobile = res.mobile;
        showCOk("登录成功，正在刷新桌面…");
        return api("GET", "/api/accounts/" + encodeURIComponent(id) + "/desktops")
          .then(function (r2) {
            var list = (r2 && (r2.desktops || r2.items)) || [];
            var sel = $("cfg-desktop");
            if (!sel) return;
            var acc = state.accounts.find(function (a) { return a.id === id; }) || {};
            var cur = acc.instance_id || "";
            sel.innerHTML = "";
            if (!list.length) {
              sel.innerHTML = '<option value="">（无桌面）</option>';
              return;
            }
            list.forEach(function (d) {
              var opt = document.createElement("option");
              opt.value = d.instance_id || "";
              opt.textContent = (d.machine_name || d.instance_id || "?") +
                (d.status ? " [" + d.status + "]" : "");
              opt.setAttribute("data-machine-id", d.machine_id || "");
              opt.setAttribute("data-machine-name", d.machine_name || "");
              if (d.instance_id === cur) opt.selected = true;
              sel.appendChild(opt);
            });
          });
      })
      .catch(function (e) {
        if (err) { err.hidden = false; err.textContent = e.message; }
        else showCErr(e.message);
      });
  }


  function renderCards() {
    var box = $("timeline");
    var empty = $("empty-state");
    box.innerHTML = "";
    if (!state.accounts.length) {
      empty.hidden = false;
      updateTopStats();
      return;
    }
    empty.hidden = true;
    state.accounts.forEach(function (acc) {
      var k = fmtKa(acc.keepalive, "path_b");
      var aka = fmtKa(acc.account_keepalive, "account");
      var running = !!k.running;
      /* #75fixak: 有 error/health=error 时卡边框立刻红；running 仅决定启停钮 */
      var hasErr = !!(k.error || aka.error || (k.health === "error") || (aka.health === "error"));
      var st = hasErr ? "error" : (running ? "running" : "idle");
      var statusText = hasErr ? "异常" : (running ? "保活中" : "空闲");
      var name = acc.label || acc.username || acc.id;
      var user = acc.username || "未设置账号";
      var deskName = acc.machine_name || "";
      var deskId = acc.instance_id || "";
      var deskShort = deskName || (deskId ? deskId.slice(0, 12) + "…" : "未选桌面");
      var intervalSec = acc.keepalive_interval || 300;
      var intervalMin = Math.max(1, Math.round(intervalSec / 60));
      var errLine = (k.error || aka.error || acc.last_error || "").trim();
      var logs = (state.cardLogs && state.cardLogs[acc.id]) || [];
      var logHtml = "";
      if (logs.length) {
        logHtml = logs.slice(-6).map(function (line) {
          var t = typeof line === "string" ? line : (line.msg || line.message || JSON.stringify(line));
          var lv = (typeof line === "object" && line.level) ? String(line.level).toLowerCase() : "info";
          if (lv.indexOf("err") >= 0) lv = "error";
          else if (lv.indexOf("warn") >= 0) lv = "warn";
          else lv = "info";
          return '<div class="log-line level-' + lv + '">' + esc(String(t)) + "</div>";
        }).join("");
      } else {
        logHtml = '<div class="log-line level-info">暂无日志 · 双击查看全部</div>';
      }
      /* 对齐爱家 cardHtml：开始保活/停止保活 二合一 + 日志头常显 */
      /* #75fixaf: starting → 禁点「启动中…」；#75fixag: stopping → 「停止中…」 */
      /* #75fixak: 循环仍在跑时只显示停止（可中断）；running=false 才显示启动 */
      var starting = !!(state.startingIds && state.startingIds[acc.id]);
      var stopping = !!(state.stoppingIds && state.stoppingIds[acc.id]);
      var startStopBtn = running
        ? (stopping
          ? '<button type="button" class="btn btn-stop" data-act="stop" disabled>停止中…</button>'
          : '<button type="button" class="btn btn-stop" data-act="stop">停止保活</button>')
        : (starting
          ? '<button type="button" class="btn btn-start btn-primary" data-act="start" disabled>启动中…</button>'
          : '<button type="button" class="btn btn-start btn-primary" data-act="start">启动保活</button>');
      var article = document.createElement("article");
      article.className = "card status-" + st + (state.configPid === acc.id ? " is-configuring" : "");
      article.setAttribute("data-id", acc.id);
      article.innerHTML =
        '<header class="card-head">' +
          '<div class="card-title">' +
            '<span class="status-dot" aria-hidden="true"></span>' +
            "<div>" +
              '<p class="card-name">' + esc(name) + "</p>" +
              '<p class="card-meta">' + esc(user) + " · " + esc(deskShort) + "</p>" +
            "</div>" +
          "</div>" +
          '<span class="badge badge-' + st + '">' + esc(statusText) + "</span>" +
        "</header>" +
        '<div class="card-summary">' +
          "<div><span>云桌面</span><strong>" + esc(deskShort) + "</strong></div>" +
          "<div><span>间隔</span><strong>" + esc(String(intervalMin)) + " 分钟</strong></div>" +
          "<div><span>账号保活</span><strong>" + esc(aka.running ? "自动·运行中" : "自动·待命") + "</strong></div>" +
          "<div><span>心跳</span><strong>" + esc(k.heart || "-") + "</strong></div>" +
          "<div><span>轮次</span><strong>" + esc(String(k.rounds || "-")) + "</strong></div>" +
          "<div><span>在线时长</span><strong>" + esc(k.uptime && k.uptime !== "-" ? k.uptime : "—") + "</strong></div>" +
        "</div>" +
        (errLine ? '<p class="card-error" role="alert">' + esc(errLine) + "</p>" : "") +
        '<div class="card-surface">' +
          '<div class="card-actions">' +
            startStopBtn +
            '<button type="button" class="btn btn-ghost" data-act="config">配置</button>' +
            '<button type="button" class="btn btn-ghost" data-act="logs" title="刷新本卡片日志显示（不影响保活任务）">刷新日志</button>' +
            '<button type="button" class="btn btn-ghost btn-danger-ghost" data-act="clear-logs" title="清空本卡片日志（不影响保活任务）">清除日志</button>' +
          "</div>" +
          '<div class="card-log card-log-expanded" data-act="log-open" title="双击查看本账号完整日志">' +
            '<div class="log-panel-head"><span>账号日志（双击查看全部）</span></div>' +
            '<div class="log-box">' + logHtml + "</div>" +
          "</div>" +
        "</div>";
      box.appendChild(article);
    });
    // bind actions
    box.querySelectorAll(".card").forEach(function (card) {
      var id = card.getAttribute("data-id");
      card.querySelectorAll("[data-act]").forEach(function (btn) {
        var act = btn.getAttribute("data-act");
        if (act === "log-open") {
          btn.addEventListener("dblclick", function (ev) {
            ev.preventDefault();
            openAccountLogFull(id);
          });
          return;
        }
        btn.addEventListener("click", function (ev) {
          ev.preventDefault();
          onCardAction(id, act, card);
        });
      });
    });
    updateTopStats();
  }

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }


  /* ---- #75fixm 爱家 needFull / applyLogs 防闪 ---- */
  function accountFingerprint(a) {
    /* #75fixak: API 字段是 last_error/health/last_heart_ok/rounds；旧 k.error 恒空导致 needFull 漏触发 */
    if (!a) return "";
    var k = a.keepalive || {};
    var ak = a.account_keepalive || {};
    return [
      a.id,
      a.label || "",
      a.username || "",
      a.instance_id || "",
      a.machine_name || "",
      a.machine_id || "",
      a.keepalive_interval || "",
      a.last_error || "",
      k.running ? 1 : 0,
      k.last_error || k.error || "",
      k.health || "",
      k.last_heart_ok === true ? "1" : (k.last_heart_ok === false ? "0" : ""),
      k.rounds != null ? String(k.rounds) : "",
      ak.running ? 1 : 0,
      ak.last_error || ak.error || "",
      ak.health || "",
      a.logged_in ? 1 : 0
    ].join("|");
  }

  function isKeepaliveLogLine(line) {
    /* #75fixz: Path B / 账号保活优先，避免登录三件套占满 6 行外露 */
    var t = typeof line === "string" ? line : (line && (line.msg || line.message || line.text)) || "";
    t = String(t);
    return (
      t.indexOf("Path B") >= 0 ||
      t.indexOf("账号保活") >= 0 ||
      t.indexOf("[账号保活]") >= 0 ||
      /heart\s*=/i.test(t) ||
      t.indexOf("保活成功") >= 0 ||
      t.indexOf("保活失败") >= 0 ||
      t.indexOf("保活异常") >= 0
    );
  }

  function isLoginNoiseLine(line) {
    var t = typeof line === "string" ? line : (line && (line.msg || line.message || line.text)) || "";
    t = String(t);
    return (
      t.indexOf("登录中:") === 0 ||
      t.indexOf("登录中: ") >= 0 ||
      t.indexOf("登录结果:") === 0 ||
      t.indexOf("登录结果: ") >= 0 ||
      t === "登录成功" ||
      t.indexOf("登录成功") === 0
    );
  }

  function pickCompactCardLogs(entries, maxN) {
    maxN = maxN || 6;
    if (!entries || !entries.length) return [];
    var ka = [];
    var rest = [];
    for (var i = 0; i < entries.length; i++) {
      var e = entries[i];
      if (isKeepaliveLogLine(e)) ka.push(e);
      else if (!isLoginNoiseLine(e)) rest.push(e);
      /* login noise dropped from compact view; still in full modal */
    }
    var out = ka.slice(-maxN);
    if (out.length < maxN) {
      var need = maxN - out.length;
      out = rest.slice(-need).concat(out);
    }
    /* keep chronological order */
    out.sort(function (a, b) {
      var sa = (a && (a.seq || 0)) || 0;
      var sb = (b && (b.seq || 0)) || 0;
      if (sa !== sb) return sa - sb;
      var ta = (a && a.ts) || "";
      var tb = (b && b.ts) || "";
      return ta < tb ? -1 : ta > tb ? 1 : 0;
    });
    return out.slice(-maxN);
  }

  function formatLogLineHtml(line) {
    var t = typeof line === "string" ? line : (line.msg || line.message || line.text || JSON.stringify(line));
    var lv = (typeof line === "object" && (line.level || line.lvl)) ? String(line.level || line.lvl).toLowerCase() : "info";
    if (lv.indexOf("err") >= 0) lv = "error";
    else if (lv.indexOf("warn") >= 0) lv = "warn";
    else lv = "info";
    var ts = (typeof line === "object" && line.ts) ? String(line.ts) + " " : "";
    return '<div class="log-line level-' + lv + '">' + esc(ts + String(t)) + "</div>";
  }

  function isLogFullModalOpen() {
    var modal = $("log-full-modal");
    if (!modal) return false;
    return !modal.hidden && !modal.classList.contains("hidden");
  }

  function syncGlobalLogModalBody() {
    /* only when modal is showing bottom 运行日志 (not card ring) */
    if (state.logModalSource !== "global") return;
    if (!isLogFullModalOpen()) return;
    var src = $("global-log");
    var body = $("log-full-body");
    if (!src || !body) return;
    body.innerHTML = src.innerHTML || '<div class="log-line">暂无日志</div>';
    try {
      body.scrollTop = body.scrollHeight;
    } catch (e) {}
  }

  function renderLogFullBody(id) {
    /* HARD: softPoll/card refresh must NEVER overwrite bottom 运行日志 modal */
    if (state.logModalSource !== "card") return;
    var fullBody = $("log-full-body");
    var modal = $("log-full-modal");
    if (!fullBody || !modal) return;
    if (!isLogFullModalOpen()) return;
    var target = id || state.logModalAccountId || state.currentId;
    if (state.logModalAccountId && target && state.logModalAccountId !== target) return;
    var entries = state.cardLogs[target] || [];
    fullBody.innerHTML = entries.length
      ? entries.map(formatLogLineHtml).join("")
      : '<div class="log-line">暂无日志</div>';
    try {
      fullBody.scrollTop = fullBody.scrollHeight;
    } catch (e) {}
  }

  function applyLogsToDom(id, force) {
    var entries = state.cardLogs[id] || [];
    var fp = entries.length + ":" + (entries.length ? (entries[entries.length - 1].seq || entries[entries.length - 1].ts || entries.length) : "0");
    state._logFp = state._logFp || {};
    if (!force && state._logFp[id] === fp) {
      /* still sync full modal if open */
      renderLogFullBody(id);
      return;
    }
    state._logFp[id] = fp;
    var card = document.querySelector('.card[data-id="' + id + '"]');
    if (card) {
      var box = card.querySelector(".log-box");
      if (box) {
        var logs = pickCompactCardLogs(entries, 6);
        if (!logs.length) {
          box.innerHTML = '<div class="log-line level-info">暂无日志 · 双击查看全部</div>';
        } else {
          box.innerHTML = logs.map(formatLogLineHtml).join("");
        }
      }
    }
    /* #75fixz: 全量弹窗打开时 softPoll 同步 body */
    renderLogFullBody(id);
  }

  function softPollAccounts() {
    /* 爱家 needFull：指纹不变只刷日志；配置弹窗打开时绝不整卡重渲 */
    return api("GET", "/api/accounts").then(function (res) {
      var list = res.accounts || res.data || [];
      if (!Array.isArray(list)) list = [];
      if (state.configPid) {
        state.accounts = list;
        updateTopStats();
        list.forEach(function (a) { refreshAccountLogs(a.id, false); });
        return;
      }
      var prev = state.accounts || [];
      var prevMap = {};
      prev.forEach(function (a) { prevMap[a.id] = accountFingerprint(a); });
      var needFull = list.length !== prev.length;
      if (!needFull) {
        for (var i = 0; i < list.length; i++) {
          var id = list[i].id;
          if (!prevMap[id] || prevMap[id] !== accountFingerprint(list[i])) {
            needFull = true;
            break;
          }
        }
      }
      var savedLogs = state.cardLogs || {};
      state.accounts = list;
      updateTopStats();
      if (needFull) {
        renderCards();
        state.cardLogs = savedLogs;
        list.forEach(function (a) {
          if (savedLogs[a.id] && savedLogs[a.id].length) applyLogsToDom(a.id, true);
          else refreshAccountLogs(a.id, false);
        });
      } else {
        list.forEach(function (a) { refreshAccountLogs(a.id, false); });
      }
    }).catch(function () {});
  }

  /* #75fixal: after start/stop, burst-poll so red-card/button catches up faster than 5s tick */
  function softPollBurst(times, gapMs) {
    times = times || 4;
    gapMs = gapMs || 700;
    var n = 0;
    function tick() {
      softPollAccounts();
      n += 1;
      if (n < times) setTimeout(tick, gapMs);
    }
    tick();
  }


  function loadAccounts() {
    return api("GET", "/api/accounts").then(function (res) {
      var list = res.accounts || res.data || [];
      if (!Array.isArray(list) && res.ok === false) {
        showCErr(res.error || "加载账号失败");
        list = [];
      }
      state.accounts = list;
      renderCards();
      /* card-logs-hook */
      (state.accounts || []).forEach(function (a) { refreshAccountLogs(a.id); });
      return list;
    }).catch(function (e) {
      showCErr("加载账号失败: " + e.message);
    });
  }

  // #75fixr: 仅当表单账号与 current 卡 username 一致时复用；否则新建第二张卡
  // （旧逻辑无脑复用 currentId，导致第二账号登录覆盖第一张卡）
  function ensureAccount() {
    var username = $("c-username").value.trim();
    var password = $("c-password").value;
    var label = $("c-label").value.trim();
    if (!username || !password) {
      showCErr("请输入账号和密码");
      return Promise.reject(new Error("missing creds"));
    }
    if (state.currentId) {
      var cur = state.accounts.find(function (a) { return a.id === state.currentId; });
      var curUser = ((cur && cur.username) || "").trim();
      if (curUser && curUser === username) {
        return Promise.resolve(state.currentId);
      }
      // 表单账号不同 → 明确新建，避免 login 改写已有卡
      state.currentId = null;
    }
    // 若列表里已有同 username 的卡，复用该卡（不重复建）
    var exist = state.accounts.find(function (a) {
      return ((a.username || "").trim() === username);
    });
    if (exist && exist.id) {
      state.currentId = exist.id;
      return Promise.resolve(exist.id);
    }
    return api("POST", "/api/accounts", {
      label: label || username,
      username: username,
      password: password
    }).then(function (res) {
      if (!res.ok && !res.account) {
        throw new Error(res.error || "创建账号失败");
      }
      var acc = res.account || res;
      state.currentId = acc.id;
      return loadAccounts().then(function () { return acc.id; });
    });
  }

  // 短信区常显；对齐 CLI main.py login 分支：
  // mobile 不占 UI：仅 state.mobile = login 回包（对齐 CLI result.mobile）；用户只输验证码
  function maskMobile(m) {
    m = (m || "").trim();
    if (m.length < 7) return m || "（未返回）";
    return m.slice(0, 3) + "****" + m.slice(-4);
  }

  function setSmsMobile(mobile) {
    state.mobile = (mobile || "").trim();
  }

  function getSmsMobile() {
    return (state.mobile || "").trim();
  }

  function setSmsHint(msg, mobile) {
    if (msg && $("c-sms-msg")) $("c-sms-msg").textContent = msg;
    if (mobile !== undefined && mobile !== null) setSmsMobile(mobile);
  }

  function resetSmsHint() {
    state.mobile = "";
    state.loginType = "";
    $("c-code").value = "";
    setSmsHint("公众 e 云 Path B（CLI 壳）。账密 → 登录；need_sms 时接口自带手机号并自动发码，你只需填验证码 → 选桌面启动保活。");
  }

  function startSendCooldown(btn) {
    var n = 60;
    btn.disabled = true;
    btn.textContent = n + "s";
    var t = setInterval(function () {
      n--;
      btn.textContent = n + "s";
      if (n <= 0) { clearInterval(t); btn.disabled = false; btn.textContent = "重发"; }
    }, 1000);
  }

  // 对齐 CLI：拿到 mobile 后立刻 send_sms，不要求用户点「发送」
  function autoSendSms() {
    if (!state.currentId) return Promise.resolve();
    var mobile = getSmsMobile();
    // 无 mobile 时不自动发（等用户在 fallback 手填后再点重发）
    if (!mobile) return Promise.resolve({ ok: false, skipped: true });
    return api("POST", "/api/accounts/" + encodeURIComponent(state.currentId) + "/send-sms", {
      mobile: mobile
    }).then(function (res) {
      if (res.ok === false) {
        showCErr(res.error || "自动发送验证码失败，可点「重发」");
        toast(res.error || "验证码发送失败", true);
        return res;
      }
      var okMsg = "验证码发送成功 · 已发至 " + maskMobile(res.mobile || mobile);
      showCOk(okMsg + "，请填写短信验证码");
      toast("验证码发送成功");
      startSendCooldown($("c-send-sms"));
      try { $("c-code").focus(); } catch (e) {}
      return res;
    }).catch(function (e) {
      showCErr(e.message || String(e));
      toast(e.message || "验证码发送失败", true);
    });
  }

  function doLogin() {
    showCErr("");
    showCOk("");
    resetSmsHint();
    var username = $("c-username").value.trim();
    var password = $("c-password").value;
    if (!username || !password) { showCErr("请输入账号和密码"); return; }
    var btn = $("c-login");
    btn.disabled = true;
    btn.textContent = "登录中...";
    ensureAccount().then(function (id) {
      return api("POST", "/api/accounts/" + encodeURIComponent(id) + "/login", {
        username: username,
        password: password
      });
    }).then(function (res) {
      // Align CLI: password first → success | need_sms | failed
      /* #75fixal: explicit failed before success heuristics */
      if (res && (res.status === "failed" || res.status === "error" || res.ok === false)) {
        showCErr(res.error || res.message || "登录失败");
        return;
      }
      if (res.status === "need_sms") {
        state.loginType = res.login_type || "device_trust";
        var mob = res.mobile || "";
        setSmsHint(
          (res.message || "需要短信验证") + "。手机号来自登录接口（" + maskMobile(mob) + "），只需填写验证码。",
          mob
        );
        // CLI 在 need_* 分支内自动 send_sms，再 input sms code
        return autoSendSms();
      }
      if (res.status === "success" || (res.ok === true && res.status !== "need_sms" && !res.error)) {
        setSmsHint("登录已成功，无需短信。若后续设备需再授权，仍可在此验证。", "");
        showCOk("登录成功，请选择要保活的云电脑");
        return afterLoginReady();
      }
      showCErr(res.error || res.message || "登录失败");
    }).catch(function (e) {
      showCErr(e.message || String(e));
    }).finally(function () {
      btn.disabled = false;
      btn.textContent = "登录";
      loadAccounts();
    });
  }

  function afterLoginReady() {
    return refreshDesktops();
  }

  function refreshDesktops() {
    if (!state.currentId) {
      showCErr("请先登录");
      return Promise.resolve();
    }
    $("c-desktop-list").innerHTML = '<p class="hint">加载桌面中...</p>';
    return api("GET", "/api/accounts/" + encodeURIComponent(state.currentId) + "/desktops")
      .then(function (res) {
        var list = res.desktops || [];
        if (res.error) {
          $("c-desktop-list").innerHTML = '<p class="composer-err">' + esc(res.error) + "</p>";
          return;
        }
        if (!list.length) {
          $("c-desktop-list").innerHTML = '<p class="hint">未找到云电脑</p>';
          $("c-start").disabled = true;
          return;
        }
        var html = "";
        list.forEach(function (d, i) {
          var iid = d.instance_id || d.instanceId || d.id || "";
          var mid = d.machine_id || d.machineId || "";
          var name = d.machine_name || d.name || d.display_name || iid || ("桌面" + (i + 1));
          var vendor = d.vendor || d.origin_company_code || "";
          var status = d.status || "?";
          var checked = i === 0 ? " checked" : "";
          if (i === 0) {
            state.selectedDesktop = { instance_id: iid, machine_id: mid, name: name };
          }
          // Layout mirrors CLI list-desktops: name + status/vendor + instance/machine
          html +=
            '<label class="desktop-item">' +
              '<input type="radio" name="desktop" value="' + esc(iid) + '" data-mid="' + esc(mid) + '" data-name="' + esc(name) + '"' + checked + ' />' +
              '<span class="desktop-meta">' +
                '<span class="desktop-name">' + esc(name) + '</span>' +
                '<span class="desktop-sub">' +
                  '<span class="desktop-status" data-status="' + esc(String(status)) + '">' + esc(String(status)) + '</span>' +
                  (vendor ? '<span class="desktop-vendor">' + esc(vendor) + '</span>' : '') +
                '</span>' +
                '<span class="desktop-id">instance=' + esc(iid) + '</span>' +
                (mid ? '<span class="desktop-id">machine=' + esc(mid) + '</span>' : '') +
              '</span>' +
            '</label>';
        });
        $("c-desktop-list").innerHTML = html;
        $("c-start").disabled = false;
        $("c-desktop-list").querySelectorAll('input[name="desktop"]').forEach(function (inp) {
          inp.addEventListener("change", function () {
            state.selectedDesktop = {
              instance_id: inp.value,
              machine_id: inp.getAttribute("data-mid") || "",
              name: inp.getAttribute("data-name") || ""
            };
          });
        });
      });
  }

  function startFromComposer() {
    if (!state.currentId) { showCErr("请先登录"); return; }
    var d = state.selectedDesktop;
    if (!d || !d.instance_id) { showCErr("请选择云电脑"); return; }
    var id = state.currentId;
    /* #75fixaf: share startingIds with card so softPoll shows 启动中… */
    if (state.startingIds[id]) return;
    var interval = parseInt($("c-interval").value, 10) || 300;
    var btn = $("c-start");
    state.startingIds[id] = true;
    btn.disabled = true;
    btn.textContent = "启动中…";
    loadAccounts();
    api("POST", "/api/accounts/" + encodeURIComponent(id) + "/keepalive/start", {
      instance_id: d.instance_id,
      machine_id: d.machine_id || "",
      interval: interval
    }).then(function (res) {
      if (res.ok === false) {
        showCErr(res.error || "启动失败");
        return;
      }
      showCOk("已启动 Path B 保活 · HEART=" + String(res.heart != null ? res.heart : (res.keepalive && res.keepalive.heart)));
      loadAccounts();
      pullGlobalLogs(true);
    }).catch(function (e) {
      showCErr(e.message);
    }).finally(function () {
      delete state.startingIds[id];
      btn.disabled = false;
      btn.textContent = "启动保活";
      loadAccounts();
      softPollBurst(4, 700); /* #75fixal */
    });
  }

  function onCardAction(id, act, card) {
    state.currentId = id;
    if (act === "start") {
      /* #75fixaf: FE in-flight guard — softPoll re-render also honors startingIds */
      if (state.startingIds[id]) return;
      var acc = state.accounts.find(function (a) { return a.id === id; });
      var body = {
        instance_id: (acc && acc.instance_id) || "",
        machine_id: (acc && acc.machine_id) || "",
        interval: (acc && acc.keepalive_interval) || 300
      };
      if (!body.instance_id) {
        showCErr("该账号尚无绑定桌面：请先点「配置」选择云电脑");
        openConfigModal(id);
        return;
      }
      state.startingIds[id] = true;
      var startBtn = card && card.querySelector('[data-act="start"]');
      if (startBtn) {
        startBtn.disabled = true;
        startBtn.textContent = "启动中…";
      }
      api("POST", "/api/accounts/" + encodeURIComponent(id) + "/keepalive/start", body)
        .then(function (res) {
          if (res.ok === false) showCErr(res.error || "启动失败");
          else showCOk("已启动桌面保活（账号态已随 CLI 自动开启）");
          loadAccounts();
          refreshAccountLogs(id);
        })
        .catch(function (e) { showCErr(e.message); })
        .then(function () {
          delete state.startingIds[id];
          loadAccounts();
          softPollBurst(4, 700); /* #75fixal */
        });
      return;
    }
    if (act === "stop") {
      /* #75fixag: FE 停止中禁点；BE 已非阻塞 stop，API 应立刻返回 */
      if (state.stoppingIds[id]) return;
      state.stoppingIds[id] = true;
      loadAccounts();
      api("POST", "/api/accounts/" + encodeURIComponent(id) + "/keepalive/stop")
        .then(function (res) {
          if (res && res.ok === false) showCErr(res.error || "停止失败");
          else showCOk("已停止桌面保活（账号保活已同步停止）");
        })
        .catch(function (e) { showCErr(e.message); })
        .then(function () {
          delete state.stoppingIds[id];
          loadAccounts();
          softPollBurst(4, 700); /* #75fixal */
        });
      return;
    }
    if (act === "logs") {
      refreshAccountLogs(id, true);
      return;
    }
    if (act === "config") {
      openConfigModal(id);
      return;
    }
    if (act === "clear-logs") {
      /* HARD_GATE#853: real backend clear (not FE-only fake clear) */
      var btn = card && card.querySelector('[data-act="clear-logs"]');
      if (btn) btn.disabled = true;
      api("DELETE", "/api/accounts/" + encodeURIComponent(id) + "/logs")
        .then(function (res) {
          if (btn) btn.disabled = false;
          if (res && res.ok === false) {
            showCErr(res.error || "清空日志失败");
            return;
          }
          state.cardLogs[id] = [];
          applyLogsToDom(id, true);
          showCOk("日志已清空");
        })
        .catch(function (e) {
          if (btn) btn.disabled = false;
          showCErr(e.message || "清空日志失败");
        });
      return;
    }
  }

  // SMS：对齐 CLI —— mobile 仅来自 login 回包；用户只输验证码；「重发」= 再次 send
  $("c-send-sms").onclick = function () {
    if (!state.currentId) { showCErr("请先点登录"); return; }
    var mobile = getSmsMobile();
    if (!mobile) { showCErr("请先登录；手机号由接口返回"); return; }
    var btn = this;
    btn.disabled = true;
    api("POST", "/api/accounts/" + encodeURIComponent(state.currentId) + "/send-sms", { mobile: mobile })
      .then(function (res) {
        if (res.ok === false) {
          showCErr(res.error || "发送失败");
          toast(res.error || "验证码发送失败", true);
          btn.disabled = false;
          return;
        }
        if (res.mobile) setSmsMobile(res.mobile);
        showCOk("验证码已发送至 " + maskMobile(res.mobile || mobile));
        toast("验证码发送成功");
        startSendCooldown(btn);
        try { $("c-code").focus(); } catch (e) {}
      }).catch(function (e) {
        showCErr(e.message);
        toast(e.message || "验证码发送失败", true);
        btn.disabled = false;
      });
  };

  $("c-verify-sms").onclick = function () {
    if (!state.currentId) { showCErr("请先点登录"); return; }
    var mobile = getSmsMobile();
    var code = $("c-code").value.trim();
    if (!code) { showCErr("请输入验证码"); return; }
    // 后端会用 session 里的 mobile；前端传空也能工作，但有值时一并带上
    var btn = this;
    btn.disabled = true;
    api("POST", "/api/accounts/" + encodeURIComponent(state.currentId) + "/verify-sms", {
      mobile: mobile,
      code: code,
      login_type: state.loginType
    }).then(function (res) {
      if (res.status === "success" || res.ok) {
        setSmsHint("短信验证已通过。", state.mobile || "");
        showCOk("短信验证成功，请选择要保活的云电脑");
        return afterLoginReady();
      }
      showCErr(res.error || res.message || "验证失败");
    }).catch(function (e) {
      showCErr(e.message);
    }).finally(function () {
      btn.disabled = false;
      loadAccounts();
    });
  };

  function pullGlobalLogs(force) {
    var q = force ? 0 : state.globalSince;
    return api("GET", "/api/global-logs?since=" + q).then(function (res) {
      var logs = res.logs || [];
      if (!logs.length && !force) {
        /* still keep open global modal in sync after clear */
        syncGlobalLogModalBody();
        return;
      }
      var box = $("global-log");
      if (force) box.innerHTML = "";
      logs.forEach(function (e) {
        // backend uses gseq for global_logs; per-account uses seq
        var gs = e.gseq != null ? e.gseq : (e.seq != null ? e.seq : e.id);
        if (gs != null && gs > state.globalSince) state.globalSince = gs;
        var line = document.createElement("div");
        line.className = "log-line level-" + String(e.level || "INFO").toLowerCase();
        var who = e.label || e.account_id || e.account || "";
        line.textContent =
          "[" + (e.level || "INFO") + "] " + (e.ts || "") +
          (who ? " (" + who + ")" : "") + " " + (e.msg || e.message || "");
        box.appendChild(line);
      });
      // cap DOM
      while (box.children.length > 300) box.removeChild(box.firstChild);
      box.scrollTop = box.scrollHeight;
      /* #75fixaa: 运行日志弹窗打开时跟随底部 viewport，不被卡日志污染 */
      syncGlobalLogModalBody();
    }).catch(function () { /* ignore poll errors */ });
  }

  $("c-login").onclick = doLogin;
  $("c-start").onclick = startFromComposer;
  $("c-refresh-desktops").onclick = function () { refreshDesktops(); };
  $("btn-refresh").onclick = function () {
    loadAccounts();
    pullGlobalLogs(true);
  };
  $("btn-clear-log").onclick = function () {
    api("POST", "/api/global-logs/clear")
      .then(function () {
        state.globalSince = 0;
        $("global-log").innerHTML = "";
        /* only wipe modal body when it is showing 运行日志, not account card ring */
        if (state.logModalSource === "global" || !state.logModalSource) {
          var fullBody = $("log-full-body");
          if (fullBody) fullBody.innerHTML = "";
        }
        pullGlobalLogs(true);
      })
      .catch(function (e) {
        toast("清空运行日志失败: " + ((e && e.message) || e), "error");
      });
  };
  $("btn-help").onclick = function () {
    $("help-modal").classList.remove("hidden");
  };
  $("help-close").onclick = function () {
    $("help-modal").classList.add("hidden");
  };

  // 对齐爱家：双击全局日志 → 全量弹窗
  function openLogFull() {
    var src = $("global-log");
    var body = $("log-full-body");
    var modal = $("log-full-modal");
    if (!src || !body || !modal) return;
    state.logModalSource = "global";
    state.logModalAccountId = null;
    var title = $("log-full-title");
    if (title) title.textContent = "运行日志";
    body.innerHTML = src.innerHTML || '<div class="log-line">暂无日志</div>';
    // HARD_GATE 对齐爱家：强制可见 + 高 z-index 压过 toast/其它 modal
    modal.classList.remove("hidden", "is-hidden");
    modal.classList.add("open", "is-open");
    modal.removeAttribute("hidden");
    modal.setAttribute("aria-hidden", "false");
    modal.style.display = "flex";
    modal.style.visibility = "visible";
    modal.style.opacity = "1";
    modal.style.pointerEvents = "auto";
    modal.style.zIndex = "1200";
    document.body.classList.add("modal-open", "log-modal-open");
    try { body.scrollTop = body.scrollHeight; } catch (e) {}
  }
  function closeLogFull() {
    var modal = $("log-full-modal");
    if (!modal) return;
    state.logModalSource = null;
    state.logModalAccountId = null;
    modal.classList.add("hidden");
    modal.classList.remove("open", "is-open");
    modal.setAttribute("hidden", "");
    modal.setAttribute("aria-hidden", "true");
    modal.style.display = "";
    modal.style.visibility = "";
    modal.style.opacity = "";
    modal.style.pointerEvents = "";
    modal.style.zIndex = "";
    document.body.classList.remove("modal-open", "log-modal-open");
  }
  (function bindLogFull() {
    var g = $("global-log");
    if (g) {
      g.addEventListener("dblclick", function (ev) {
        ev.preventDefault();
        openLogFull();
      });
    }
    // 完整日志按钮已删；对齐爱家：双击运行日志打开二级页
    var closeBtn = $("log-full-close");
    if (closeBtn) closeBtn.addEventListener("click", closeLogFull);
    var modal = $("log-full-modal");
    if (modal) {
      modal.addEventListener("click", function (ev) {
        if (ev.target === modal) closeLogFull();
      });
    }
    document.addEventListener("keydown", function (ev) {
      if (ev.key === "Escape") {
        var m = $("log-full-modal");
        if (m && !m.classList.contains("hidden") && !m.hasAttribute("hidden")) {
          closeLogFull();
        }
      }
    });
  })();

  
  function setGateErr(msg, which) {
    var setup = $("gate-setup-err");
    var login = $("gate-login-err");
    if (which === "setup" || !which) {
      if (setup) setup.textContent = msg || "";
    }
    if (which === "login" || !which) {
      if (login) login.textContent = msg || "";
    }
    if (which === "setup") { if (login) login.textContent = ""; }
    if (which === "login") { if (setup) setup.textContent = ""; }
  }

  function showAccessGate(mode) {
    var gate = $("access-gate");
    var app = $("app");
    if (!gate) return;
    state.gateMode = mode || (state.setupRequired ? "setup" : "login");
    gate.classList.remove("hidden");
    gate.removeAttribute("hidden");
    gate.hidden = false;
    gate.setAttribute("aria-hidden", "false");
    if (app) {
      app.classList.add("gate-locked");
      app.setAttribute("aria-hidden", "true");
    }
    var title = $("gate-title");
    var sub = $("gate-sub");
    var setupPane = $("gate-setup-panel");
    var loginPane = $("gate-login-panel");
    if (state.gateMode === "setup") {
      if (title) title.textContent = "设置访问密钥";
      if (sub) sub.textContent = "首次部署可选：保护控制台，之后可在顶栏修改。";
      if (setupPane) setupPane.classList.remove("hidden");
      if (loginPane) loginPane.classList.add("hidden");
      setTimeout(function () { var el = $("gate-setup-input"); if (el) el.focus(); }, 50);
    } else {
      if (title) title.textContent = "输入访问密钥";
      if (sub) sub.textContent = "控制台已启用访问保护，请输入密钥后继续。";
      if (setupPane) setupPane.classList.add("hidden");
      if (loginPane) loginPane.classList.remove("hidden");
      setTimeout(function () { var el = $("gate-login-input"); if (el) el.focus(); }, 50);
    }
    updateTokenBtn();
  }

  function hideAccessGate() {
    var gate = $("access-gate");
    var app = $("app");
    if (gate) {
      gate.classList.add("hidden");
      gate.setAttribute("hidden", "");
      gate.hidden = true;
      gate.setAttribute("aria-hidden", "true");
    }
    if (app) {
      app.classList.remove("gate-locked");
      app.setAttribute("aria-hidden", "false");
    }
    state.gateMode = "";
    setGateErr("");
    updateTokenBtn();
  }

  function updateTokenBtn() {
    var btn = $("btn-token");
    if (!btn) return;
    if (state.authEnabled || state.tokenRequired) {
      btn.textContent = "密钥✓";
      btn.title = "访问密钥已启用（点此修改/关闭）";
    } else {
      btn.textContent = "密钥";
      btn.title = "设置访问密钥（可选）";
    }
  }

  function loadSysInfo() {
    return api("GET", "/api/system/info").then(function (d) {
      var el = $("sys-info");
      if (el) {
        var v = (d && (d.version || d.app_version || d.webui_version)) || "";
        v = v ? ("v" + String(v).replace(/^v/, "")) : "";
        var bits = ["公众移动云电脑保活", "WebUI"];
        if (d && d.product) bits.push(d.product);
        else bits.push("Path B");
        if (d && d.claim != null) bits.push("claim=" + d.claim);
        if (d && d.dual_evidence != null) bits.push("dual=" + d.dual_evidence);
        else bits.push("dual=false");
        if (v) bits.push(v);
        el.textContent = bits.join(" · ");
      }
      return d;
    }).catch(function () {
      var el = $("sys-info");
      if (el) el.textContent = "公众移动云电脑保活 · WebUI · Path B · dual=false";
      return null;
    });
  }

  function refreshAuthStatus() {
    return api("GET", "/api/auth/status").then(function (st) {
      if (!st) return null;
      // server: authEnabled/tokenRequired/setupRequired/authenticated
      state.tokenRequired = !!(st.tokenRequired);
      state.authEnabled = !!(st.authEnabled != null ? st.authEnabled : st.tokenRequired);
      state.setupRequired = !!(st.setupRequired);
      state.authSource = (st.tokenSource || st.source || "") || state.authSource;
      updateTokenBtn();
      return st;
    }).catch(function () { return null; });
  }

  function enterConsoleAfterAuth() {
    hideAccessGate();
    loadSysInfo();
    loadAccounts();
    pullGlobalLogs(true);
    if (state.pollTimer) clearInterval(state.pollTimer);
    /* #75fixm: poll only soft-sync; never full-render every 5s (闪屏根因) */
    state.pollTimer = setInterval(function () {
      softPollAccounts();
      pullGlobalLogs(false);
    }, 5000);
  }

  // config modal binds (once at parse time; NOT inside poll interval)
  (function bindConfigModal() {
    var closeBtn = $("config-modal-close");
    var saveBtn = $("config-modal-save");
    var loginBtn = $("config-modal-login");
    var delBtn = $("config-modal-delete");
    var modal = $("config-modal");
    if (closeBtn) closeBtn.addEventListener("click", closeConfigModal);
    if (saveBtn) saveBtn.addEventListener("click", saveConfigModal);
    if (loginBtn) loginBtn.addEventListener("click", loginFromConfigModal);
    if (delBtn) delBtn.addEventListener("click", function () {
      var id = state.configPid || state.currentId;
      if (id) onDeleteAccount(id);
    });
    if (modal) modal.addEventListener("click", function (ev) {
      if (ev.target === modal) closeConfigModal();
    });
  })();

  function randomToken() {
    var chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    var out = "";
    try {
      var arr = new Uint8Array(18);
      crypto.getRandomValues(arr);
      for (var i = 0; i < arr.length; i++) out += chars[arr[i] % chars.length];
    } catch (_) {
      out = "ecloud" + String(Date.now()).slice(-8);
    }
    return out;
  }

  function submitGateSetup() {
    setGateErr("", "setup");
    var input = $("gate-setup-input");
    var token = (input && input.value || "").trim();
    if (!token) { setGateErr("请输入要设置的访问密钥，或点「随机生成」", "setup"); return; }
    if (token.length < 4) { setGateErr("密钥至少 4 位", "setup"); return; }
    var btn = $("gate-setup-ok");
    if (btn) btn.disabled = true;
    api("POST", "/api/auth/setup", { token: token }).then(function (res) {
      if (btn) btn.disabled = false;
      if (!res || res.ok === false) {
        setGateErr((res && (res.message || res.error)) || "设置失败", "setup");
        return;
      }
      var t = (res.token || token || "").trim();
      setToken(t);
      if (input) input.value = t;
      state.setupRequired = false;
      state.tokenRequired = true;
      state.authEnabled = true;
      enterConsoleAfterAuth();
    }).catch(function (e) {
      if (btn) btn.disabled = false;
      setGateErr((e && e.message) || "网络异常", "setup");
    });
  }

  function submitGateLogin() {
    setGateErr("", "login");
    var input = $("gate-login-input");
    var token = (input && input.value || "").trim();
    if (!token) { setGateErr("请输入访问密钥", "login"); return; }
    var btn = $("gate-login-ok");
    if (btn) btn.disabled = true;
    // store first so login request carries Authorization
    setToken(token);
    api("POST", "/api/auth/login", { token: token }).then(function (res) {
      if (btn) btn.disabled = false;
      if (!res || res.ok === false) {
        setToken("");
        setGateErr((res && (res.message || res.error)) || "密钥无效", "login");
        return;
      }
      var t = (res.token || token || "").trim();
      setToken(t);
      state.tokenRequired = true;
      state.authEnabled = true;
      enterConsoleAfterAuth();
    }).catch(function (e) {
      if (btn) btn.disabled = false;
      setToken("");
      setGateErr((e && e.message) || "网络异常", "login");
    });
  }

  function skipGateSetup() {
    // enter without setting token — server remains open
    setToken("");
    state.setupRequired = false;
    enterConsoleAfterAuth();
  }

  function wireAccessGate() {
    var setupOk = $("gate-setup-ok");
    var setupGen = $("gate-setup-gen");
    var setupSkip = $("gate-setup-skip");
    var setupShow = $("gate-setup-show");
    var setupInput = $("gate-setup-input");
    var loginOk = $("gate-login-ok");
    var loginShow = $("gate-login-show");
    var loginInput = $("gate-login-input");
    if (setupOk) setupOk.onclick = submitGateSetup;
    if (setupGen) setupGen.onclick = function () {
      var t = randomToken();
      if (setupInput) {
        setupInput.type = "text";
        setupInput.value = t;
      }
      if (setupShow) {
        setupShow.textContent = "隐藏密钥";
        setupShow.setAttribute("aria-pressed", "true");
        setupShow.setAttribute("aria-label", "隐藏密钥");
      }
      setGateErr("", "setup");
    };
    if (setupSkip) setupSkip.onclick = skipGateSetup;
    if (setupShow && setupInput) setupShow.onclick = function () {
      var show = setupInput.type === "password";
      setupInput.type = show ? "text" : "password";
      // 门控与爱家一致：长文案「显示密钥/隐藏密钥」（token-modal 仍用短文案）
      setupShow.textContent = show ? "隐藏密钥" : "显示密钥";
      setupShow.setAttribute("aria-pressed", show ? "true" : "false");
      setupShow.setAttribute("aria-label", show ? "隐藏密钥" : "显示密钥");
    };
    if (loginOk) loginOk.onclick = submitGateLogin;
    if (loginShow && loginInput) loginShow.onclick = function () {
      var show = loginInput.type === "password";
      loginInput.type = show ? "text" : "password";
      loginShow.textContent = show ? "隐藏密钥" : "显示密钥";
      loginShow.setAttribute("aria-pressed", show ? "true" : "false");
      loginShow.setAttribute("aria-label", show ? "隐藏密钥" : "显示密钥");
    };
    if (setupInput) setupInput.addEventListener("keydown", function (e) {
      if (e.key === "Enter") submitGateSetup();
    });
    if (loginInput) loginInput.addEventListener("keydown", function (e) {
      if (e.key === "Enter") submitGateLogin();
    });
  }

  function setTokenModalErr(msg) {
    var el = $("token-modal-err");
    if (el) el.textContent = msg || "";
  }

  function hideTokenModal() {
    var m = $("token-modal");
    if (!m) return;
    m.classList.add("hidden");
    m.setAttribute("hidden", "");
    m.setAttribute("aria-hidden", "true");
  }

  function showTokenModal() {
    var m = $("token-modal");
    if (!m) return;
    m.classList.remove("hidden");
    m.removeAttribute("hidden");
    m.setAttribute("aria-hidden", "false");
    setTokenModalErr("");
    var cur = $("token-modal-current");
    var neu = $("token-modal-new");
    if (cur) {
      cur.value = getToken() || "";
      cur.type = "password";
    }
    if (neu) {
      neu.value = "";
      neu.type = "password";
    }
    var shC = $("token-modal-show-current");
    var shN = $("token-modal-show-new");
    if (shC) { shC.textContent = "显示"; shC.setAttribute("aria-pressed", "false"); }
    if (shN) { shN.textContent = "显示"; shN.setAttribute("aria-pressed", "false"); }
    refreshAuthStatus().then(function () {
      var st = $("token-modal-status");
      if (!st) return;
      if (state.authEnabled || state.tokenRequired) {
        st.textContent = "鉴权已开启：操作控制台需要访问密钥。可修改、清除本机或关闭鉴权。";
      } else {
        st.textContent = "鉴权未开启：任何人可访问控制台。填写密钥后点「启用 / 修改」开启。";
      }
    }).catch(function () {
      var st = $("token-modal-status");
      if (st) st.textContent = "无法读取鉴权状态，仍可尝试本地操作。";
    });
  }

  function openTokenManager() {
    // Secondary page (not gate wizard). Gate remains first-run / 401 only.
    showTokenModal();
  }

  function wireTokenModal() {
    var closeBtn = $("token-modal-close");
    if (closeBtn) closeBtn.onclick = hideTokenModal;
    var modal = $("token-modal");
    if (modal) {
      modal.addEventListener("click", function (e) {
        if (e.target === modal) hideTokenModal();
      });
    }
    function bindShow(btnId, inputId) {
      var btn = $(btnId);
      var input = $(inputId);
      if (!btn || !input) return;
      btn.onclick = function () {
        var show = input.type === "password";
        input.type = show ? "text" : "password";
        btn.textContent = show ? "隐藏" : "显示";
        btn.setAttribute("aria-pressed", show ? "true" : "false");
      };
    }
    bindShow("token-modal-show-current", "token-modal-current");
    bindShow("token-modal-show-new", "token-modal-new");
    var gen = $("token-modal-gen");
    if (gen) gen.onclick = function () {
      var chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
      var out = "";
      for (var i = 0; i < 16; i++) out += chars.charAt(Math.floor(Math.random() * chars.length));
      var neu = $("token-modal-new");
      if (neu) { neu.value = out; neu.type = "text"; }
      var shN = $("token-modal-show-new");
      if (shN) { shN.textContent = "隐藏"; shN.setAttribute("aria-pressed", "true"); }
      setTokenModalErr("已生成随机密钥，确认后点「启用 / 修改」");
    };
    var clearLocal = $("token-modal-clear-local");
    if (clearLocal) clearLocal.onclick = function () {
      setToken("");
      var cur = $("token-modal-current");
      if (cur) cur.value = "";
      setTokenModalErr("已清除本机保存的密钥（服务端鉴权状态不变）");
      if (state.tokenRequired) {
        hideTokenModal();
        showAccessGate("login");
      }
    };
    var disableBtn = $("token-modal-disable");
    if (disableBtn) disableBtn.onclick = function () {
      var curEl = $("token-modal-current");
      var cur = ((curEl && curEl.value) || getToken() || "").trim();
      if (!cur) { setTokenModalErr("关闭鉴权需要当前密钥"); return; }
      api("POST", "/api/auth/disable", { token: cur }).then(function (res) {
        if (!res || res.ok === false) {
          setTokenModalErr((res && (res.message || res.error)) || "关闭失败");
          return;
        }
        setToken("");
        state.authEnabled = false;
        state.tokenRequired = false;
        hideTokenModal();
        enterConsoleAfterAuth();
      });
    };
    var enableBtn = $("token-modal-enable");
    if (enableBtn) enableBtn.onclick = function () {
      var curEl = $("token-modal-current");
      var neuEl = $("token-modal-new");
      var cur = ((curEl && curEl.value) || getToken() || "").trim();
      var neu = ((neuEl && neuEl.value) || "").trim();
      var token = neu || cur;
      if (!token || token.length < 4) {
        setTokenModalErr("密钥至少 4 位（启用填新密钥；修改填新密钥）");
        return;
      }
      function okDone(t) {
        setToken(t || token);
        state.authEnabled = true;
        state.tokenRequired = true;
        hideTokenModal();
        enterConsoleAfterAuth();
      }
      // change if auth already on; else setup
      if (state.authEnabled || state.tokenRequired) {
        if (!neu) { setTokenModalErr("修改密钥请填写「新密钥」"); return; }
        api("POST", "/api/auth/change", { token: neu, currentToken: cur }).then(function (res) {
          if (!res || res.ok === false) {
            setTokenModalErr((res && (res.message || res.error)) || "修改失败");
            return;
          }
          okDone((res && res.token) || neu);
        });
      } else {
        api("POST", "/api/auth/setup", { token: token }).then(function (res) {
          if (!res || res.ok === false) {
            setTokenModalErr((res && (res.message || res.error)) || "启用失败");
            return;
          }
          okDone((res && res.token) || token);
        });
      }
    };
  }

  function boot() {
    wireAccessGate();
    wireTokenModal();
    var btnTok = $("btn-token");
    if (btnTok) btnTok.onclick = openTokenManager;
    refreshAuthStatus().then(function (st) {
      loadSysInfo();
      // No server key → optional setup gate once
      if (state.setupRequired && !getToken()) {
        // only force setup UI if server says setupRequired true explicitly
        if (st && st.setupRequired) {
          showAccessGate("setup");
          return;
        }
      }
      if (state.tokenRequired && !getToken()) {
        showAccessGate("login");
        return;
      }
      // If token required and we have token, verify via a protected call
      if (state.tokenRequired && getToken()) {
        return api("GET", "/api/accounts").then(function (res) {
          if (res && res._http === 401) {
            setToken("");
            showAccessGate("login");
            return;
          }
          enterConsoleAfterAuth();
        }).catch(function () { enterConsoleAfterAuth(); });
      }
      enterConsoleAfterAuth();
    }).catch(function () {
      enterConsoleAfterAuth();
    });
  }


// boot
  boot();
})();
