package com.audit.collector.web;

/**
 * 監査コンソールの HTML / JS。
 * <p>
 * XSS 対策：ログの値（URI・ユーザー名など、外部から入ってくる文字列）は
 * すべて {@code textContent} で入れる。{@code innerHTML} にログ値を連結しない。
 * さらに JS を別ファイルで配信し、CSP で インラインスクリプトの実行を禁止している（二重の防御）。
 */
final class ConsoleAssets {

    private ConsoleAssets() {
    }

    static final String HTML = """
            <!DOCTYPE html>
            <html lang="ja">
            <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>監査コンソール | Japan Audit Platform（デモ）</title>
            <style>
              :root { --bg:#0b1220; --panel:#111a2e; --line:#23304d; --text:#e2e8f0; --muted:#8a99b5;
                      --crit:#f87171; --warn:#fbbf24; --ok:#34d399; --info:#60a5fa; }
              * { box-sizing:border-box; }
              body { margin:0; background:var(--bg); color:var(--text); font:14px/1.5 system-ui, "Hiragino Sans", "Noto Sans JP", sans-serif; }
              header { padding:16px 24px; border-bottom:1px solid var(--line); display:flex; gap:16px; align-items:center; flex-wrap:wrap; }
              h1 { font-size:18px; margin:0; }
              .note { color:var(--muted); font-size:12px; }
              main { padding:20px 24px; display:grid; gap:16px; }
              .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:12px; }
              .card { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:12px 14px; }
              .card .label { color:var(--muted); font-size:12px; }
              .card .value { font-size:24px; font-weight:700; margin-top:4px; font-variant-numeric:tabular-nums; }
              table { width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--line); border-radius:8px; overflow:hidden; }
              th, td { padding:8px 10px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; font-size:13px; }
              th { color:var(--muted); font-weight:600; background:#0e1628; }
              td.mono, .mono { font-family:ui-monospace, Menlo, Consolas, monospace; }
              .badge { display:inline-block; padding:1px 8px; border-radius:999px; font-size:12px; font-weight:700; }
              .CRITICAL { background:rgba(248,113,113,.15); color:var(--crit); }
              .WARN { background:rgba(251,191,36,.15); color:var(--warn); }
              .INFO { background:rgba(96,165,250,.15); color:var(--info); }
              .OK { color:var(--ok); } .BROKEN { color:var(--crit); } .UNAVAILABLE { color:var(--muted); }
              button { background:#1d4ed8; color:#fff; border:0; border-radius:6px; padding:8px 14px; cursor:pointer; font-weight:600; }
              button:hover { background:#2563eb; }
              #problems li { color:var(--crit); }
              .reason { color:var(--muted); font-size:12px; }
            </style>
            </head>
            <body>
            <header>
              <h1>監査コンソール</h1>
              <span class="note">デモ環境・表示データはすべて架空／個人情報はマスキング済み</span>
            </header>
            <main>
              <section class="cards">
                <div class="card"><div class="label">表示中のログ</div><div class="value" id="c-total">-</div></div>
                <div class="card"><div class="label">CRITICAL</div><div class="value" id="c-crit">-</div></div>
                <div class="card"><div class="label">WARN</div><div class="value" id="c-warn">-</div></div>
                <div class="card"><div class="label">ハッシュチェーン検証</div><div class="value" id="c-chain">未実行</div></div>
              </section>
              <section>
                <button id="btn-verify">チェーンを今すぐ検証</button>
                <span class="note" id="verify-note"></span>
                <ul id="problems"></ul>
              </section>
              <table>
                <thead><tr>
                  <th>#</th><th>日時(UTC)</th><th>システム</th><th>ユーザー</th><th>接続元</th>
                  <th>操作</th><th>個人情報</th><th>警戒</th>
                </tr></thead>
                <tbody id="rows"></tbody>
              </table>
            </main>
            <script src="/console.js"></script>
            </body>
            </html>
            """;

    static final String JS = """
            'use strict';
            // ログの値は必ず textContent で入れる（innerHTML に連結しない）
            function cell(tr, text, cls) {
              const td = document.createElement('td');
              td.textContent = text == null ? '' : String(text);
              if (cls) td.className = cls;
              tr.appendChild(td);
              return td;
            }
            async function loadLogs() {
              const res = await fetch('/api/v1/collector/logs?limit=100', { cache: 'no-store' });
              if (!res.ok) return;
              const logs = await res.json();
              const tbody = document.getElementById('rows');
              tbody.replaceChildren();
              let crit = 0, warn = 0;
              for (const l of logs) {
                if (l.alertLevel === 'CRITICAL') crit++;
                if (l.alertLevel === 'WARN') warn++;
                const tr = document.createElement('tr');
                cell(tr, l.chainSeq, 'mono');
                cell(tr, l.timestamp.replace('T', ' ').substring(0, 19), 'mono');
                cell(tr, l.systemCode, 'mono');
                cell(tr, l.userId, 'mono');
                cell(tr, l.clientIp, 'mono');
                cell(tr, l.httpMethod + ' ' + l.requestUri + ' → ' + l.httpStatus + ' (' + l.executionTimeMs + 'ms)', 'mono');
                const pii = l.details.length === 0 ? '-'
                  : l.details.slice(0, 3).map(d => d.piiType + ' ' + d.maskedValue).join(' / ')
                    + (l.details.length > 3 ? ' …他' + (l.details.length - 3) + '件' : '')
                    + (l.myNumberPersonCount > 0 ? '（本人数 ' + l.myNumberPersonCount + '）' : '');
                cell(tr, pii, 'mono');
                const td = cell(tr, '');
                const badge = document.createElement('span');
                badge.className = 'badge ' + l.alertLevel;
                badge.textContent = l.alertLevel;
                td.appendChild(badge);
                if (l.alertReason) {
                  const r = document.createElement('div');
                  r.className = 'reason';
                  r.textContent = l.alertReason;
                  td.appendChild(r);
                }
                tbody.appendChild(tr);
              }
              document.getElementById('c-total').textContent = logs.length;
              document.getElementById('c-crit').textContent = crit;
              document.getElementById('c-warn').textContent = warn;
            }
            async function verify() {
              const res = await fetch('/api/v1/collector/chain/verify', { cache: 'no-store' });
              const v = await res.json();
              const el = document.getElementById('c-chain');
              el.textContent = v.status;
              el.className = 'value ' + v.status;
              document.getElementById('verify-note').textContent =
                v.status === 'UNAVAILABLE' ? 'メモリ保存モードのため検証できません'
                : v.checkedRows + '行を検証 / アンカー ' + v.anchors + '件と照合 (' + new Date().toLocaleTimeString() + ')';
              const ul = document.getElementById('problems');
              ul.replaceChildren();
              for (const p of v.problems) {
                const li = document.createElement('li');
                li.textContent = (p.chainSeq == null ? '' : '#' + p.chainSeq + ' ') + p.problem;
                ul.appendChild(li);
              }
            }
            document.getElementById('btn-verify').addEventListener('click', verify);
            loadLogs(); verify();
            setInterval(loadLogs, 3000);
            """;
}
