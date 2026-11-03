package com.audit.demo;

/** デモ業務アプリの操作画面（ブラウザから監査ログを発生させるためのもの）。 */
final class DemoPage {

    private DemoPage() {
    }

    static final String HTML = """
            <!DOCTYPE html>
            <html lang="ja">
            <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>架空 顧客管理システム（監査センサー組込みデモ）</title>
            <style>
              body { margin:0; font:14px/1.6 system-ui, "Hiragino Sans", "Noto Sans JP", sans-serif; background:#f6f7f9; color:#1f2937; }
              header { background:#1e3a5f; color:#fff; padding:14px 24px; }
              header h1 { margin:0; font-size:18px; }
              header p { margin:2px 0 0; font-size:12px; opacity:.8; }
              main { padding:20px 24px; display:grid; gap:14px; max-width:980px; }
              .row { display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
              button { padding:8px 14px; border-radius:6px; border:1px solid #1e3a5f; background:#fff; color:#1e3a5f; font-weight:600; cursor:pointer; }
              button.primary { background:#1e3a5f; color:#fff; }
              pre { background:#0f172a; color:#e2e8f0; padding:12px; border-radius:8px; max-height:340px; overflow:auto; font-size:12px; }
              .hint { color:#6b7280; font-size:12px; }
            </style>
            </head>
            <body>
            <header>
              <h1>架空 顧客管理システム</h1>
              <p>表示されるデータはすべて架空です。このアプリの前段に監査フィルターが入っています。</p>
            </header>
            <main>
              <div class="row">
                <label>操作者：
                  <select id="token">
                    <option value="demo-token-0001">EMP_DEMO_0001</option>
                    <option value="demo-token-0002">EMP_DEMO_0002</option>
                    <option value="demo-token-0003">EMP_DEMO_0003</option>
                    <option value="">（未ログイン）</option>
                  </select>
                </label>
              </div>
              <div class="row">
                <button class="primary" data-call="GET /api/v1/customers/1">顧客1件を照会（WARN）</button>
                <button data-call="GET /api/v1/customers/export?count=50">50件出力（WARN）</button>
                <button data-call="GET /api/v1/customers/export?count=120">120件出力（CRITICAL）</button>
                <button data-call="SPLIT">60件×2回に分割（CRITICAL：累計で検知）</button>
                <button data-call="GET /api/v1/customers/abc">存在しないURL（INFO・404）</button>
              </div>
              <p class="hint">監査コンソール（別ポート、既定 http://localhost:8081/）で結果を確認できます。</p>
              <pre id="out">ボタンを押すとレスポンスが表示されます。</pre>
            </main>
            <script>
              'use strict';
              async function call(spec) {
                const [method, url] = spec.split(' ');
                const token = document.getElementById('token').value;
                const headers = token ? { 'Authorization': 'Bearer ' + token } : {};
                const t0 = performance.now();
                const res = await fetch(url, { method, headers });
                const text = await res.text();
                return method + ' ' + url + ' → ' + res.status + ' (' + Math.round(performance.now() - t0) + 'ms)\\n'
                     + text.substring(0, 1500) + (text.length > 1500 ? '\\n…' : '');
              }
              document.querySelectorAll('button[data-call]').forEach(b => b.addEventListener('click', async () => {
                const out = document.getElementById('out');
                const spec = b.dataset.call;
                if (spec === 'SPLIT') {
                  const a = await call('GET /api/v1/customers/export?count=60&from=1000');
                  const c = await call('GET /api/v1/customers/export?count=60&from=2000');
                  out.textContent = a + '\\n\\n' + c;
                } else {
                  out.textContent = await call(spec);
                }
              }));
            </script>
            </body>
            </html>
            """;
}
