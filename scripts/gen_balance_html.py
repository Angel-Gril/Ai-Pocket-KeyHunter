"""Generate a simple HTML dashboard showing the latest balance results."""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
OUTPUT_HTML = RESULTS_DIR.parent / "preview" / "balance_dashboard.html"


def find_latest_valid_json() -> Path | None:
    """Find the most recent valid_*.json across all run directories."""
    candidates = sorted(RESULTS_DIR.glob("run_*/valid_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0] if candidates else None


def generate_html(json_path: Path) -> str:
    data = json.loads(json_path.read_text(encoding="utf-8"))
    scan_time = data.get("scan_time", "unknown")
    total_valid = data.get("total_valid", 0)
    credentials = data.get("credentials", [])

    # Build table rows
    rows = ""
    for i, item in enumerate(credentials, 1):
        cred = item.get("credential", {})
        apikey = cred.get("apikey", "")
        apiurl = cred.get("apiurl", "")
        host = cred.get("host", "")
        gateway = item.get("gateway", "")
        balance = item.get("balance", "N/A")
        model = item.get("model_available", "")
        provider_info = item.get("provider_info", {})
        balance_provider = provider_info.get("balance_provider", "")
        models = ", ".join(provider_info.get("models_available", []))
        validated_at = item.get("validated_at", "")

        # Parse balance detail
        rate_limit = item.get("rate_limit_headers", {})
        balance_detail = rate_limit.get("balance_detail", "")
        balance_cny = ""
        if "balance_cny" in balance_detail:
            try:
                # Extract CNY value from the string repr
                import re
                m = re.search(r"'balance_cny':\s*([\d.]+)", balance_detail)
                if m:
                    balance_cny = m.group(1)
            except Exception:
                pass

        # Mask API key for display
        masked_key = apikey[:8] + "..." + apikey[-4:] if len(apikey) > 12 else apikey

        rows += f"""
        <tr>
          <td>{i}</td>
          <td><code>{masked_key}</code></td>
          <td>{host}</td>
          <td>{gateway}</td>
          <td class="balance">${balance}</td>
          <td class="balance">¥{balance_cny}</td>
          <td>{models}</td>
          <td>{validated_at[:19] if validated_at else ''}</td>
        </tr>"""

    # Format scan time for display
    try:
        dt = datetime.strptime(scan_time, "%Y%m%dT%H%M%SZ")
        display_time = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        display_time = scan_time

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AIPocket 余额概览</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
    background: #1a1a2e;
    color: #e0e0e0;
    padding: 2rem;
    min-height: 100vh;
  }}
  .header {{
    text-align: center;
    margin-bottom: 2rem;
    padding-bottom: 1rem;
    border-bottom: 1px solid #333;
  }}
  .header h1 {{
    font-size: 1.5rem;
    color: #00d4aa;
    margin-bottom: 0.5rem;
  }}
  .meta {{
    font-size: 0.85rem;
    color: #888;
  }}
  .meta span {{
    margin: 0 1rem;
  }}
  .stats {{
    display: flex;
    gap: 1.5rem;
    justify-content: center;
    margin-bottom: 2rem;
  }}
  .stat-card {{
    background: #16213e;
    border: 1px solid #0f3460;
    border-radius: 8px;
    padding: 1rem 2rem;
    text-align: center;
  }}
  .stat-card .value {{
    font-size: 2rem;
    font-weight: bold;
    color: #00d4aa;
  }}
  .stat-card .label {{
    font-size: 0.8rem;
    color: #888;
    margin-top: 0.3rem;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    background: #16213e;
    border-radius: 8px;
    overflow: hidden;
  }}
  th {{
    background: #0f3460;
    padding: 0.8rem 1rem;
    text-align: left;
    font-size: 0.8rem;
    text-transform: uppercase;
    color: #aaa;
  }}
  td {{
    padding: 0.7rem 1rem;
    border-bottom: 1px solid #1a1a2e;
    font-size: 0.85rem;
  }}
  tr:hover td {{
    background: #1a2744;
  }}
  .balance {{
    font-weight: bold;
    color: #4caf50;
    font-size: 1rem;
  }}
  code {{
    background: #0d1b2a;
    padding: 2px 6px;
    border-radius: 3px;
    font-size: 0.8rem;
  }}
  .footer {{
    text-align: center;
    margin-top: 2rem;
    font-size: 0.75rem;
    color: #555;
  }}
</style>
</head>
<body>
  <div class="header">
    <h1>🔑 AIPocket 余额概览</h1>
    <div class="meta">
      <span>扫描时间: {display_time}</span>
      <span>数据文件: {json_path.name}</span>
      <span>生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
    </div>
  </div>

  <div class="stats">
    <div class="stat-card">
      <div class="value">{total_valid}</div>
      <div class="label">有效密钥</div>
    </div>
    <div class="stat-card">
      <div class="value">${credentials[0]['balance'] if credentials else '0'}</div>
      <div class="label">余额 (美元)</div>
    </div>
    <div class="stat-card">
      <div class="value">{credentials[0].get('gateway', 'N/A') if credentials else 'N/A'}</div>
      <div class="label">网关</div>
    </div>
  </div>

  <table>
    <thead>
      <tr>
        <th>#</th>
        <th>API 密钥</th>
        <th>主机</th>
        <th>网关</th>
        <th>美元</th>
        <th>人民币</th>
        <th>可用模型</th>
        <th>验证时间</th>
    </thead>
    <tbody>{rows}
    </tbody>
  </table>

  <div class="footer">
    临时展示页 &mdash; 执行 <code>python3 scripts/gen_balance_html.py</code> 刷新数据
  </div>
</body>
</html>"""
    return html


def main():
    json_path = None
    if len(sys.argv) > 1:
        json_path = Path(sys.argv[1])
    else:
        json_path = find_latest_valid_json()

    if not json_path or not json_path.exists():
        print("No valid_*.json found in results/")
        sys.exit(1)

    print(f"Using: {json_path}")
    html = generate_html(json_path)
    OUTPUT_HTML.write_text(html, encoding="utf-8")
    print(f"Dashboard written to: {OUTPUT_HTML}")


if __name__ == "__main__":
    main()
