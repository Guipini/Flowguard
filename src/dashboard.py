"""
dashboard.py - Streamlit UI reading alerts.db.

Read-only viewer for the SQLite database that capture.py writes to. Auto-refreshes
every second. Never writes to the database - this preserves the single-writer
invariant that keeps WAL-mode SQLite fast and consistent.

Usage (in its own terminal, does NOT need to be Administrator):
    streamlit run src/dashboard.py
Then open http://localhost:8501 in a browser.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

import pandas as pd
import streamlit as st

# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = PROJECT_ROOT / 'alerts.db'

REFRESH_INTERVAL_S = 1.0
RECENT_LIMIT = 50


st.set_page_config(
    layout='wide',
    page_title='Anomaly Detector',
    page_icon='🛡️',
)

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    st.markdown('### Connection')
    db_path_str = st.text_input('alerts.db path', value=str(DEFAULT_DB))
    paused = st.toggle('Pause auto-refresh', value=False)
    st.caption('Dashboard reads a read-only view of the DB; capture.py is the only writer.')
    st.markdown('---')
    st.markdown('### How to demo')
    st.markdown(
        '1. Start `capture.py` in an Admin terminal\n'
        '2. Open this page\n'
        '3. From a third terminal (Admin), run `attack_simulator.py`\n'
        '4. Watch alerts appear in red below'
    )

db_path = Path(db_path_str)

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

st.title('🛡️ Network Traffic Anomaly Detector')
st.caption(f'SQLite source: `{db_path}`  |  refresh {REFRESH_INTERVAL_S:.0f}s  |  classifier: Random Forest on CICIDS2017')

# Bail early if the DB isn't there yet
if not db_path.exists():
    st.warning(
        f'`{db_path.name}` not found. Start `capture.py` first - the database is '
        'created on its first write.'
    )
    st.stop()


# ---------------------------------------------------------------------------
# Data loader
# ---------------------------------------------------------------------------

@st.cache_data(ttl=REFRESH_INTERVAL_S, show_spinner=False)
def load_alerts(db_file: str, limit: int) -> pd.DataFrame:
    """Read-only query. TTL-cached so rapid rerenders don't hammer SQLite."""
    uri = f'file:{db_file}?mode=ro'
    conn = sqlite3.connect(uri, uri=True, timeout=5.0)
    try:
        df = pd.read_sql_query(
            f'SELECT * FROM alerts ORDER BY id DESC LIMIT {int(limit)}',
            conn,
        )
    except pd.errors.DatabaseError:
        # Schema not created yet
        df = pd.DataFrame()
    finally:
        conn.close()
    return df


@st.cache_data(ttl=REFRESH_INTERVAL_S, show_spinner=False)
def load_totals(db_file: str) -> dict:
    """Totals for the metric strip.

    `benign` counts rows where the model's argmax was benign.
    `ddos` / `portscan` count *alert* rows by their likely_attack_class
    (not predicted_class) - because under loopback distribution shift
    the argmax often stays benign even when we alert.
    """
    uri = f'file:{db_file}?mode=ro'
    conn = sqlite3.connect(uri, uri=True, timeout=5.0)
    try:
        total_row = conn.execute('SELECT COUNT(*) FROM alerts').fetchone()
        total = int(total_row[0]) if total_row else 0
        benign_row = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE predicted_class = 'benign'"
        ).fetchone()
        benign = int(benign_row[0]) if benign_row else 0
        # Alerts broken down by the dominant attack class
        attack_rows = conn.execute("""
            SELECT likely_attack_class, COUNT(*) AS n
            FROM alerts
            WHERE severity = 'alert'
            GROUP BY likely_attack_class
        """).fetchall()
    except sqlite3.DatabaseError:
        total = benign = 0
        attack_rows = []
    finally:
        conn.close()
    out = {'total': total, 'benign': benign, 'alerts': 0, 'ddos': 0, 'portscan': 0}
    for likely_attack_class, n in attack_rows:
        key = (likely_attack_class or '').lower()
        out['alerts'] += int(n)
        if key in out:
            out[key] += int(n)
    return out


totals = load_totals(str(db_path))
df = load_alerts(str(db_path), RECENT_LIMIT)

# ---------------------------------------------------------------------------
# Metric strip
# ---------------------------------------------------------------------------

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric('Total flows scored', f'{totals["total"]:,}')
c2.metric('🚨 Alerts raised', f'{totals["alerts"]:,}',
          delta=f'+{totals["alerts"]}' if totals['alerts'] else None,
          delta_color='inverse')
c3.metric('Benign', f'{totals["benign"]:,}')
c4.metric('DDoS', f'{totals["ddos"]:,}')
c5.metric('Port scans', f'{totals["portscan"]:,}')

# ---------------------------------------------------------------------------
# Big banner: most recent alert
# ---------------------------------------------------------------------------

if not df.empty and (df['severity'] == 'alert').any():
    recent = df[df['severity'] == 'alert'].iloc[0]
    # likely_attack_class is the dominant attack class (argmax of non-benign probs).
    # Fall back to predicted_class for old rows from a pre-migration DB.
    attack_label = str(recent.get('likely_attack_class') or recent['predicted_class']).upper()
    st.error(
        f'### 🚨 ATTACK DETECTED: `{attack_label}`\n\n'
        f'**Flow**: `{recent["src_ip"]}:{recent["src_port"]}` → '
        f'`{recent["dst_ip"]}:{recent["dst_port"]}` (`{recent["protocol"]}`)  \n'
        f'**Attack probability**: {recent["attack_probability"]:.2%}  |  '
        f"**Model's top vote**: `{recent['predicted_class']}` ({recent['confidence']:.2%})  |  "
        f'**Close reason**: `{recent["close_reason"]}`  |  '
        f'**Packets**: {recent["packet_count"]}'
    )

# ---------------------------------------------------------------------------
# Recent flows table
# ---------------------------------------------------------------------------

st.subheader(f'Recent flows (last {RECENT_LIMIT})')

if df.empty:
    st.info('No flows scored yet. Waiting for traffic...')
else:
    display = df[[
        'timestamp', 'severity', 'predicted_class', 'confidence', 'attack_probability',
        'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol',
        'packet_count', 'close_reason',
    ]].copy()
    display['time']        = pd.to_datetime(display['timestamp'], unit='s').dt.strftime('%H:%M:%S.%f').str[:-3]
    display['confidence']  = display['confidence'].map(lambda x: f'{x:.2%}')
    display['attack_prob'] = display['attack_probability'].map(lambda x: f'{x:.2%}')
    display = display[[
        'time', 'severity', 'predicted_class', 'confidence', 'attack_prob',
        'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol',
        'packet_count', 'close_reason',
    ]]

    def _row_color(row):
        if row['severity'] == 'alert':
            return ['background-color: #5a1e1e; color: white'] * len(row)
        return [''] * len(row)

    st.dataframe(
        display.style.apply(_row_color, axis=1),
        use_container_width=True,
        hide_index=True,
        height=600,
    )

# ---------------------------------------------------------------------------
# Auto-refresh
# ---------------------------------------------------------------------------

if not paused:
    time.sleep(REFRESH_INTERVAL_S)
    st.rerun()
