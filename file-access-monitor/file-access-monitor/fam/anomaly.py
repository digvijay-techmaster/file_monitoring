"""Data-science part: find strange activity spikes with machine learning (Isolation Forest)."""
import pandas as pd
from sklearn.ensemble import IsolationForest


def per_minute(rows):
    """Turn the list of events into one row per minute: how many events, files, deletes."""
    df = pd.DataFrame(rows)
    df["t"] = pd.to_datetime(df["ts_epoch"], unit="s", utc=True)
    df["is_delete"] = df["action"].isin(["deleted", "moved_from"]).astype(int)
    return (
        df.set_index("t")
        .groupby(pd.Grouper(freq="1min"))
        .agg(events=("path", "size"), files=("path", "nunique"), deletes=("is_delete", "sum"))
    )


def analyze(store, contamination=0.05, min_minutes=20):
    """Returns (table, message). The table has an 'anomaly' column (True = strange minute)."""
    rows = store.recent("events", 50000)
    if not rows:
        return None, "No events yet."
    per = per_minute(rows)
    if len(per) < min_minutes:
        return per, f"Need at least {min_minutes} minutes of data (have {len(per)}). Let the monitor run longer."
    X = per[["events", "files", "deletes"]]
    model = IsolationForest(contamination=contamination, random_state=42)
    flagged = model.fit_predict(X) == -1
    std = float(per["events"].std()) or 1.0
    z = (per["events"] - per["events"].mean()) / std
    # The forest always flags ~5% of minutes. We only keep the ones that are also a real spike.
    per["score"] = model.score_samples(X)
    per["anomaly"] = flagged & (z > 2)
    return per, "ok"
