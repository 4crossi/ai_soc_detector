"""
ML training and detection utilities for Phase 4.

Trains an IsolationForest on simple per-IP features like failed attempt count and unique ports.
"""
import os
import json
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from .db import DB


def extract_features(db: DB, window_minutes: int = 60):
    """Extract per-IP features from attempts table.

    Features:
    - failed_count: number of failed attempts
    - success_count: number of successful attempts
    - unique_ports: number of unique destination ports seen (if available)
    """
    conn = db.connect()
    cur = conn.cursor()
    cur.execute("SELECT ip FROM attempts GROUP BY ip")
    ips = [r[0] for r in cur.fetchall()]
    X = []
    ipmap = []
    for ip in ips:
        cur.execute("SELECT COUNT(1) FROM attempts WHERE ip=? AND outcome='failed'", (ip,))
        failed = cur.fetchone()[0]
        cur.execute("SELECT COUNT(1) FROM attempts WHERE ip=? AND outcome!='failed'", (ip,))
        succ = cur.fetchone()[0]
        cur.execute("SELECT COUNT(DISTINCT port) FROM attempts WHERE ip=? AND port IS NOT NULL", (ip,))
        ports = cur.fetchone()[0] or 0
        X.append([failed, succ, ports])
        ipmap.append(ip)
    return np.array(X), ipmap


def train_model(db_path: str, model_path: str = 'models/iforest.joblib'):
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    db = DB(db_path)
    db.connect()
    X, ips = extract_features(db)
    if X.shape[0] == 0:
        raise RuntimeError('No data to train on')
    clf = IsolationForest(contamination=0.02, random_state=42)
    clf.fit(X)
    joblib.dump({'model': clf, 'ips': ips}, model_path)
    return model_path


def infer(db_path: str, model_path: str = 'models/iforest.joblib'):
    data = joblib.load(model_path)
    clf = data['model']
    ips = data['ips']
    db = DB(db_path)
    db.connect()
    X, ipmap = extract_features(db)
    preds = clf.predict(X)
    # -1 is anomaly
    anomalies = [ipmap[i] for i,p in enumerate(preds) if p == -1]
    return anomalies
