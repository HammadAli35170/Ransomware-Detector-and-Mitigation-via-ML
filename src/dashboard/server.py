# src/dashboard/server.py
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import threading
import logging
import sqlite3
import os
from collections import Counter

app = FastAPI(title="Ransomware EDR Dashboard 2025")
app.mount("/static", StaticFiles(directory="src/dashboard/static"), name="static")

# Enable CORS for API endpoints
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class DashboardState:
    def __init__(self):
        self.connections: List[WebSocket] = []
        self.total_events = 0
        self.total_alerts = 0
        self.entropy_hits = 0
        self.honeypot_hits = 0
        # per-minute buckets for last 60+ minutes: {minute_iso: {'stage1':n,'stage2':n,'stage3':n,'all':n}}
        self.minute_buckets: Dict[str, Dict[str, int]] = {}
        # per-second stage counters for real-time chart (last 60 seconds)
        from collections import deque
        self.second_buckets: Dict[str, int] = {'stage1': 0, 'stage2': 0, 'stage3': 0, 'stage4': 0}
        self._current_second = None  # Track current second for bucket reset
        # recent raw events buffer for inspection
        self.recent_events = deque(maxlen=1000)

state = DashboardState()

# --- simple SQLite persistence for alerts
DB_PATH = os.path.join(os.path.dirname(__file__), 'dashboard.db')

def init_db():
    """Initialize all database tables."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # Alerts table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            pid TEXT,
            image TEXT,
            reasons TEXT,
            raw TEXT
        )
        """
    )
    # Jumps/actions table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS jumps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            action TEXT,
            pid TEXT,
            image TEXT,
            raw TEXT
        )
        """
    )
    # Stage 3 dataset labels (for training)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS stage3_labels (
            event_uuid TEXT PRIMARY KEY,
            label INTEGER,
            source TEXT,
            ts TEXT,
            note TEXT
        )
        """
    )
    conn.commit()
    conn.close()


def upsert_stage3_label(event_uuid: str, label: int, source: str = "dashboard", note: str = "") -> None:
    """Upsert a label for an event_uuid into stage3_labels."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO stage3_labels(event_uuid, label, source, ts, note)
            VALUES(?,?,?,?,?)
            ON CONFLICT(event_uuid) DO UPDATE SET
                label=excluded.label,
                source=excluded.source,
                ts=excluded.ts,
                note=excluded.note
            """,
            (str(event_uuid), int(label), str(source), datetime.now().isoformat(), str(note or "")),
        )
        conn.commit()
    finally:
        conn.close()

def save_alert_to_db(payload: Dict[str, Any]):
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("INSERT INTO alerts (ts,pid,image,reasons,raw) VALUES (?,?,?,?,?)",
                    (payload.get('timestamp'), str(payload.get('pid')), payload.get('image'), json.dumps(payload.get('reasons',[])), json.dumps(payload.get('raw',{}))))
        conn.commit()
    except Exception:
        logging.exception('Failed to save alert to DB')
    finally:
        try:
            conn.close()
        except:
            pass

def save_jump_to_db(payload: Dict[str, Any]):
    """
    Save jump/action event to database. Uses 'jumps' table to match admin endpoint.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS jumps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT,
                action TEXT,
                pid TEXT,
                image TEXT,
                raw TEXT
            )
            """
        )
        cur.execute("INSERT INTO jumps (ts,action,pid,image,raw) VALUES (?,?,?,?,?)",
                    (payload.get('ts') or datetime.now().isoformat(), 
                     payload.get('action') or 'jump', 
                     str(payload.get('pid') or ''), 
                     payload.get('image') or '', 
                     json.dumps(payload.get('raw') or {})))
        conn.commit()
    except Exception:
        logging.exception('Failed to save jump to DB')
    finally:
        try:
            conn.close()
        except:
            pass

def get_alerts_history(minutes: int = 60):
    # return per-minute counts for the past `minutes`
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT ts FROM alerts ORDER BY ts DESC LIMIT 1000")
        rows = cur.fetchall()
        conn.close()
        # count per minute
        now = datetime.now()
        buckets = Counter()
        for (ts,) in rows:
            try:
                t = datetime.fromisoformat(ts)
                diff = int((now - t).total_seconds() // 60)
                if 0 <= diff < minutes:
                    buckets[minutes - diff - 1] += 1
            except Exception:
                continue
        labels = []
        counts = []
        for i in range(minutes):
            minute_label = (now - timedelta(minutes=(minutes - i - 1))).strftime('%H:%M')
            labels.append(minute_label)
            counts.append(buckets.get(i, 0))
        return {'labels': labels, 'counts': counts}
    except Exception:
        logging.exception('Failed to build alerts history')
        return {'labels': [], 'counts': [], 'stage1': [], 'stage3': [], 'stage4': []}

def get_minute_series(minutes: int = 60):
    # Build labels and per-stage counts from in-memory minute_buckets
    try:
        now = datetime.now()
        labels = []
        s1 = []
        s3 = []
        s4 = []
        for i in range(minutes):
            t = now - timedelta(minutes=(minutes - i - 1))
            key = t.strftime('%Y-%m-%dT%H:%M')
            labels.append(t.strftime('%H:%M'))
            bucket = state.minute_buckets.get(key, {})
            s1.append(bucket.get('stage1', 0))
            s3.append(bucket.get('stage3', 0))
            s4.append(bucket.get('stage4', 0))
        return {'labels': labels, 'stage1': s1, 'stage3': s3, 'stage4': s4}
    except Exception:
        logging.exception('failed to build minute series')
        return {'labels': [], 'stage1': [], 'stage2': [], 'stage3': []}

async def broadcast(data: Dict):
    dead = []
    connection_count = len(state.connections)
    if connection_count == 0:
        logging.warning('Broadcasting event but no WebSocket connections active')
    for ws in state.connections:
        try:
            await ws.send_json(data)
        except (ConnectionError, BrokenPipeError, OSError) as e:
            # Normal connection errors - client disconnected
            dead.append(ws)
        except AssertionError:
            # Windows asyncio ProactorEventLoop bug - non-fatal, suppress
            # This is a known Windows asyncio issue with pipe transport
            pass
        except Exception as e:
            # Other errors - log at debug level and remove connection
            logging.debug(f'WebSocket send failed (removing connection): {e}')
            dead.append(ws)
    for ws in dead:
        if ws in state.connections:
            state.connections.remove(ws)
    if connection_count > 0 and len(dead) > 0:
        logging.debug(f'Broadcast complete: {connection_count} connections, {len(dead)} removed')

# stage-3 handlers: allow other modules (launcher) to register a callback
_stage3_handlers: List[callable] = []

def register_stage3_handler(func: callable):
    try:
        if callable(func):
            _stage3_handlers.append(func)
            logging.info('Registered stage3 handler: %s', getattr(func, '__name__', str(func)))
    except Exception:
        logging.exception('failed to register stage3 handler')

def _notify_stage3_handlers(msg: Dict[str, Any]):
    # call handlers in best-effort fashion
    for h in list(_stage3_handlers):
        try:
            # call synchronously; handlers should handle threading concerns
            h(msg)
        except Exception:
            logging.exception('stage3 handler raised')

# Manual event promotion: Registry for stage engines
_stage3_engine: Optional[Any] = None
_stage4_engine: Optional[Any] = None

def register_stage_engines(stage3_engine: Optional[Any] = None, stage4_engine: Optional[Any] = None):
    """
    Register stage engines for manual event promotion.
    Called by unified_launcher to expose engines to dashboard API.
    """
    global _stage3_engine, _stage4_engine
    _stage3_engine = stage3_engine
    _stage4_engine = stage4_engine
    logging.info('Registered stage engines for manual promotion: Stage3=%s, Stage4=%s', 
                 stage3_engine is not None, stage4_engine is not None)

def send_to_dashboard(event: Dict, promoted: bool = False, reasons: List[str] = None, stage_override: Optional[str] = None):
    if reasons is None:
        reasons = []
    # normalize pid and image from common keys
    pid = event.get("ProcessID") or event.get("ProcessId") or event.get("process_id") or event.get('pid') or None
    image = event.get("Image") or event.get("image") or event.get('ImagePath') or 'Unknown'
    
    # Use stage_override if provided, otherwise determine from event state
    # Stage 2 is under the hood - dashboard only shows stage1, stage3 (Threat Analysis), stage4 (Active Threat)
    if stage_override:
        stage_label = stage_override
    else:
        # Determine stage: stage4 (Active Threat) > stage3 (Threat Analysis) > stage1 (Event Collection)
        if event.get('__stage4') or promoted:
            stage_label = 'stage4'  # Active Threat
        elif event.get('__stage3') or event.get('__stage3_score') is not None:
            stage_label = 'stage3'  # Threat Analysis
        else:
            stage_label = 'stage1'  # Event Collection
    payload = {
        "type": "alert" if promoted else "event",
        # Use ISO timestamp so frontend can parse reliably
        "timestamp": datetime.now().isoformat(),
        "pid": str(pid) if pid is not None else '???',
        "image": image,
        "reasons": reasons[:6],
        "raw": event,
        "stage": stage_label
    }
    # Add Stage 3 ML score if available
    if event.get("__stage3_score") is not None:
        payload["ml_score"] = float(event.get("__stage3_score", 0.0))
        payload["ml_threshold"] = True  # Indicates this was scored by ML
    
    # Add Stage 3 tier if available (for benign detection)
    if event.get("__stage3_tier") is not None:
        payload["stage3_tier"] = event.get("__stage3_tier")
        # Set status based on tier (for dashboard display)
        tier = event.get("__stage3_tier", "").lower()
        if tier == "low":
            payload["status"] = "Benign"
        elif tier in ["medium", "high", "critical"]:
            payload["status"] = "Suspicious" if tier == "medium" else "Malicious"
        else:
            payload["status"] = "Unknown"
    
    # Add Stage 3 genealogy if available (for visualization)
    if event.get("__stage3_genealogy") is not None:
        payload["genealogy"] = event.get("__stage3_genealogy")
    
    # Add Stage 4 results if available
    if event.get("__stage4_verdict") is not None:
        payload["stage4_verdict"] = event.get("__stage4_verdict")
        payload["stage4_score"] = float(event.get("__stage4_score", 0.0))
        payload["stage4_confidence"] = float(event.get("__stage4_confidence", 0.0))
    
    # Add manual promotion flag if present
    if event.get("__manually_promoted"):
        payload["manually_promoted"] = True
        payload["manual_promotion_timestamp"] = event.get("__manual_promotion_timestamp", datetime.now().isoformat())
    # store raw event for admin inspection
    try:
        state.recent_events.appendleft(event)
    except Exception:
        pass
    # update minute buckets
    try:
        minute_key = datetime.now().strftime('%Y-%m-%dT%H:%M')
        # Stage 2 is under the hood - only track stage1, stage3, stage4
        b = state.minute_buckets.setdefault(minute_key, {'stage1': 0, 'stage3': 0, 'stage4': 0, 'all': 0})
        if stage_label in ['stage1', 'stage3', 'stage4']:
            b[stage_label] = b.get(stage_label, 0) + 1
        b['all'] = b.get('all', 0) + 1
        # keep only recent 180 buckets to avoid memory growth
        if len(state.minute_buckets) > 180:
            # drop oldest
            keys = sorted(state.minute_buckets.keys())
            for k in keys[:-180]:
                state.minute_buckets.pop(k, None)
    except Exception:
        logging.exception('failed to update minute buckets')
    
    # update per-second buckets for real-time chart
    try:
        now = datetime.now()
        current_second = now.strftime('%Y-%m-%d %H:%M:%S')
        # Reset buckets if we've moved to a new second
        # Stage 2 is under the hood - only track stage1, stage3, stage4
        if not hasattr(state, '_current_second') or state._current_second != current_second:
            state.second_buckets = {'stage1': 0, 'stage3': 0, 'stage4': 0}
            state._current_second = current_second
        
        if stage_label in state.second_buckets:
            state.second_buckets[stage_label] = state.second_buckets.get(stage_label, 0) + 1
    except Exception:
        logging.exception('failed to update second buckets')
    # Log broadcast for debugging
    logging.debug(f'Broadcasting event to dashboard: type={payload.get("type")}, stage={payload.get("stage")}, pid={payload.get("pid")}, connections={len(state.connections)}')
    
    asyncio.create_task(broadcast(payload))
    # persist promoted alerts
    if promoted:
        try:
            save_alert_to_db(payload)
        except Exception:
            logging.exception('save_alert_to_db failed')

def update_dashboard_stats(promoted: bool = False, reasons: List[str] = None):
    if reasons is None:
        reasons = []
    state.total_events += 1
    if promoted:
        state.total_alerts += 1
        if any("entropy" in r.lower() for r in reasons):
            state.entropy_hits += 1
        if "honeypot" in " ".join(reasons):
            state.honeypot_hits += 1
    
    # Broadcast stats update with per-stage counts for chart
    # Stage 2 is under the hood - only track stage1, stage3, stage4
    current_counts = {
        'stage1': state.second_buckets.get('stage1', 0),
        'stage3': state.second_buckets.get('stage3', 0),
        'stage4': state.second_buckets.get('stage4', 0)
    }
    
    asyncio.create_task(broadcast({
        "type": "stats",
        "total": state.total_events,
        "alerts": state.total_alerts,
        "entropy": state.entropy_hits,
        "honey": state.honeypot_hits,
        "rate": round(state.total_alerts / max(1, state.total_events) * 100, 2),
        "stage1": current_counts['stage1'],
        "stage3": current_counts['stage3'],
        "stage4": current_counts['stage4']
    }))

@app.get("/", response_class=HTMLResponse)
async def root():
    with open("src/dashboard/static/index.html", encoding="utf-8") as f:
        return f.read()


@app.get('/admin/recent')
async def admin_recent():
    # return last N raw events
    try:
        items = list(state.recent_events)[:200]
        return {'count': len(items), 'events': items}
    except Exception:
        logging.exception('failed to return recent events')
        return {'count': 0, 'events': []}


@app.get('/admin/jumps')
async def admin_jumps():
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute('SELECT id, ts, action, pid, image, raw FROM jumps ORDER BY id DESC LIMIT 200')
        rows = cur.fetchall()
        conn.close()
        return {'count': len(rows), 'jumps': [{'id': r[0], 'ts': r[1], 'action': r[2], 'pid': r[3], 'image': r[4], 'raw': json.loads(r[5]) if r[5] else {}} for r in rows]}
    except Exception:
        logging.exception('failed to read jumps')
        return {'count': 0, 'jumps': []}


@app.get('/admin/alerts')
async def admin_alerts():
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute('SELECT id, ts, pid, image, reasons, raw FROM alerts ORDER BY id DESC LIMIT 200')
        rows = cur.fetchall()
        conn.close()
        return {'count': len(rows), 'alerts': [{'id': r[0], 'ts': r[1], 'pid': r[2], 'image': r[3], 'reasons': json.loads(r[4]) if r[4] else [], 'raw': json.loads(r[5]) if r[5] else {}} for r in rows]}
    except Exception:
        logging.exception('failed to read alerts')
        return {'count': 0, 'alerts': []}

@app.post('/api/promote/stage3')
async def promote_to_stage3(request: Request):
    """
    Manually promote an event to Stage 3 (Threat Analysis).
    
    Request body should contain:
    - event: The event data dictionary (required)
    - or event_id: Reference to event in recent_events (optional)
    """
    try:
        body = await request.json()
        event = body.get('event')
        event_id = body.get('event_id')
        
        # If event_id provided, try to find it in recent_events
        if event_id and not event:
            try:
                # Try to find event by index or identifier
                events_list = list(state.recent_events)
                if isinstance(event_id, int) and 0 <= event_id < len(events_list):
                    event = events_list[event_id]
                else:
                    # Try to find by PID or other identifier
                    for evt in events_list:
                        if (str(evt.get('ProcessID', '')) == str(event_id) or 
                            str(evt.get('pid', '')) == str(event_id)):
                            event = evt
                            break
            except Exception:
                pass
        
        if not event:
            return {'success': False, 'error': 'Event data not provided or not found'}
        
        # Ensure event is a dict
        if isinstance(event, str):
            try:
                event = json.loads(event)
            except Exception:
                return {'success': False, 'error': 'Invalid event JSON'}
        
        # Mark as manually promoted
        event['__manually_promoted'] = True
        event['__manual_promotion_timestamp'] = datetime.now().isoformat()
        event['__manual_promotion_source'] = 'dashboard_api'
        
        # Remove any existing stage markers to ensure fresh processing
        event.pop('__stage3', None)
        event.pop('__stage3_score', None)
        event.pop('__stage3_result', None)
        
        # Process through Stage 3
        if _stage3_engine is None:
            return {'success': False, 'error': 'Stage 3 engine not registered'}
        
        try:
            result = _stage3_engine.process_event(event)
            
            # Log the manual promotion
            pid = event.get('ProcessID') or event.get('ProcessId') or event.get('pid') or '???'
            image = event.get('Image') or event.get('image') or 'Unknown'
            logging.info(f'Manual promotion to Stage 3: PID={pid} Image={image} Score={result.score:.2f} Tier={result.tier.value}')
            
            # Save to jumps table
            save_jump_to_db({
                'ts': datetime.now().isoformat(),
                'action': 'manual_promote_stage3',
                'pid': str(pid),
                'image': image,
                'raw': event
            })
            
            # ALWAYS send updated event back to dashboard with Stage 3 data, even if LOW tier
            # This ensures manually promoted events appear in Threat Analysis filter and tab
            tier_label = result.tier.value if hasattr(result.tier, 'value') else str(result.tier)
            reasons_list = [f"Manually promoted to Stage 3 (Score: {result.score:.2f}, Tier: {tier_label})"]
            
            # Add "benign" indicator for LOW tier
            if tier_label == 'low':
                reasons_list.append("Benign - Low risk")
            
            # Log before sending to dashboard for debugging
            logging.info(f'Sending manually promoted event to dashboard: PID={pid}, stage=stage3, score={result.score:.2f}')
            
            send_to_dashboard(
                event,
                promoted=False,  # Not an alert, just a stage promotion
                reasons=reasons_list,
                stage_override='stage3'
            )
            
            logging.info(f'Event sent to dashboard successfully (should appear in Threat Analysis tab)')
            
            return {
                'success': True,
                'message': 'Event promoted to Stage 3',
                'result': {
                    'score': result.score,
                    'tier': result.tier.value if hasattr(result.tier, 'value') else str(result.tier),
                    'promoted_to_stage4': result.promoted_to_stage4,
                    'immediate_response_triggered': result.immediate_response_triggered
                },
                'pid': str(pid),
                'image': image
            }
        except Exception as e:
            logging.exception('Error processing event in Stage 3')
            return {'success': False, 'error': f'Stage 3 processing failed: {str(e)}'}
            
    except Exception as e:
        logging.exception('Error in promote_to_stage3 endpoint')
        return {'success': False, 'error': str(e)}


@app.post('/api/label')
async def label_event(request: Request):
    """
    Label an event for Stage 3 dataset training.

    Body:
      - event_uuid: str (required)  (also accepts __event_uuid)
      - label: int (0 benign, 1 malicious) (required)
      - note: str (optional)
    """
    try:
        body = await request.json()
        event_uuid = body.get("event_uuid") or body.get("__event_uuid")
        label = body.get("label")
        note = body.get("note") or ""

        if not event_uuid:
            return {"success": False, "error": "event_uuid is required"}
        try:
            label_int = int(label)
        except Exception:
            return {"success": False, "error": "label must be 0 or 1"}
        if label_int not in (0, 1):
            return {"success": False, "error": "label must be 0 (benign) or 1 (malicious)"}

        upsert_stage3_label(str(event_uuid), label_int, source="dashboard", note=str(note))
        return {"success": True, "event_uuid": str(event_uuid), "label": label_int}
    except Exception as e:
        logging.exception("label_event failed")
        return {"success": False, "error": str(e)}

@app.post('/api/promote/stage4')
async def promote_to_stage4(request: Request):
    """
    Manually promote an event to Stage 4 (Active Threat).
    
    Request body should contain:
    - event: The event data dictionary (required)
    - or event_id: Reference to event in recent_events (optional)
    - force: If True, bypass Stage 3 and go directly to Stage 4 (default: False)
    """
    try:
        body = await request.json()
        event = body.get('event')
        event_id = body.get('event_id')
        force = body.get('force', False)
        
        # If event_id provided, try to find it in recent_events
        if event_id and not event:
            try:
                events_list = list(state.recent_events)
                if isinstance(event_id, int) and 0 <= event_id < len(events_list):
                    event = events_list[event_id]
                else:
                    # Try to find by PID or other identifier
                    for evt in events_list:
                        if (str(evt.get('ProcessID', '')) == str(event_id) or 
                            str(evt.get('pid', '')) == str(event_id)):
                            event = evt
                            break
            except Exception:
                pass
        
        if not event:
            return {'success': False, 'error': 'Event data not provided or not found'}
        
        # Ensure event is a dict
        if isinstance(event, str):
            try:
                event = json.loads(event)
            except Exception:
                return {'success': False, 'error': 'Invalid event JSON'}
        
        # Mark as manually promoted
        event['__manually_promoted'] = True
        event['__manual_promotion_timestamp'] = datetime.now().isoformat()
        event['__manual_promotion_source'] = 'dashboard_api'
        event['__manual_promotion_force'] = force
        
        # If force=True, skip Stage 3 and go directly to Stage 4
        # Otherwise, ensure event has been through Stage 3 first
        if not force:
            # Check if event has Stage 3 data, if not, run through Stage 3 first
            if not event.get('__stage3') and not event.get('__stage3_score'):
                if _stage3_engine is None:
                    return {'success': False, 'error': 'Stage 3 engine not registered. Use force=true to bypass.'}
                try:
                    stage3_result = _stage3_engine.process_event(event)
                    # Continue with Stage 4 even if Stage 3 didn't promote
                except Exception as e:
                    logging.warning(f'Stage 3 processing failed before Stage 4: {e}')
        
        # Process through Stage 4
        if _stage4_engine is None:
            return {'success': False, 'error': 'Stage 4 engine not registered'}
        
        try:
            decision = _stage4_engine.process_event(event)
            
            # Log the manual promotion
            pid = event.get('ProcessID') or event.get('ProcessId') or event.get('pid') or '???'
            image = event.get('Image') or event.get('image') or 'Unknown'
            logging.info(f'Manual promotion to Stage 4: PID={pid} Image={image} Verdict={decision.verdict.value} Score={decision.score:.2f}')
            
            # Save to jumps table
            save_jump_to_db({
                'ts': datetime.now().isoformat(),
                'action': 'manual_promote_stage4',
                'pid': str(pid),
                'image': image,
                'raw': event
            })
            
            # Send updated event back to dashboard with Stage 4 data
            # This ensures it appears in Active Threats filter
            send_to_dashboard(
                event,
                promoted=True,  # Stage 4 events are always alerts
                reasons=decision.reasoning if hasattr(decision, 'reasoning') else [f"Manually promoted to Stage 4 (Verdict: {decision.verdict.value}, Score: {decision.score:.2f})"],
                stage_override='stage4'
            )
            
            return {
                'success': True,
                'message': 'Event promoted to Stage 4',
                'result': {
                    'verdict': decision.verdict.value if hasattr(decision.verdict, 'value') else str(decision.verdict),
                    'score': decision.score,
                    'confidence': decision.confidence,
                    'reasons': decision.reasoning
                },
                'pid': str(pid),
                'image': image
            }
        except Exception as e:
            logging.exception('Error processing event in Stage 4')
            return {'success': False, 'error': f'Stage 4 processing failed: {str(e)}'}
            
    except Exception as e:
        logging.exception('Error in promote_to_stage4 endpoint')
        return {'success': False, 'error': str(e)}

@app.websocket("/ws")
async def websocket(ws: WebSocket):
    await ws.accept()
    state.connections.append(ws)
    await ws.send_json({
        "type": "stats",
        "total": state.total_events,
        "alerts": state.total_alerts,
        "entropy": state.entropy_hits,
        "honey": state.honeypot_hits,
        "rate": round(state.total_alerts / max(1, state.total_events) * 100, 2) if state.total_events else 0
    })
    # send recent alerts history to newly connected client
    try:
        init_db()
        history = get_alerts_history(minutes=60)
        minute_series = get_minute_series(minutes=60)
        await ws.send_json({"type": "history", "alerts": history, "series": minute_series})
    except Exception:
        logging.exception('failed to send history on connect')
    
    # Send recent events that happened before WebSocket connection
    # This fixes the delay where events don't appear until new ones arrive
    try:
        recent_events_list = list(state.recent_events)
        if recent_events_list:
            # Send last 50 recent events to catch up the client
            for event in recent_events_list[:50]:
                try:
                    # Reconstruct the payload as it would have been sent originally
                    pid = event.get("ProcessID") or event.get("ProcessId") or event.get("process_id") or event.get('pid') or None
                    image = event.get("Image") or event.get("image") or event.get('ImagePath') or 'Unknown'
                    
                    # Determine stage label
                    if event.get('__stage4') or event.get('__stage5'):
                        stage_label = 'stage4'
                    elif event.get('__stage3') or event.get('__stage3_score') is not None:
                        stage_label = 'stage3'
                    else:
                        stage_label = 'stage1'
                    
                    promoted = bool(event.get('__stage4') or event.get('__stage5') or event.get('__stage3_immediate_response'))
                    reasons = event.get("__reasons", [])
                    
                    payload = {
                        "type": "alert" if promoted else "event",
                        "timestamp": event.get("timestamp") or event.get("EventTime") or datetime.now().isoformat(),
                        "pid": str(pid) if pid is not None else '???',
                        "image": image,
                        "reasons": reasons[:6] if isinstance(reasons, list) else [],
                        "raw": event,
                        "stage": stage_label
                    }
                    
                    # Add ML score if available
                    if event.get("__stage3_score") is not None:
                        payload["ml_score"] = float(event.get("__stage3_score", 0.0))
                        payload["ml_threshold"] = True
                    
                    if event.get("__stage3_tier") is not None:
                        payload["stage3_tier"] = event.get("__stage3_tier")
                    
                    if event.get("__stage4_verdict") is not None:
                        payload["stage4_verdict"] = event.get("__stage4_verdict")
                        payload["stage4_score"] = float(event.get("__stage4_score", 0.0))
                    
                    await ws.send_json(payload)
                except Exception as e:
                    logging.debug(f"Failed to send recent event to new client: {e}")
                    continue
            logging.info(f"Sent {min(50, len(recent_events_list))} recent events to newly connected client")
    except Exception:
        logging.exception('failed to send recent events on connect')
    try:
        while True:
            text = await ws.receive_text()
            try:
                msg = json.loads(text)
            except Exception:
                # ignore malformed messages
                continue
            
            # Handle ping/pong for keepalive
            if msg.get('type') == 'ping':
                try:
                    await ws.send_json({'type': 'pong', 'timestamp': msg.get('timestamp')})
                    continue
                except Exception:
                    # Connection might be dead, break loop to clean up
                    break
            
            # handle a 'jump' action from the UI
            try:
                if msg.get('type') == 'jump':
                    logging.info('Received jump request for pid=%s image=%s', msg.get('pid'), msg.get('image'))
                    # persist the action
                    try:
                        save_jump_to_db({'ts': datetime.now().isoformat(), 'action': 'jump', 'pid': msg.get('pid'), 'image': msg.get('image'), 'raw': msg.get('raw')})
                    except Exception:
                        logging.exception('save_jump_to_db failed')
                    # acknowledge back to sender
                    try:
                        await ws.send_json({'type': 'jump_ack', 'status': 'ok', 'pid': msg.get('pid'), 'ts': datetime.now().isoformat()})
                    except Exception:
                        logging.exception('failed to send jump_ack')
                    # broadcast action to other clients
                    try:
                        await broadcast({'type': 'action', 'action': 'jump', 'pid': msg.get('pid'), 'image': msg.get('image'), 'ts': datetime.now().isoformat()})
                    except Exception:
                        logging.exception('broadcast action failed')
                    # notify any registered stage3 handlers (launcher)
                    try:
                        _notify_stage3_handlers(msg)
                    except Exception:
                        logging.exception('notify stage3 handlers failed')
                else:
                    # other message types can be ignored or extended
                    logging.debug('ws message: %s', msg.get('type'))
            except Exception:
                logging.exception('error handling incoming ws message')
    except WebSocketDisconnect:
        state.connections.remove(ws)
    except Exception:
        state.connections.remove(ws)

# THIS FUNCTION WAS MISSING — THIS IS THE FIX
def start_dashboard_background():
    import uvicorn
    logging.getLogger("uvicorn").setLevel(logging.WARNING)
    try:
        logging.info("Starting dashboard server on http://127.0.0.1:8000")
        uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")
    except Exception as e:
        logging.exception(f"Dashboard server failed to start: {e}")
        raise

print("DASHBOARD SERVER LOADED — READY FOR CONNECTIONS")