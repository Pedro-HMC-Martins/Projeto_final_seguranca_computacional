from datetime import datetime, timezone
from db.models.logs import Log
from db.database import db

def log_event(user_id, ip_address, event_type, message,success):
    log = Log(
        user_id=user_id,
        event_type=event_type,
        message=message,
        ip_address=ip_address,
        timestamp=datetime.now(timezone.utc),
        success=success
    )
    try:
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        print(f"ocorreu um erro {e}")
