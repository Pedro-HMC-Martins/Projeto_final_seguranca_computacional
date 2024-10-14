
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db.models.logs import Log
from db.models.quarantine import Quarantine
from db.models.users import User
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timezone

DATABASE_URL = os.getenv('DATABASE_URL')

engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

logs = session.query(Log).all()

logs_data = []
for log in logs:
    logs_data.append({
        'id': log.id,
        'user_id': log.user_id,
        'event_type': log.event_type,
        'timestamp': log.timestamp,
        'message': log.message,
        'ip_address': log.ip_address,
        'success': log.success
    })

logs_df = pd.DataFrame(logs_data)

logs_df['timestamp'] = pd.to_datetime(logs_df['timestamp'])
logs_df['date'] = logs_df['timestamp'].dt.date
logs_df['hour'] = logs_df['timestamp'].dt.hour

quarantines = session.query(Quarantine).all()

quarantine_data = []
for q in quarantines:
    quarantine_data.append({
        'id': q.id,
        'user_id': q.user_id,
        'start_time': q.start_time,
        'end_time': q.end_time,
        'reason': q.reason,
        'ip_address': q.ip_address
    })

quarantine_df = pd.DataFrame(quarantine_data)

quarantine_df['start_time'] = pd.to_datetime(quarantine_df['start_time'])
quarantine_df['end_time'] = pd.to_datetime(quarantine_df['end_time'])

print(quarantine_df['start_time'].dtype)
print(quarantine_df['end_time'].dtype)

if quarantine_df['start_time'].dt.tz is None:
    quarantine_df['start_time'] = quarantine_df['start_time'].dt.tz_localize('UTC')

if quarantine_df['end_time'].dt.tz is None:
    quarantine_df['end_time'] = quarantine_df['end_time'].dt.tz_localize('UTC')

now = datetime.now(timezone.utc)

current_quarantines = quarantine_df[
    (quarantine_df['start_time'] <= now) & (quarantine_df['end_time'] >= now)
]

num_users_in_quarantine = current_quarantines['user_id'].nunique()
num_ips_in_quarantine = current_quarantines['ip_address'].nunique()

print(f'Número de usuários em quarentena: {num_users_in_quarantine}')
print(f'Número de IPs em quarentena: {num_ips_in_quarantine}')

hourly_attempts = logs_df.groupby('hour').size()

hourly_attempts.plot(kind='bar', figsize=(12, 6))
plt.title('Tentativas de Login por Hora do Dia')
plt.xlabel('Hora do Dia')
plt.ylabel('Número de Tentativas')
plt.tight_layout()
plt.show()

plt.savefig('login_attempts_by_date.png')
plt.show()