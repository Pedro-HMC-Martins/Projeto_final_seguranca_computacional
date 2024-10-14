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

log_entries = session.query(Log).all()

logs_data = []
for log in log_entries:
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

quarantine_entries = session.query(Quarantine).all()

quarantine_data = []
for quarantine in quarantine_entries:
    quarantine_data.append({
        'id': quarantine.id,
        'user_id': quarantine.user_id,
        'start_time': quarantine.start_time,
        'end_time': quarantine.end_time,
        'reason': quarantine.reason,
        'ip_address': quarantine.ip_address
    })

quarantine_df = pd.DataFrame(quarantine_data)

quarantine_df['start_time'] = pd.to_datetime(quarantine_df['start_time'])
quarantine_df['end_time'] = pd.to_datetime(quarantine_df['end_time'])

if quarantine_df['start_time'].dt.tz is None:
    quarantine_df['start_time'] = quarantine_df['start_time'].dt.tz_localize('UTC')

if quarantine_df['end_time'].dt.tz is None:
    quarantine_df['end_time'] = quarantine_df['end_time'].dt.tz_localize('UTC')

current_time = datetime.now(timezone.utc)

active_quarantines = quarantine_df[
    (quarantine_df['start_time'] <= current_time) & (quarantine_df['end_time'] >= current_time)
]

num_users_in_quarantine = active_quarantines['user_id'].nunique()
num_ips_in_quarantine = active_quarantines['ip_address'].nunique()

print(f'Número de usuários em quarentena: {num_users_in_quarantine}')
print(f'Número de IPs em quarentena: {num_ips_in_quarantine}')

hourly_attempts = logs_df.groupby('hour').size()

hourly_attempts.plot(kind='bar', figsize=(12, 6))
plt.title('Tentativas de Login por Hora do Dia')
plt.xlabel('Hora do Dia')
plt.ylabel('Número de Tentativas')
plt.tight_layout()

plt.savefig('login_attempts_by_hour.png')
plt.show()
plt.close()

success_counts = logs_df['success'].value_counts()

success_counts.plot(kind='bar', figsize=(8, 6))
plt.title('Tentativas de Login: Sucesso vs. Falha')
plt.xlabel('Resultado')
plt.ylabel('Número de Tentativas')
plt.xticks([0, 1], ['Falha', 'Sucesso'], rotation=0)
plt.tight_layout()

plt.savefig('login_attempts_success_vs_failure.png')
plt.show()
plt.close()

top_ip_attempts = logs_df['ip_address'].value_counts()

top_ip_attempts.plot(kind='bar', figsize=(12, 6))
plt.title('Top 10 Endereços IP por Tentativas de Login')
plt.xlabel('Endereço IP')
plt.ylabel('Número de Tentativas')
plt.tight_layout()

plt.savefig('login_attempts_by_ip.png')
plt.show()
plt.close()