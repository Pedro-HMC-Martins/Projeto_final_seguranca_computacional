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

# Obter a URL do banco de dados a partir da variável de ambiente
DATABASE_URL = os.getenv('DATABASE_URL')

# Criar a conexão com o banco de dados
engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

# Consultar todos os logs do banco de dados
log_entries = session.query(Log).all()

# Converter os logs em uma lista de dicionários
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

# Criar um DataFrame a partir dos logs
logs_df = pd.DataFrame(logs_data)

# Converter 'timestamp' para datetime e extrair data e hora
logs_df['timestamp'] = pd.to_datetime(logs_df['timestamp'])
logs_df['date'] = logs_df['timestamp'].dt.date
logs_df['hour'] = logs_df['timestamp'].dt.hour

# Consultar todas as quarentenas do banco de dados
quarantine_entries = session.query(Quarantine).all()

# Converter as quarentenas em uma lista de dicionários
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

# Criar um DataFrame a partir das quarentenas
quarantine_df = pd.DataFrame(quarantine_data)

# Converter 'start_time' e 'end_time' para datetime
quarantine_df['start_time'] = pd.to_datetime(quarantine_df['start_time'])
quarantine_df['end_time'] = pd.to_datetime(quarantine_df['end_time'])

# Verificar se 'start_time' e 'end_time' estão com fuso horário; se não, definir como UTC
if quarantine_df['start_time'].dt.tz is None:
    quarantine_df['start_time'] = quarantine_df['start_time'].dt.tz_localize('UTC')

if quarantine_df['end_time'].dt.tz is None:
    quarantine_df['end_time'] = quarantine_df['end_time'].dt.tz_localize('UTC')

# Obter o tempo atual em UTC
current_time = datetime.now(timezone.utc)

# Filtrar quarentenas ativas no momento atual
active_quarantines = quarantine_df[
    (quarantine_df['start_time'] <= current_time) & (quarantine_df['end_time'] >= current_time)
]

# Calcular o número de usuários e IPs únicos em quarentena
num_users_in_quarantine = active_quarantines['user_id'].nunique()
num_ips_in_quarantine = active_quarantines['ip_address'].nunique()

print(f'Número de usuários em quarentena: {num_users_in_quarantine}')
print(f'Número de IPs em quarentena: {num_ips_in_quarantine}')

# Plotar tentativas de login por hora do dia
hourly_attempts = logs_df.groupby('hour').size()

hourly_attempts.plot(kind='bar', figsize=(12, 6))
plt.title('Tentativas de Login por Hora do Dia')
plt.xlabel('Hora do Dia')
plt.ylabel('Número de Tentativas')
plt.tight_layout()

# Salvar o gráfico antes de mostrar
plt.savefig('login_attempts_by_hour.png')
plt.show()
plt.close()

# Plotar tentativas de login por data
daily_attempts = logs_df.groupby('date').size()

daily_attempts.plot(kind='line', figsize=(12, 6))
plt.title('Tentativas de Login por Data')
plt.xlabel('Data')
plt.ylabel('Número de Tentativas')
plt.tight_layout()

plt.savefig('login_attempts_by_date.png')
plt.show()
plt.close()

# Plotar tentativas de login bem-sucedidas vs. mal-sucedidas
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

# Plotar tentativas de login por endereço IP
top_ip_attempts = logs_df['ip_address'].value_counts().head(10)

top_ip_attempts.plot(kind='bar', figsize=(12, 6))
plt.title('Top 10 Endereços IP por Tentativas de Login')
plt.xlabel('Endereço IP')
plt.ylabel('Número de Tentativas')
plt.tight_layout()

plt.savefig('login_attempts_by_ip.png')
plt.show()
plt.close()