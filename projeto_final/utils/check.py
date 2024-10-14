from db.models.logs import Log
from db.models.quarantine import Quarantine
from datetime import timedelta, datetime, timezone
from db.database import db
from db.models.users import User
from flask import current_app
from flask_mail import Message

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_TIME = timedelta(minutes=10)

def quarantine(user_id, ip_address):
    # Utilizando UTC para a comparação de tempo
    now = datetime.now(timezone.utc)

    # Verificando se o usuário ou o IP está em quarentena
    find_user = Quarantine.query.filter(
        Quarantine.user_id == user_id,
        Quarantine.end_time >= now  # Comparando com UTC
    ).first() 
    
    find_ip = Quarantine.query.filter(
        Quarantine.ip_address == ip_address,
        Quarantine.end_time >= now  # Comparando com UTC
    ).first() 
    
    if find_user or find_ip:
        return True
    
    return False
    

def check_limit(user_id, ip_address):
    # Utilizando UTC para o limite de tempo
    now = datetime.now(timezone.utc)
    time_threshold = now - LOCKOUT_TIME
    
    # Contar as tentativas de login falhadas com base no tempo UTC
    failed_attempts = Log.query.filter(
        Log.user_id == user_id,
        Log.timestamp >= time_threshold,  # Comparando com UTC
        Log.success == False  
    ).count()

    # Se as tentativas falhadas excederem o limite, colocar o usuário em quarentena
    if failed_attempts >= MAX_FAILED_ATTEMPTS:
        quarantine_entry = Quarantine(
            user_id=user_id,
            start_time=now,  # Usando UTC
            end_time=now + LOCKOUT_TIME,  # Usando UTC
            reason='TOO MANY ATTEMPTS',
            ip_address=ip_address
        )
        try:
            db.session.add(quarantine_entry)
            db.session.commit()
        except Exception as e:
            print(f'Ocorreu um erro ao colocar em quarentena: {e}')
            
        if user_id:
            user = User.query.get(user_id)
            if user:
                try:
                    msg = Message('Alerta de Segurança', recipients=[user.email])
                    msg.body = '''
                    Detectamos várias tentativas de login falhas em sua conta. 
                    Por segurança, bloqueamos temporariamente o acesso.
                    Se não foi você, recomendamos que altere sua senha após o desbloqueio.
                    '''
                    mail = current_app.extensions.get('mail')
                    if mail:
                        mail.send(msg)
                    else:
                        print('Mail extension not found in current_app')
                except Exception as e:
                    print(f'Erro ao enviar email de alerta: {e}')
                    
        return True
    
    return False