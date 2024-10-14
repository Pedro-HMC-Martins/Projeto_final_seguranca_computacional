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
    now = datetime.now(timezone.utc)

    find_user = Quarantine.query.filter(
        Quarantine.user_id == user_id,
        Quarantine.end_time >= now 
    ).first() 
    
    find_ip = Quarantine.query.filter(
        Quarantine.ip_address == ip_address,
        Quarantine.end_time >= now 
    ).first() 
    
    if find_user or find_ip:
        return True
    
    return False
    

def check_limit(user_id, ip_address):
    now = datetime.now(timezone.utc)
    time_threshold = now - LOCKOUT_TIME
    failed_attempts = Log.query.filter(
        Log.user_id == user_id,
        Log.timestamp >= time_threshold,  
        Log.success == False  
    ).count()

    if failed_attempts >= MAX_FAILED_ATTEMPTS:
        quarantine_entry = Quarantine(
            user_id=user_id,
            start_time=now, 
            end_time=now + LOCKOUT_TIME, 
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