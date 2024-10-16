from flask import Flask, render_template, request, redirect, url_for, session
from flask_mail import Mail, Message
from db.database import db, init_app
from db.models.users import User
from db.models.quarantine import Quarantine
from db.models.logs import Log
from utils.hash import *
import random
from utils.check import *
from utils.detection import *
from utils.patterns import *
from utils.log_event import *

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = os.getenv('MAIL_PORT')
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS')
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

mail = Mail(app)

init_app(app)

def enviar_email_verificacao(token,email_destinatario):
    try:
        msg = Message('Token de verificacao', recipients=[f'{email_destinatario}'])
        msg.body = f'Seu token de verificacao e esse {token}'
        mail.send(msg)
        return 'email enviado'
    except Exception as e:
        return f'Erro ao enviar email'

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        ip_address = request.remote_addr
        email = request.form.get('email', '')
        senha = request.form.get('password', '')
        
        #Verificacao de injecao
        sql_injection_detected = is_sql_injection(email) or is_sql_injection(senha)
        xss_detected = is_xss_attempt(email) or is_xss_attempt(senha)
        command_injection_detected = is_command_injection(email) or is_command_injection(senha)
        
        user = User.query.filter_by(email=email).first()
        
        user_id = user.id if user else None 
        
        if quarantine(user_id, ip_address):
            print('IP ou usuario temporariamente banido')
            return 'IP ou usuario temporariamente banido'

        if check_limit(user_id, ip_address):
            print('IP/email temporariamente bloqueado devido a muitas tentativas de login')
            log_event(user_id, ip_address, 'LOGIN_FAILURE_WITH_POSSIBLE_BRUTE_FORCE_ATTEMPT','Possivel tentativa de ataque de forca bruta durante o login', False)
            return 'IP/email temporariamente bloqueado devido a muitas tentativas de login'
        
        if not user or hashing_input_with_salt(senha, user.salt) != user.password_hash:
            print("email ou senha invalido")
            
            # Log the event
            if sql_injection_detected:
                log_event(user_id, ip_address, 'LOGIN_FAILURE_WITH_SQL_INJECTION_ATTEMPT', 'Possivel tentativa de SQL Injection durante o login', False)
                move_quarantine(user_id=user_id,ip_address=ip_address, reason='SQL INJECTION ATTEMPT')
            elif xss_detected:
                log_event(user_id, ip_address, 'LOGIN_FAILURE_WITH_XSS_INJECTION_ATTEMPT', 'Possivel tentativa de XSS Injection durante o login', False)
                move_quarantine(user_id=user_id,ip_address=ip_address, reason='XSS ATTEMPT')
            elif command_injection_detected:
                log_event(user_id, ip_address, 'LOGIN_FAILURE_WITH_COMMAND_INJECTION_ATTEMPT', 'Possivel tentativa de Command Injection durante o login', False)
                move_quarantine(user_id=user_id,ip_address=ip_address, reason='COMMAND INJECTION ATTEMPT')
            else:
                log_event(user_id, ip_address, 'LOGIN_FAILURE', 'Falha ao tentar efetuar login', False)
            
            return render_template('login.html')
        
        log_event(user_id, ip_address, 'LOGIN_ATTEMPT', 'Usuario conseguiu efetuar login', True)
        return f'Bem-vindo, {user.email}!'
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        senha = request.form.get('senha')
        
        user = User.query.filter_by(email = email).first()
        if user:
            return 'Email ja registrado', 400
        safety_token = str(random.randint(100000, 999999))
        session['codigo_verificacao'] = safety_token
        session['novo_usuario'] = {'email': email, 'senha': senha, 'safety_token': safety_token}
        
        enviar_email_verificacao(safety_token, email)
        
        return redirect(url_for('token_verify'))
    return render_template('register.html')

@app.route('/token_verify', methods=['GET', 'POST'])
def token_verify():
    if request.method == 'POST':
        codigo_inserido = request.form.get('codigo')
        codigo_verificacao = session.get('codigo_verificacao')
        
        if codigo_inserido == codigo_verificacao:
            novo_usuario = session.get('novo_usuario')
            if novo_usuario:
                try:
                    salt = generate_salt()
                    user = User(
                        email=novo_usuario['email'],
                        password_hash = hashing_input_with_salt(novo_usuario['senha'], salt),
                        salt = salt,
                        is_active = True,
                        safety_token=novo_usuario['safety_token'] 
                    )
                    db.session.add(user)
                    db.session.commit()
                    print("usuario criado")
                    session.pop('codigo_verificacao', None)
                    session.pop('novo_usuario', None)
                    return(redirect('/'))
                except Exception:
                    return 'erro ao enviar ao BD', 500
            else:
                return 'erro ao recuperar dados do usuario', 400
        else:
            return 'Código de verificacao incorreto', 400
    return render_template('token_verify.html')

if __name__ == '__main__':
    app.run(debug=True)