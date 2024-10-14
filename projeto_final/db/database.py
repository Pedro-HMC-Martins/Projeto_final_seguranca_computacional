import os
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv

load_dotenv()

# Inicializar o SQLAlchemy
db = SQLAlchemy()

def init_app(app):
    """Função para inicializar o banco de dados com o Flask app."""
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
    db.init_app(app)