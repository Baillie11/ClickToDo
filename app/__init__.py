from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'your-secret-key'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///clicktodo.db'

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'

    from .routes import main
    app.register_blueprint(main)

    return app
