from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, login_required, logout_user, current_user
from . import db, login_manager
from .models import User, Task

main = Blueprint('main', __name__)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@main.route('/')
def index():
    return redirect(url_for('main.login'))

@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('main.dashboard'))
        flash('Invalid username or password')
    return render_template('login.html')

@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
        else:
            new_user = User(username=username)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful. Please log in.')
            return redirect(url_for('main.login'))
    return render_template('register.html')

@main.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        content = request.form['content']
        new_task = Task(content=content, owner=current_user)
        db.session.add(new_task)
        db.session.commit()
    tasks = Task.query.filter_by(owner=current_user).all()
    return render_template('dashboard.html', tasks=tasks)

@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))
