from flask import render_template, redirect, url_for, request, abort
from flask_login import login_required, current_user
from app.models import Task
from app import db
from flask import Blueprint
from flask_login import login_user, logout_user
from app.models import User
from werkzeug.security import check_password_hash
from flask import flash



main = Blueprint('main', __name__)

@main.route('/')
def home():
    return redirect(url_for('main.dashboard'))

@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('main.dashboard'))
        else:
            flash('Invalid email or password.')

    return render_template('login.html')



@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        password = request.form.get('password')

        if User.query.filter_by(email=email).first():
            flash('Email already registered.')
            return redirect(url_for('main.register'))

        new_user = User(full_name=full_name, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created. Please log in.')
        return redirect(url_for('main.login'))

    return render_template('register.html')



@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))


@main.route('/dashboard')
@login_required
def dashboard():
    tasks = Task.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', tasks=tasks)

@main.route('/add', methods=['POST'])
@login_required
def add_task():
    content = request.form.get('content')
    if content:
        new_task = Task(content=content, user_id=current_user.id)
        db.session.add(new_task)
        db.session.commit()
    return redirect(url_for('main.dashboard'))

@main.route('/toggle/<int:task_id>', methods=['POST'])
@login_required
def toggle_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        abort(403)
    task.completed = not getattr(task, 'completed', False)
    db.session.commit()
    return redirect(url_for('main.dashboard'))

@main.route('/delete/<int:task_id>', methods=['POST'])
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        abort(403)
    db.session.delete(task)
    db.session.commit()
    return redirect(url_for('main.dashboard'))

@main.route('/edit/<int:task_id>', methods=['POST'])
@login_required
def edit_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        abort(403)

    new_content = request.form.get('new_content')
    if new_content:
        task.content = new_content
        db.session.commit()
        flash('Task updated.')

    return redirect(url_for('main.dashboard'))