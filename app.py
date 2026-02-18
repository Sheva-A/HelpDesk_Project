from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
# Конфігурація БД та сесій
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///helpdesk.db'
app.config['SECRET_KEY'] = 'helpdesk-secret-key'

db = SQLAlchemy(app)

# Налаштування Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# МОДЕЛІ

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='student')
    room_number = db.Column(db.String(10), nullable=True)
    tickets = db.relationship('Ticket', backref='author', lazy=True)

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Нова')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    admin_comment = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# МАРШРУТИ

ALLOWED_DOMAIN = '@stud.duikt.edu.ua'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard' if current_user.role == 'admin' else 'my_tickets'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')
        room_number = request.form.get('room_number')

        # Валідація пароля
        if not password or password.strip() == "":
            flash('Пароль не може бути порожнім', 'danger')
            return redirect(url_for('register'))
        if not (8 <= len(password) <= 250):
            flash('Довжина пароля: 8-250 символів', 'danger')
            return redirect(url_for('register'))

        # Валідація домену та унікальності
        if not username or not username.endswith(ALLOWED_DOMAIN):
            flash(f'Дозволено тільки {ALLOWED_DOMAIN}', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash('Email вже зареєстровано', 'danger')
            return redirect(url_for('register'))

        try:
            new_user = User(
                username=username,
                password=generate_password_hash(password),
                role='student',
                room_number=room_number
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Акаунт створено!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Помилка БД: {str(e)}', 'danger')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard' if current_user.role == 'admin' else 'my_tickets'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')

        if not password or len(password) > 250:
            flash('Некоректний пароль', 'danger')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Успішний вхід!', 'success')
            return redirect(url_for('dashboard') if user.role == 'admin' else url_for('my_tickets'))
        
        flash('Невірні дані', 'danger')
    return render_template('login.html')

@app.route('/create_ticket', methods=['GET', 'POST'])
@login_required
def create_ticket():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description', '').strip()

        if not title or not description:
            flash('Опис не може бути порожнім або містити лише пробіли!', 'warning')
            return redirect(url_for('create_ticket'))

        if len(description) > 500:
            flash('Опис занадто довгий (максимум 500 символів)!', 'danger')
            return redirect(url_for('create_ticket'))

        try:
            new_ticket = Ticket(
                title=title,
                description=description,
                user_id=current_user.id
            )
            db.session.add(new_ticket)
            db.session.commit()
            flash('Заявку створено!', 'success')
            return redirect(url_for('my_tickets')) 
        except Exception as e:
            db.session.rollback()
            flash('Виникла помилка при збереженні. Спробуйте ще раз.', 'danger')

    return render_template('student/create_ticket.html')

@app.route('/my_tickets')
@login_required
def my_tickets():
    tickets = Ticket.query.filter_by(user_id=current_user.id).order_by(Ticket.created_at.desc()).all()
    return render_template('student/my_tickets.html', tickets=tickets)

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role != 'admin':
        flash('Доступ заборонено!', 'danger')
        return redirect(url_for('my_tickets'))

    status_filter = request.args.get('status')
    query = Ticket.query
    if status_filter:
        query = query.filter_by(status=status_filter)
    
    all_tickets = query.order_by(Ticket.created_at.desc()).all()
    return render_template('admin/dashboard.html', tickets=all_tickets)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Ви вийшли із системи', 'info')
    return redirect(url_for('login'))

@app.route('/edit_ticket/<int:ticket_id>', methods=['GET', 'POST'])
@login_required
def edit_ticket(ticket_id):
    if current_user.role != 'admin':
        return redirect(url_for('my_tickets'))
    
    ticket = Ticket.query.get_or_404(ticket_id)
    
    if request.method == 'POST':
        new_status = request.form.get('status') or ticket.status
        admin_comment = (request.form.get('admin_comment') or "").strip()
        old_status = ticket.status

        if len(admin_comment) > 500:
            flash('Коментар занадто довгий (максимум 500 символів)!', 'danger')
            return redirect(url_for('edit_ticket', ticket_id=ticket.id))

        if new_status != old_status:
            if old_status in ['Виконано', 'Відхилено']:
                flash('Неможливо змінити закриту заявку!', 'danger')
                return redirect(url_for('edit_ticket', ticket_id=ticket.id))
            
            if old_status == 'Нова' and new_status == 'Виконано':
                flash('Спочатку переведіть в статус "В роботі"!', 'warning')
                return redirect(url_for('edit_ticket', ticket_id=ticket.id))

        ticket.status = new_status
        ticket.admin_comment = admin_comment
        
        try:
            db.session.commit()
            flash('Збережено!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Помилка БД: {str(e)}', 'danger')
            return redirect(url_for('edit_ticket', ticket_id=ticket.id))

    return render_template('admin/edit_ticket.html', ticket=ticket)

@app.route('/delete_ticket/<int:ticket_id>', methods=['POST'])
@login_required
def delete_ticket(ticket_id):
    if current_user.role != 'admin':
        return redirect(url_for('my_tickets'))
    
    ticket = Ticket.query.get_or_404(ticket_id)
    db.session.delete(ticket)
    db.session.commit()
    flash('Заявку видалено', 'warning')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)