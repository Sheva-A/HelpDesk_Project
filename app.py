from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
# Налаштування БД та секретний ключ для захисту сесій
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///helpdesk.db'
app.config['SECRET_KEY'] = 'helpdesk-secret-key'

db = SQLAlchemy(app)

# Налаштування менеджера логіну
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    # Отримання об'єкта користувача з БД за його ID
    return User.query.get(int(user_id))

# МОДЕЛІ БД
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
        # Видаляємо зайві пробіли на початку і в кінці
        # Робимо email нечутливим до регістру
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')
        room_number = request.form.get('room_number')

        # Перевірка, чи пароль не порожній та не складається лише з пробілів
        if not password or password.strip() == "":
            flash('Пароль не може бути порожнім або складатися лише з пробілів', 'danger')
            return redirect(url_for('register'))

        # Перевірка мінімальної довжини
        if len(password) < 8:
            flash('Пароль має містити не менше 8 символів', 'danger')
            return redirect(url_for('register'))
        
        # Перевірка максимальної довжини
        if len(password) > 250:
            flash('Пароль занадто довгий (максимум 250 символів)', 'danger')
            return redirect(url_for('register'))

        # Перевірка домену
        if not username or not username.endswith(ALLOWED_DOMAIN):
            flash(f'Реєстрація тільки для пошти {ALLOWED_DOMAIN}', 'danger')
            return redirect(url_for('register'))

        # Перевірка на унікальність email в системі
        if User.query.filter_by(username=username).first():
            flash('Цей Email вже зареєстровано', 'danger')
            return redirect(url_for('register'))

        # Спроба створити нового користувача
        try:
            # Хешування пароля та збереження
            new_user = User(
                username=username,
                password=generate_password_hash(password),
                role='student',
                room_number=room_number
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Акаунт створено! Тепер увійдіть.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Помилка бази даних: {str(e)}', 'danger')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard' if current_user.role == 'admin' else 'my_tickets'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')

        # Перевірка на пробіли при вході
        if not password or password.strip() == "":
            flash('Введіть пароль', 'danger')
            return redirect(url_for('login'))

        # Обмеження довжини при вході
        if len(password) > 250:
            flash('Пароль занадто довгий', 'danger')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()

        # Перевірка пароля через хеш
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Ви успішно увійшли!', 'success')
            return redirect(url_for('dashboard') if user.role == 'admin' else url_for('my_tickets'))
        
        flash('Невірні дані для входу', 'danger')

    return render_template('login.html')

@app.route('/create_ticket', methods=['GET', 'POST'])
@login_required
def create_ticket():
    # Форма створення нової заявки
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')

        # Валідація: чи не пусті поля
        if not title or not description:
            flash('Будь ласка, заповніть всі поля!', 'warning')
            return redirect(url_for('create_ticket'))

        try:
            # Створення об'єкта заявки та прив'язка до автора
            new_ticket = Ticket(
                title=title,
                description=description,
                user_id=current_user.id,
                status='Нова'
            )

            # Збереження нової заявки в базу даних
            db.session.add(new_ticket)
            db.session.commit()
            
            flash('Заявку успішно створено!', 'success')
            return redirect(url_for('my_tickets')) 

        except Exception as e:
            # Відкат змін у разі помилки
            db.session.rollback()
            flash(f'Помилка створення заявки: {str(e)}', 'danger')

    return render_template('student/create_ticket.html') 


@app.route('/my_tickets')
@login_required
def my_tickets():
    # Отримання списку заявок поточного користувача
    tickets = Ticket.query.filter_by(user_id=current_user.id).order_by(Ticket.created_at.desc()).all()
    
    return render_template('student/my_tickets.html', tickets=tickets)


@app.route('/dashboard')
@login_required
def dashboard():
    # Панель управління для адміністратора
    if current_user.role != 'admin':
        flash('У вас немає прав доступу до панелі адміністратора!', 'danger')
        return redirect(url_for('my_tickets'))

    # Отримання всіх заявок усіх користувачів
    all_tickets = Ticket.query.order_by(Ticket.created_at.desc()).all()

    return render_template('admin/dashboard.html', tickets=all_tickets)


@app.route('/logout')
@login_required
def logout():
    # Процес виходу користувача із системи
    logout_user()
    flash('Ви вийшли з системи', 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)