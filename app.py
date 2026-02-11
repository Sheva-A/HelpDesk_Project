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
login_manager.login_view = 'login' # Перенаправляє сюди, якщо доступ заборонено

@login_manager.user_loader
def load_user(user_id):
    # Отримання об'єкта користувача з БД за його ID
    return User.query.get(int(user_id))

# МОДЕЛІ БД

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False) # Використовуємо email як логін
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='student')
    room_number = db.Column(db.String(10), nullable=True) # Тільки для студентів
    # Зв'язок: дозволяє отримати всі заявки користувача через user.tickets
    tickets = db.relationship('Ticket', backref='author', lazy=True)

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Нова')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    admin_comment = db.Column(db.Text, nullable=True)
    # Зовнішній ключ для зв'язку з таблицею User
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# МАРШРУТИ

ALLOWED_DOMAIN = '@stud.duikt.edu.ua'

@app.route('/')
def index():
    # Головна сторінка 
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Якщо користувач вже увійшов, перенаправляємо за роллю
    if current_user.is_authenticated:
        return redirect(url_for('dashboard' if current_user.role == 'admin' else 'my_tickets'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        room_number = request.form.get('room_number')

        # Перевірка корпоративної пошти
        if not username or not username.endswith(ALLOWED_DOMAIN):
            flash(f'Реєстрація тільки для пошти {ALLOWED_DOMAIN}', 'danger')
            return redirect(url_for('register'))

        # Перевірка, чи пошта вже зайнята
        if User.query.filter_by(username=username).first():
            flash('Цей Email вже зареєстровано', 'danger')
            return redirect(url_for('register'))

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
    # Якщо користувач вже увійшов, перенаправляємо за роллю
    if current_user.is_authenticated:
        return redirect(url_for('dashboard' if current_user.role == 'admin' else 'my_tickets'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        # Перевірка пароля через хеш
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Ви успішно увійшли!', 'success')
            return redirect(url_for('dashboard') if user.role == 'admin' else url_for('my_tickets'))
        
        flash('Невірні дані для входу', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user() # Вихід
    flash('Ви вийшли з системи', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Контроль доступу
    if current_user.role != 'admin':
        flash('У вас немає прав для перегляду цієї сторінки', 'danger')
        return redirect(url_for('my_tickets'))
    return "Вітаємо, Коменданте! Тут список усіх заявок гуртожитку."

@app.route('/my_tickets')
@login_required
def my_tickets():
    return f"Ваші заявки, {current_user.username}. Кімната: {current_user.room_number}"

@app.route('/create_ticket', methods=['GET', 'POST'])
@login_required
def create_ticket():
    return "Тут буде форма для нової заявки"

if __name__ == '__main__':
    app.run(debug=True)