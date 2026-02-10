from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask import render_template, request, redirect, url_for, flash

# Налаштування додатку
app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Куди кидати, якщо юзер не увійшов

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Вказуємо, де буде лежати файл бази даних (у папці instance) 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///helpdesk.db'
app.config['SECRET_KEY'] = 'helpdesk-secret-key' # Потрібен для сесій/безпеки

# Ініціалізація БД
db = SQLAlchemy(app)

# МОДЕЛІ (Таблиці БД)

# Модель користувача (Студент або Комендант)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False) # Логін
    password = db.Column(db.String(200), nullable=False) # Пароль
    role = db.Column(db.String(20), nullable=False, default='student') # Роль: 'student' або 'admin' 
    room_number = db.Column(db.String(10), nullable=True) # Номер кімнати (для студентів) 
    
    # Зв'язок: один юзер може мати багато заявок
    tickets = db.relationship('Ticket', backref='author', lazy=True)

# Модель заявки
class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False) # Тема (Сантехніка і т.д.) 
    description = db.Column(db.Text, nullable=False)  # Опис проблеми
    status = db.Column(db.String(20), default='Нова') # Статус: Нова, Виконано 
    created_at = db.Column(db.DateTime, default=datetime.utcnow) # Дата створення
    admin_comment = db.Column(db.Text, nullable=True) # Коментар адміністратора
    
    # Зв'язок: хто створив заявку (Foreign Key)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# МАРШРУТИ (Контролери)
# Backend Logic Dev пише код тут 

ALLOWED_DOMAIN = '@stud.duikt.edu.ua'  

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Якщо користувач вже авторизований - не пускаємо на реєстрацію
    if current_user.is_authenticated:
        return redirect(url_for('dashboard')) # Або інший редірект

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        room_number = request.form.get('room_number')

        
        # 1. Перевірка домену 
        if not username or not username.endswith(ALLOWED_DOMAIN):
            flash(f'Реєстрація дозволена лише для пошти домену {ALLOWED_DOMAIN}', 'danger')
            return redirect(url_for('register'))

        # 2. Перевірка на унікальність 
        if User.query.filter_by(username=username).first():
            flash('Користувач з таким email вже існує', 'danger')
            return redirect(url_for('register'))


        try:
            # Хешування паролю 
            hashed_password = generate_password_hash(password)

            # Створення користувача 
            new_user = User(
                username=username,
                password=hashed_password,
                role='student',
                room_number=room_number
            )

            db.session.add(new_user)
            db.session.commit()

            flash('Реєстрація успішна! Увійдіть у систему.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            # У реальному проді помилку краще писати в лог, а юзеру показувати загальну
            flash(f'Помилка при збереженні: {str(e)}', 'danger')

    return render_template('register.html')
@app.route('/index')
def index():
    # Це головна сторінка (або редірект на логін)
    return "Вітаю в HelpDesk! (Тут буде сторінка входу)"

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Тут логіка входу
    return "Сторінка входу"

@app.route('/dashboard')
def dashboard():
    # Дашборд для коменданта
    return "Дашборд"

@app.route('/my_tickets')
def my_tickets():
    # Дашборд для одного конкретного студента
    return "Тут буде список заявок студента"

@app.route('/create_ticket', methods=['GET', 'POST'])
def create_ticket():
    # Створення заявки
    return "Форма заявки"

# ЗАПУСК
if __name__ == '__main__':
    app.run(debug=True) 