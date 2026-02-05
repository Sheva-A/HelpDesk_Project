from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

# Налаштування додатку
app = Flask(__name__)
# Вказуємо, де буде лежати файл бази даних (у папці instance) [cite: 17]
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///helpdesk.db'
app.config['SECRET_KEY'] = 'secret_key_for_university_project' # Потрібен для сесій/безпеки

# Ініціалізація БД
db = SQLAlchemy(app)

# --- МОДЕЛІ (Таблиці БД) ---

# Модель користувача (Студент або Комендант)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False) # Логін
    password = db.Column(db.String(200), nullable=False) # Пароль
    role = db.Column(db.String(20), nullable=False, default='student') # Роль: 'student' або 'admin' [cite: 2, 8]
    room_number = db.Column(db.String(10), nullable=True) # Номер кімнати (для студентів) [cite: 6]
    
    # Зв'язок: один юзер може мати багато заявок
    tickets = db.relationship('Ticket', backref='author', lazy=True)

# Модель заявки
class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False) # Тема (Сантехніка і т.д.) [cite: 5]
    description = db.Column(db.Text, nullable=False)  # Опис проблеми [cite: 6]
    status = db.Column(db.String(20), default='Нова') # Статус: Нова, Виконано [cite: 7]
    created_at = db.Column(db.DateTime, default=datetime.utcnow) # Дата створення
    
    # Зв'язок: хто створив заявку (Foreign Key)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# --- ЗАПУСК ---
if __name__ == '__main__':
    app.run(debug=True)