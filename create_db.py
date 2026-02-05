from app import app, db

# Цей код створить файл бази даних
with app.app_context():
    db.create_all()
    print("База даних створена.")