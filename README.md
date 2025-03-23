# Система управления оценками

Веб-приложение для управления оценками студентов по различным дисциплинам. Разработано с использованием Flask и SQLAlchemy.

## Функциональность

- Система аутентификации с поддержкой ролей (администратор, преподаватель, студент)
- Управление пользователями (добавление, редактирование, удаление)
- Управление дисциплинами (добавление, редактирование, удаление)
- Просмотр оценок по дисциплинам
- Административный интерфейс для управления системой

## Установка

1. Клонируйте репозиторий:
```bash
git clone https://github.com/DxrkFuture/grade-management-system.git
cd grade-management-system
```

2. Создайте виртуальное окружение с использованием python3.11:
```bash
python -m venv venv
source venv/bin/activate  # для Linux/Mac
# или
venv\Scripts\activate  # для Windows
```

3. Установите зависимости:
```bash
pip install -r requirements.txt
```

4. Запустите приложение:
```bash
python app.py
```

## Доступ к системе

### Администратор
- URL: http://localhost:5000
- Логин: admin
- Пароль: admin

### Студенты и преподаватели
- Создаются администратором через веб-интерфейс
- Доступ: http://localhost:5000/login

## Структура базы данных

### Таблица users
- id (Primary Key)
- username (Уникальное имя пользователя)
- group (Роль пользователя: admin/teacher/student)
- password_hash (Хеш пароля)

### Таблица subjects
- id (Primary Key)
- title (Название дисциплины)
- description (Описание дисциплины)

### Таблица grades
- id (Primary Key)
- value (Оценка)
- user_id (Foreign Key -> users.id)
- subject_id (Foreign Key -> subjects.id)

## Зависимости

- Flask==3.1.0
- Flask-SQLAlchemy==3.1.1
- Flask-Login==0.6.3
- Werkzeug==3.1.3
- python-dotenv==1.0.1
- SQLAlchemy==2.0.39

## Лицензия

MIT License

Copyright (c) 2025 до н.э.