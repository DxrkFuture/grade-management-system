from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    group = db.Column(db.String(20), nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    grades = db.relationship('Grade', backref='user', lazy=True)

class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    grades = db.relationship('Grade', backref='subject', lazy=True)

class Grade(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    subjects = Subject.query.all()
    return render_template('index.html', subjects=subjects)

@app.route('/subject/<int:subject_id>')
@login_required
def subject(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    if current_user.group == 'admin':
        grades = Grade.query.filter_by(subject_id=subject_id).all()
        users = User.query.filter(User.group != 'admin').all()
    else:
        grades = Grade.query.filter_by(subject_id=subject_id, user_id=current_user.id).all()
        users = []
    return render_template('subject.html', subject=subject, grades=grades, users=users)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Неверное имя пользователя или пароль')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/add_grade/<int:subject_id>', methods=['POST'])
@login_required
def add_grade(subject_id):
    if current_user.group != 'admin':
        flash('У вас нет прав для выполнения этого действия')
        return redirect(url_for('subject', subject_id=subject_id))
    
    user_id = request.form.get('user_id')
    value = float(request.form.get('value'))
    
    grade = Grade(value=value, user_id=user_id, subject_id=subject_id)
    db.session.add(grade)
    db.session.commit()
    
    flash('Оценка успешно добавлена')
    return redirect(url_for('subject', subject_id=subject_id))

@app.route('/add_subject', methods=['GET', 'POST'])
@login_required
def add_subject():
    if current_user.group != 'admin':
        flash('У вас нет прав для выполнения этого действия')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        
        subject = Subject(title=title, description=description)
        db.session.add(subject)
        db.session.commit()
        
        flash('Предмет успешно добавлен')
        return redirect(url_for('index'))
    
    return render_template('add_subject.html')

@app.route('/edit_subject/<int:subject_id>', methods=['GET', 'POST'])
@login_required
def edit_subject(subject_id):
    if current_user.group != 'admin':
        flash('У вас нет прав для выполнения этого действия')
        return redirect(url_for('index'))
    
    subject = Subject.query.get_or_404(subject_id)
    
    if request.method == 'POST':
        subject.title = request.form.get('title')
        subject.description = request.form.get('description')
        db.session.commit()
        
        flash('Предмет успешно обновлен')
        return redirect(url_for('index'))
    
    return render_template('edit_subject.html', subject=subject)

@app.route('/delete_subject/<int:subject_id>')
@login_required
def delete_subject(subject_id):
    if current_user.group != 'admin':
        flash('У вас нет прав для выполнения этого действия')
        return redirect(url_for('index'))
    
    subject = Subject.query.get_or_404(subject_id)
    db.session.delete(subject)
    db.session.commit()
    
    flash('Предмет успешно удален')
    return redirect(url_for('index'))

@app.route('/users')
@login_required
def users():
    if current_user.group != 'admin':
        flash('У вас нет прав для выполнения этого действия')
        return redirect(url_for('index'))
    users = User.query.filter(User.group != 'admin').all()
    return render_template('users.html', users=users)

@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if current_user.group != 'admin':
        flash('У вас нет прав для выполнения этого действия')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        group = request.form.get('group')
        
        if User.query.filter_by(username=username).first():
            flash('Пользователь с таким именем уже существует')
            return redirect(url_for('add_user'))
        
        user = User(
            username=username,
            group=group,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        
        flash('Пользователь успешно добавлен')
        return redirect(url_for('users'))
    
    return render_template('add_user.html')

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.group != 'admin':
        flash('У вас нет прав для выполнения этого действия')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(user_id)
    if user.group == 'admin':
        flash('Нельзя редактировать администратора')
        return redirect(url_for('users'))
    
    if request.method == 'POST':
        user.username = request.form.get('username')
        if request.form.get('password'):
            user.password_hash = generate_password_hash(request.form.get('password'))
        user.group = request.form.get('group')
        db.session.commit()
        
        flash('Пользователь успешно обновлен')
        return redirect(url_for('users'))
    
    return render_template('edit_user.html', user=user)

@app.route('/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    if current_user.group != 'admin':
        flash('У вас нет прав для выполнения этого действия')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(user_id)
    if user.group == 'admin':
        flash('Нельзя удалить администратора')
        return redirect(url_for('users'))
    
    db.session.delete(user)
    db.session.commit()
    
    flash('Пользователь успешно удален')
    return redirect(url_for('users'))

def init_db():
    with app.app_context():
        db.create_all()
        # Создаем админа, если его еще нет
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                group='admin',
                password_hash=generate_password_hash('admin')
            )
            db.session.add(admin) # добавляем админа в базу данных(так не нужно делать но мы так делаем)
            db.session.commit()

if __name__ == '__main__':
    init_db()
    app.run(debug=True) 