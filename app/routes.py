from flask import render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, current_user, login_required
from app.models import User
from app import app, db, bcrypt
from app.forms import RegistrationForm, LoginForm, AccountForm

@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Вы успешно зарегистрировались!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form, title='Register')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('home'))
        else:
            flash('Введены неверные данные')
    return render_template('login.html', form=form, title='Login')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    form = AccountForm(obj=current_user)  # Инициализация формы текущими данными пользователя
    if form.validate_on_submit():
        changes_made = False

        # Обновление пароля
        if form.password.data:
            if form.password.data == form.confirm_password.data:
                current_user.password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
                changes_made = True
            else:
                flash('Пароли не совпадают!', 'danger')
                return redirect(url_for('account'))

        # Обновление email
        if form.email.data and form.email.data != current_user.email:
            if User.query.filter_by(email=form.email.data).first():
                flash('Этот email уже занят.', 'danger')
                return redirect(url_for('account'))
            current_user.email = form.email.data
            changes_made = True

        # Обновление username
        if form.username.data and form.username.data != current_user.username:
            if User.query.filter_by(username=form.username.data).first():
                flash('Это имя уже занято.', 'danger')
                return redirect(url_for('account'))
            current_user.username = form.username.data
            changes_made = True

        if changes_made:
            db.session.commit()
            flash('Ваши данные изменены!', 'success')
        else:
            flash('Изменений не было.', 'info')

        return redirect(url_for('account'))

    if form.errors:
        print("Ошибки формы:", form.errors)

    return render_template('account.html', form=form, title='Account')
