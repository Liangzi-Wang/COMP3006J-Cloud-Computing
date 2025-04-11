import os

from flask import render_template, flash, redirect, url_for, session, request
from werkzeug.security import generate_password_hash, check_password_hash

from app import app, db
from app.config import Config
from app.models import User

with app.app_context():
    db.create_all()

@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if 'login_submit' in request.form:
            username = request.form.get('username')
            password = request.form.get('password')
            print("[DEBUG] Login form submitted:")
            print("[DEBUG] Username: {}".format(username))
            print("[DEBUG] Password: {}".format(password))

            user_in_db = User.query.filter(User.username == username).first()
            print(f"[DEBUG] User found: {user_in_db}")

            if not user_in_db:
                print("[DEBUG] No user found with this username")
                flash('No user found with username: {}'.format(username))
                return redirect(url_for('login'))

            if check_password_hash(user_in_db.password_hash, password):
                print("[DEBUG] Password correct")
                session["USERNAME"] = user_in_db.username
                return redirect(url_for('home'))
            else:
                print("[DEBUG] Password incorrect")
                flash('Incorrect Password')
                return redirect(url_for('login'))


        elif 'signup_submit' in request.form:
            print("[DEBUG] Signup form submitted:")
            regis_username = request.form.get('regis_username')
            regis_password = request.form.get('regis_password')
            print("[DEBUG] Username: {}".format(regis_username))
            print("[DEBUG] Password: {}".format(regis_password))

            # Check if username already exists
            existing_user = User.query.filter(User.username == regis_username).first()
            if existing_user:
                print("[DEBUG] Username already exists")
                flash('Username already exists')
                return redirect(url_for('login'))

            # Create password hash
            passw_hash = generate_password_hash(regis_password)

            print(f"[DEBUG] Password hash: {passw_hash}")

            # Create new user
            user = User(username=regis_username, password_hash=passw_hash)
            print(f"[DEBUG] User created: {user}")

            # Add to database
            db.session.add(user)
            db.session.commit()
            print("[DEBUG] User saved to database")

            flash('User registered with username: {}'.format(regis_username))
            return redirect(url_for('login'))

    return render_template('login.html', title='Sign In')


@app.route('/home', methods=['GET', 'POST'])
def home():
    if not session.get("USERNAME") is None:
        if request.method == 'POST':
            if 'logout' in request.form:
                print("logout")
                session.pop("USERNAME", None)
                return redirect(url_for('login'))
        return render_template('homePage.html')

    else:
        flash("User needs to either login or signup first")
        return redirect(url_for('login'))



# @app.route('/home', methods=['GET', 'POST'])
# def logout():
#     if 'logout' in request.form:
#         session.pop("USERNAME", None)
#         return redirect(url_for('login'))
