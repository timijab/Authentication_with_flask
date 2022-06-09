import flask
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from sqlalchemy import exc

app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)
app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# you pass flask_login userMixin to the database creation class
##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


# Line below only required once, when creating DB.
# db.create_all()
is_logged_in = False

@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'GET':
        return render_template("register.html")
    else:
        username = request.form.get('name')
        user_email = request.form.get('email')
        user_password = request.form.get('password')
        # we use the generate_password_hash() to authenticate and further protect our passwords in our database from, hackerrs
        try:
            new_registration = User(
                email=user_email,
                password=generate_password_hash(password=user_password, method='pbkdf2:sha256', salt_length=8),
                name=username,
            )
            db.session.add(new_registration)
            db.session.commit()
            return render_template('secrets.html', name=username)
        except exc.IntegrityError:
            flash('user already exists')
            return redirect(url_for('login'))



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        # database = User.query.all()
        user = User.query.filter_by(email=email).first()
        if user.email == email:
            checker = check_password_hash(pwhash=user.password, password=password)
            print(checker)
            if checker is True:
                login_user(user)
                flash('Logged in successfully')
                return render_template('secrets.html', name=user.name, is_logged_in=True)
            else:
                flash(message='Sorry! user doesnt exist click on register to become a new user')
                return redirect(url_for('login'))
        elif user.email != email:
            flash(message='Sorry user doesnt exit')
            return redirect(url_for('register'))

    elif request.method == 'GET':
        return render_template("login.html")


@app.route('/secrets')
def secrets():
    return render_template("secrets.html")


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# send from a directory needs a flask component called flask.send_from_directory()
@app.route('/download')
def download():
    return send_from_directory(directory='/Users/Isaac Afolayan/Desktop/Flask Authentication /static/files',
                               filename='cheat_sheet.pdf')


if __name__ == "__main__":
    app.run(debug=True)
