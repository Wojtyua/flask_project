from email.policy import default
from flask import Flask, render_template, url_for, redirect, flash, abort, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from wtforms.widgets import TextArea
from werkzeug.utils import secure_filename
import uuid as uuid
import os
import datetime

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'

#Setting folder for uploaded images
UPLOAD_FOLDER = 'static/images/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(30), nullable=False, unique=True)
    name = db.Column(db.String(20), nullable=False)
    last_name = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(80), nullable=False)
    login_count = db.Column(db.Integer, nullable=False, default=0)
    isAdmin = db.Column(db.Boolean(), nullable=False, default=False)

class Posts(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(20), nullable=False)
    author = db.Column(db.String(30), nullable=False)
    content = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(80), nullable=False)
    image = db.Column(db.String(), nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.datetime.utcnow())



class RegisterForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Length(min = 4, max=30)], render_kw={"placeholder": "Email"})
    name = StringField(validators=[InputRequired(), Length(min = 4, max=20)], render_kw={"placeholder": "Imie"})
    last_name = StringField(validators=[InputRequired(), Length(min = 4, max=20)], render_kw={"placeholder": "Nazwisko"})
    password = PasswordField(validators=[InputRequired(), Length(min = 4, max=20)], render_kw={"placeholder": "Hasło"})

    submit = SubmitField("Register")

class UserForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Length(min = 4, max=30)], render_kw={"placeholder": "Email"})
    name = StringField(validators=[InputRequired(), Length(min = 4, max=20)], render_kw={"placeholder": "Imie"})
    last_name = StringField(validators=[InputRequired(), Length(min = 4, max=20)], render_kw={"placeholder": "Nazwisko"})
    password = PasswordField(validators=[Length(min = 4, max=20)], render_kw={"placeholder": "Hasło"})

    submit = SubmitField("Update")

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(
            email = email.data).first()
        if existing_user_email:
            raise ValidationError("Email zajety")

class LoginForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Length(min = 4, max=30)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min = 4, max=20)], render_kw={"placeholder": "Hasło"})

    submit = SubmitField("Login")

class PostForm(FlaskForm):

    title = StringField(validators=[InputRequired(), Length(min = 4, max=20)], render_kw={"placeholder": "Title"})
    author = StringField(validators=[InputRequired(), Length(min = 4, max=20)], render_kw={"placeholder": "Author"})
    content = StringField(validators=[InputRequired()], widget=TextArea(), render_kw={"placeholder": "Content"})
    category = SelectField('category', choices=[('Sport', 'Sport'), ('Polityka', 'Polityka'), ('Zwierzęta', 'Zwierzęta'), ('News', 'News'), ('Memes', 'Polityka')], validators=[InputRequired()])

    image = FileField('post_image')

    submit = SubmitField("Add post")


@app.route('/home', methods=['GET', 'POST'])
def home():
    view = 'grid'
    if request.method == 'POST':
        if request.form['view'] == 'table':
            view = 'table'
        elif request.form['view'] == 'grid':
            view = 'grid'
    all_posts = db.session.query(Posts).order_by(Posts.date_posted.desc())
    return render_template('home.html', posts=all_posts, view = view)


@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                #incrementing login count in database
                user.login_count = User.login_count + 1
                db.session.commit()
                              
                login_user(user)
                flash(f"You have been logged in as {current_user.name}")
                return redirect(url_for('home'))

    return render_template('login.html', form=form)



@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash("You have been logged out")
    return redirect(url_for('home'))


@app.route('/add_post', methods=['GET', 'POST'])
@login_required
def add_post():
    form = PostForm()

    if form.validate_on_submit():
    
        image = form.image.data
        image_filename = secure_filename(image.filename)
        image_name = str(uuid.uuid1()) + "_" + image_filename 

        #saving img to UPLOAD_FOLDER

        saver = form.image.data
   
        #change to string to save to db
        image = image_name

        post = Posts(title = form.title.data, author = form.author.data, content = form.content.data, category = form.category.data, image = image)

        db.session.add(post)
        db.session.commit()
        saver.save(os.path.join(app.config['UPLOAD_FOLDER'], image_name))

        return redirect(url_for('home'))

        
    return render_template('add_post.html', form = form)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = current_user
    return render_template('profile.html', user=user)




@app.route('/post/delete/<int:id>', methods = ['GET','POST'])
@login_required
def deletePostById(id):
    post = Posts.query.filter_by(id=id).first() 
    if current_user.isAdmin != True:
        return redirect("/home")
    else: 
        db.session.delete(post)
        db.session.commit()
        return redirect('/home')
     

@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(name=form.name.data, email=form.email.data, last_name=form.last_name.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


#admin page only if logged as admin
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    view = 'table'
    if(current_user.isAdmin == True):
        all_users = User.query.all()
        if request.method == 'POST':
            if request.form['view'] == 'table':
                view = 'table'
            elif request.form['view'] == 'grid':
                view = 'grid'
        return render_template('admin.html', users = all_users, view = view)
    else:
        return redirect(url_for('home'))



#delete if admin or user owner
@app.route('/delete/<int:id>', methods = ['GET','POST'])
@login_required
def deleteById(id):
    user = User.query.filter_by(id=id).first()
    if(current_user.isAdmin == True):
        if user: 
            db.session.delete(user)
            db.session.commit()
            return redirect('/admin')
        else:
            return 'bad request!', 400
    elif (current_user.id == user.id):
        if user: 
            db.session.delete(user)
            db.session.commit()
            return redirect('/home')
        else:
            return 'bad request!', 400


#update profile if admin or user
@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def updateProfileById(id):
    user = User.query.filter_by(id=id).first() 
    form = UserForm()
    if user:
        if current_user.id == user.id:    
            if request.method == "POST":
                user.email = request.form['email']
                user.name = request.form['name']
                user.last_name = request.form['last_name']
                if(len(request.form['password']) != 0):
                    hashed_password = bcrypt.generate_password_hash(request.form['password'])
                    user.password = hashed_password  
                try:
                    db.session.commit()
                    return redirect('/profile')
                except:
                    return render_template("update.html", form=form, user = user)
            else:
                return render_template("update.html", form=form, user = user)
        elif current_user.isAdmin == True:
            if request.method == "POST":
                user.email = request.form['email']
                user.name = request.form['name']
                user.last_name = request.form['last_name']
                if(len(request.form['password']) != 0):
                    hashed_password = bcrypt.generate_password_hash(request.form['password'])
                    user.password = hashed_password  
                try:
                    db.session.commit()
                    return redirect('/admin')
                except:
                    return render_template("update.html", form=form, user = user)
            else:
                return render_template("update.html", form=form, user = user)
        else:
            return 'bad request!', 400
    return redirect('/home')


#top users page
@app.route('/top_users', methods=['GET', 'POST'])
def topUsers():
    #return all users by login count 
    top_users = db.session.query(User).order_by(User.login_count.desc()).limit(3)
    return render_template('top_users.html', users = top_users)


if __name__ == "__main__":
    app.run(debug=True)