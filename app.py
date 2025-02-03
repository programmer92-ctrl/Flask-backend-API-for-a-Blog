from flask import Flask, jsonify, request, make_response
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re
import os
import werkzeug
from werkzeug.utils import secure_filename
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from models import db, Users, Posts, Comments, Contacts, Subscribers, Admin_Users, Visitors
from flask_migrate import Migrate, migrate
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from flask_wtf import CSRFProtect
import bleach
from markupsafe import escape
from flask_talisman import Talisman
from flask_wtf import FlaskForm
from wtforms import Form, StringField, IntegerField, PasswordField, EmailField, TextAreaField, SubmitField, FileField, validators
from wtforms.validators import InputRequired, DataRequired
from wtforms_json import patch_data
import wtforms_json
from flask_bcrypt import Bcrypt

app = Flask(__name__)

CORS(app)
app.secret_key = 'your secret key'

app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost:3306/blogdb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JWT_SECRET_KEY"] = 'your_jwt_secret_key'
app.config['JWT_TOKEN_LOCATION'] = ['headers']

jwt = JWTManager(app)
bcrypt = Bcrypt(app)

with app.app_context():
    db.init_app(app)

migrate = Migrate(app, db)
wtforms_json.init()

class PostForm(Form):
    title = StringField('Title', [validators.DataRequired()])
    post = StringField('Post', [validators.DataRequired()])
    published = StringField('Published',[validators.DataRequired()])
    author = StringField('Author', [validators.DataRequired()])

class UserForm(Form):
    username = StringField('Username', [validators.DataRequired()])
    password = PasswordField('Password', [validators.DataRequired()])
    email = EmailField('Email', [validators.DataRequired()])

class ContactForm(Form):
    firstname = StringField('Firstname', [validators.DataRequired()])
    lastname = StringField('Lastname', [validators.DataRequired()])
    message = StringField('Message', [validators.DataRequired()])

class SubscribeForm(Form):
    email = EmailField('Email', [validators.DataRequired()])

class VisitorsForm(Form):
    visit = IntegerField('Visit', [validators.DataRequired()])

class CommentsForm(Form):
    comment = StringField('Comment', [validators.DataRequired()])
    blogid = IntegerField('Blogid', [validators.DataRequired()])

class AdminUsersForm(Form):
    username = StringField('Username', [validators.DataRequired()])
    password = PasswordField('Password', [validators.DataRequired()])

@app.route('/createadminuser', methods=['POST'])
def createadminuser():
    json = request.get_json()
    form = AdminUsersForm.from_json(json)
    if form.validate():
        try:
            adminuser = Admin_User(username=form.username.data, password=form.password.data)
            db.session.add(adminuser)
            db.session.commit()
            return jsonify({'message': 'Admin user created successfully'})
        except Exception as e:
            return jsonify({'message': 'Database error'})
    else:
        return jsonify({'message': 'Fields empty'})

@app.route('/showadminusers', methods=['GET'])
def showadminusers():
    admin_users = Admin_Users.query.all()
    return jsonify([admin_user.to_dict() for admin_user in admin_users])


@app.route('/adminuser/<int:id>', methods=['GET'])
def adminuser(id):
    admin_user = Admin_Users.query.get(id)
    return jsonify(admin_user.to_dict())

@app.route('/deleteadminuser/<int:id>', methods=['DELETE'])
def deleteadminuser(id):
    admin_user = Admin_Users.query.filter_by(id=id).first()
    db.session.delete(admin_user)
    db.session.commit()
    return jsonify({'message': 'Admin user deleted successfully'})

@app.route('/comment', methods=['POST'])
def comment():
    json = request.get_json()
    form = CommentsForm.from_json(json)
    if form.validate():
        try:
            comment = Comments(comment=form.comment.data, blogid=form.blogid.data)
            db.session.add(comment)
            db.session.commit()
            return jsonify({'message': 'Comment added successfully'})
        except Exception as e:
            return jsonify({'message': 'Database error'})
    else:
        return jsonify({'message': 'Fields empty'})

@app.route('/editcomment/<int:id>/comment', methods=['UPDATE'])
def editcomment(id, comment):
    updated_comment = Comments.query.get(id)
    updated_comment.comment = comment
    db.session.commit()
    return jsonify({'message': 'Comment edited successfully'})

@app.route('/deletecomment/<int:id>', methods=['DELETE'])
def deletecomment(id):
    comment = Comment.query.get(id)
    db.session.delete(comment)
    db.session.commit()
    return jsonify({'message': 'Comment deleted successfully'})

@app.route('/getcomment/<int:id>', methods=['GET'])
def getcomment(id):
    comment = Comments.query.filter_by(blogid=id)
    return jsonify({'comment', comment})

@app.route('/visit', methods=['POST'])
def visit():
    json = request.get_json()
    form = VisitorsForm.from_json(json)
    if form.validate():
        try:
            visit = Visitors(visit=form.visit.data)
            db.session.add(visit)
            db.session.commit()
            return jsonify({'message': 'Hit'})
        except Exception as e:
            return jsonify({'message': 'Database error'})
    else:
        return jsonify({'message': 'Empty fields'})

@app.route('/getvisitors', methods=['GET'])
def getvisitors():
    visitors = Visitors.query.all()
    return jsonify([visitor.to_dict() for vistor in visitors]) 

@app.route('/contact', methods=['POST'])
def contact():
    json = request.get_json()
    form = ContactForm.from_json(json)
    if form.validate():
        try:
            message = Contacts(firstname=form.firstname.data, lastname=form.lastname.data, message=form.message.data)
            db.session.add(message)
            db.session.commit()
            return jsonify({'message': 'Message sent successfully!'})
        except Exception as e:
            return jsonify({'message': 'Database error'})
    else:
        return jsonify({'message': 'Fields empty'})

@app.route('/getcontacts', methods=['GET'])
def getcontacts():
    contacts = Contacts.query.all()
    return jsonify([contact.to_dict() for contact in contacts])

@app.route('/deletecontact/<int:id>', methods=['DELETE'])
def deletecontact(id):
    contact = Contacts.query.get(id)
    db.session.delete(contact)
    db.session.commit()
    return jsonify({'message': 'Contact deleted'})

@app.route('/subscribe', methods=['POST'])
def subscribe():
    json = request.get_json()
    form = SubscribeForm.from_json(json)
    if form.validate():
        try:
            subscriber = Subscribers(email=form.email.data)
            db.session.add(subscriber)
            db.session.commit()
            return jsonify({'message': 'Subscribed successfully!'})
        except Exception as e:
            return jsonify({'message': 'Database error'})
    else:
        return jsonify({'message': 'Fields empty'})

@app.route('/deleteuser/<int:id>', methods=['POST'])
def deleteuser(id):
    user = Users.query.get(id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'Deleted user'})

@app.route('/getuser/<int:id>', methods=['GET'])
def getuser(id):
    user = Users.query.get(id)
    return jsonify(user.to_dict())

@app.route('/register', methods=['POST'])
def register():
    user = Users.query.filter_by(username=request.get_json()['username']).first()
    if user:
        return jsonify({'message', 'User exists'})
    else:
        json = request.get_json()
        form = UserForm.from_json(json)
        if form.validate():
            try:
                hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
                user = Users(username=form.username.data, password=hashed_password, email=form.email.data)
                db.session.add(user)
                db.session.commit()
                return jsonify({'message': 'User registered'})
            except Exception as e:
                return jsonify({'error': 'Database error'}), 500
        else:
            return jsonify({'message': 'Form fields missing'})

@app.route('/posts', methods=['GET'])
def posts():
    posts = Posts.query.all()
    return jsonify([post.to_dict() for post in posts])

@app.route('/postit', methods=['POST'])
def postit():
    title = request.form.get('title')
    post = request.form.get('post')
    published = request.form.get('published')
    author = request.form.get('author')
    if 'photo' not in request.files:
        return jsonify({'message': 'No file'})
    file = request.files['photo']
    if file.filename == '':
        return jsonify({'message': 'No filename'})
    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    try:
        post = Posts(title=title, post=post, photo=file.filename, published=published, author=author)
        db.session.add(post)
        db.session.commit()
        return jsonify({'message': 'Successfully posted'})
    except Exception as e:
        return jsonify({'message': 'Database error'})

@app.route('/post', methods=['POST'])
def post():
    form = PostForm(request.form)
    if form.validate():
        if 'photo' not in request.files:
            return jsonify({'message': 'No file'})
        file = request.files['photo']
        if file.filename == '':
            return jsonify({'message': 'No filename'})
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        try:
            post = Posts(title=form.title.data, post=form.post.data, photo=file.filename, published=form.published.data, author=form.author.data)
            db.session.add(post)
            db.session.commit()
            return jsonify({'message': 'Post created successfully'})
        except Exception as e:
            return jsonify({'message': 'Database error', 'error': e}), 500

@app.route('/login', methods=['POST'])
def login():
    json = request.get_json()
    username = json['username']
    password = json['password']
    if username != '' and password != '':
        user = Users.query.filter_by(username=username).first()
        pw = Users.query.filter_by(password=password).first()
        if user and bcrypt.check_password_hash(pw, pw):
            access_token = create_access_token(identity=user.id)
            refresh_token = create_refresh_token(identity=user.id)
            return jsonify({'message': 'Login Success', 'access_token': access_token, 'refresh_token': refresh_token})
        else:
            return jsonify({'message': 'Wrong username or password'})

@app.route('/refreshtoken', methods=['GET'])
@jwt_required(refresh=True)
def refreshtoken():
    current_user = get_jwt_identity()
    new_token = create_access_token(identity=current_user)
    return jsonify({'message': 'Token refreshed', 'new_access_token': new_token})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int("80"))
