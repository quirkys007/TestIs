from flask import Flask
from flask_restx import Resource, Api, reqparse
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import jwt

app = Flask(__name__)  # Instantiation of Flask object.
api = Api(app)  # Instantiation of Flask-RESTX object.

############################
##### BEGIN: Database #####
##########################
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://root:@127.0.0.1:3306/webservice"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True

db = SQLAlchemy(app)  # Instantiation of Flask-SQLAlchemy object.


class User(db.Model):
    id = db.Column(db.Integer(), primary_key=True, nullable=False)
    email = db.Column(db.String(32), unique=True, nullable=False)
    name = db.Column(db.String(64), nullable=False)
    password = db.Column(db.String(256), nullable=False)


@app.route("/api/create_user", methods=["GET"])
def user_db():
    with app.app_context():
        db.create_all()


##########################
##### END: Database #####
########################

###########################
##### BEGIN: Sign Up #####
#########################
parser4Reg = reqparse.RequestParser()
parser4Reg.add_argument('email', type=str, help='Email', location='json', required=True)
parser4Reg.add_argument('name', type=str, help='Name', location='json', required=True)
parser4Reg.add_argument('password', type=str, help='Password', location='json', required=True)
parser4Reg.add_argument('re_password', type=str, help='Retype Password', location='json', required=True)


@api.route('/signup')
class Registration(Resource):
    @api.expect(parser4Reg)
    def post(self):
        # BEGIN: Get request parameters.
        args = parser4Reg.parse_args()
        email = args['email']
        name = args['name']
        password = args['password']
        rePassword = args['re_password']
        # END: Get request parameters.

        # BEGIN: Check re_password.
        if password != rePassword:
            return {
                       'messege': 'Password must be the same!'
                   }, 400
        # END: Check re_password.

        # BEGIN: Check email existance.
        user = db.session.execute(db.select(User).filter_by(email=email)).first()
        if user:
            return "This email address has been used!"
        # END: Check email existance.

        # BEGIN: Insert new user.
        user = User()  # Instantiate User object.
        user.email = email
        user.name = name
        user.password = generate_password_hash(password)

        db.session.add(user)
        db.session.commit()
        # END: Insert new user.

        return {'messege': 'Successful!'}, 201


#########################
##### END: Sign Up #####
#######################

###########################
##### BEGIN: Sign In #####
#########################
SECRET_KEY = "WhatEverYouWant"
ISSUER = "myFlaskWebservice"
AUDIENCE_MOBILE = "myMobileApp"

parser4LogIn = reqparse.RequestParser()
parser4LogIn.add_argument('email', type=str, help='Email', location='json', required=True)
parser4LogIn.add_argument('password', type=str, help='Password', location='json', required=True)


@api.route('/signin')
class LogIn(Resource):
    @api.expect(parser4LogIn)
    def post(self):
        # BEGIN: Get request parameters.
        args = parser4LogIn.parse_args()
        email = args['email']
        password = args['password']
        # END: Get request parameters.

        if not email or not password:
            return {
                       'message': 'Please fill your email and password!'
                   }, 400

        # BEGIN: Check email existance.
        user = db.session.execute(
            db.select(User).filter_by(email=email)).first()

        if not user:
            return {
                       'message': 'The email or password is wrong!'
                   }, 400
        else:
            user = user[0]  # Unpack the array.
        # END: Check email existance.

        # BEGIN: Check password hash.
        if check_password_hash(user.password, password):
            payload = {
                'user_id': user.id,
                'email': user.email,
                'aud': AUDIENCE_MOBILE,  # AUDIENCE_WEB
                'iss': ISSUER,
                'iat': datetime.utcnow(),
                'exp': datetime.utcnow() + timedelta(hours=2)
            }
            token = jwt.encode(payload, SECRET_KEY)
            return {
                       'token': token
                   }, 200
        else:
            return {
                       'message': 'Wrong email or password!'
                   }, 400
        # END: Check password hash.


#########################
##### END: Sign In #####
#######################

# Token Aut
SECRET_KEY = "WhatEverYouWant"
ISSUER = "myFlaskWebService"
AUDIENCE_MOBILE = "myMobileApp"

parser4token = reqparse.RequestParser()
parser4token.add_argument('token', type=str,
                          location='headers', required=True)


@api.route('/Token')
class token(Resource):
    @api.expect(parser4token)
    def post(self):
        args = parser4token.parse_args()
        token = args['token']
        payload = jwt.decode(
            token,
            SECRET_KEY,
            audience=AUDIENCE_MOBILE,
            issuer=ISSUER,
            algorithms=['HS256'],
            options={"require": ["aud", "iss", "iat", "exp"]}
        )
        if payload:
            return {
                "token": "token_value", "message": "Token Success! Cek Email Token!"
            }
        else:
            return {
                "message": "Token Gagal!"

            }


####################################

parser4pass = reqparse.RequestParser()
parser4pass.add_argument('email', type=str,
                         location='headers', required=True)
parser4pass.add_argument('password', type=str,
                         location='headers', required=True)


@api.route('/password')
class password(Resource):
    @api.expect(parser4pass)
    def post(self):
        args = parser4pass.parse_args()

        email = args["email"]
        password = args["password"]

        # get db
        user = db.session.execute(
            db.select(User).filter_by(email=email)).first()

        if not user:
            return f"Email {email} tidak Ada!", 400
        else:
            user = user[0]

        if email:
            user.email = email
            user.password = generate_password_hash(password)

            db.session.add(user)
            db.session.commit()

            return "Update Password Success!"


##################################
################################

if __name__ == '__main__':
    app.run(debug=True)