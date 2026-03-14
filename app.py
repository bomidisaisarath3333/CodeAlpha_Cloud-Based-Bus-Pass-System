from flask import Flask, request, jsonify, send_from_directory
import os

from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import jwt
import datetime
import uuid

basedir = os.path.abspath(os.path.dirname(__file__))
static_dir = os.path.join(basedir, '..', 'frontend')
app = Flask(__name__, static_folder=static_dir, static_url_path='')

# Enable CORS
CORS(app)

# Configuration
app.config['SECRET_KEY'] = 'super-secret-bus-pass-key-2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///buspass.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ---------------- MODELS ---------------- #

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

class BusPass(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pass_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    pass_type = db.Column(db.String(20), nullable=False)
    price = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='Active')
    valid_until = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# Create database
with app.app_context():
    db.create_all()

# ---------------- HOME ROUTE ---------------- #

@app.route('/')
def home():
    print("Home route hit, serving index.html from:", app.static_folder)
    return send_from_directory(app.static_folder, 'index.html')

# ---------------- TOKEN AUTH ---------------- #

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        token = None

        if 'Authorization' in request.headers:
            token = request.headers['Authorization']

        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            token = token.split(" ")[1]

            data = jwt.decode(
                token,
                app.config['SECRET_KEY'],
                algorithms=["HS256"]
            )

            current_user = User.query.get(data['user_id'])

        except Exception as e:
            return jsonify({'message': 'Token invalid'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

# ---------------- PASS PRICING ---------------- #

PRICING = {
    "Daily": 50.0,
    "Weekly": 300.0,
    "Monthly": 1000.0
}

# ---------------- REGISTER ---------------- #

@app.route('/api/register', methods=['POST'])
def register():

    data = request.get_json()

    if not data:
        return jsonify({"message": "No input data"}), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify({"message": "User already exists"}), 400

    hashed_password = generate_password_hash(data['password'])

    user = User(
        username=data['username'],
        email=data['email'],
        password_hash=hashed_password
    )

    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"})


# ---------------- LOGIN ---------------- #

@app.route('/api/login', methods=['POST'])
def login():

    data = request.get_json()

    user = User.query.filter_by(username=data['username']).first()

    if not user:
        return jsonify({"message": "User not found"}), 404

    if not check_password_hash(user.password_hash, data['password']):
        return jsonify({"message": "Wrong password"}), 401

    token = jwt.encode(
        {
            "user_id": user.id,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        },
        app.config['SECRET_KEY'],
        algorithm="HS256"
    )

    return jsonify({
        "token": token,
        "username": user.username
    })


# ---------------- BOOK PASS ---------------- #

@app.route('/api/book_pass', methods=['POST'])
@token_required
def book_pass(current_user):

    data = request.get_json()

    pass_type = data.get("pass_type")

    if pass_type not in PRICING:
        return jsonify({"message": "Invalid pass type"}), 400

    now = datetime.datetime.utcnow()

    if pass_type == "Daily":
        valid_until = now + datetime.timedelta(days=1)

    elif pass_type == "Weekly":
        valid_until = now + datetime.timedelta(days=7)

    else:
        valid_until = now + datetime.timedelta(days=30)

    new_pass = BusPass(
        user_id=current_user.id,
        pass_type=pass_type,
        price=PRICING[pass_type],
        valid_until=valid_until
    )

    db.session.add(new_pass)
    db.session.commit()

    return jsonify({
        "message": "Pass booked successfully",
        "pass_id": new_pass.pass_id,
        "valid_until": new_pass.valid_until
    })


# ---------------- MY PASSES ---------------- #

@app.route('/api/my_passes', methods=['GET'])
@token_required
def my_passes(current_user):

    passes = BusPass.query.filter_by(user_id=current_user.id).all()

    output = []

    for p in passes:
        output.append({
            "pass_id": p.pass_id,
            "pass_type": p.pass_type,
            "price": p.price,
            "status": p.status,
            "valid_until": p.valid_until,
            "created_at": p.created_at
        })

    return jsonify({"passes": output})


# ---------------- RUN SERVER ---------------- #

if __name__ == "__main__":
    app.run(debug=True)