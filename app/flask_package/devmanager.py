from flask_package import db, login_manager
from flask_login import UserMixin

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class CA(db.Model):
    ca_id = db.Column( db.Integer, primary_key=True)
    caname = db.Column (db.String(100))
    remotemac = db.Column (db.String(80))
    pr = db.Column (db.String(80))
    kyc = db.Column (db.String(80))
    fp = db.Column (db.String(80))
    status = db.Column (db.String(12))
    IP = db.Column(db.String(80))

class User(db.Model, UserMixin):
    id = db.Column( db.Integer, primary_key=True)
    username = db.Column (db.String(80), unique=True, nullable=False)
    email = db.Column (db.String(120), unique=True, nullable=False)
    password = db.Column (db.String(60), nullable=False)
    
    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"
