from flask import Flask, abort, jsonify, request, session
from datetime import datetime
from flask_wtf import CSRFProtect
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
import re

from flask_sqlalchemy import SQLAlchemy
import os


app = Flask (__name__)
app.secret_key='my_secret_key1'
#csrf= CSRFProtect(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ca.db'

db=SQLAlchemy(app)
bcrypt= Bcrypt(app)
login_manager=LoginManager(app)

from flask_package import devmanager, routes

