from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from app import db, login_manager


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    tasks = db.relationship('Task', backref='creator', lazy='dynamic')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Task(db.Model):
    __tablename__ = 'tasks'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    task_type = db.Column(db.String(20), nullable=False)  # IP, Web, Network
    target = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, running, completed, failed
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    progress = db.Column(db.Integer, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    vulnerabilities = db.relationship('Vulnerability', backref='task', lazy='dynamic')
    

class Vulnerability(db.Model):
    __tablename__ = 'vulnerabilities'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(20), nullable=False)  # critical, high, medium, low, info
    target = db.Column(db.String(255), nullable=False)
    port = db.Column(db.Integer, nullable=True)
    path = db.Column(db.String(255), nullable=True)
    details = db.Column(db.Text, nullable=True)
    discovery_time = db.Column(db.DateTime, default=datetime.utcnow)
    task_id = db.Column(db.Integer, db.ForeignKey('tasks.id'), nullable=False)
    verifications = db.relationship('VulnerabilityVerification', backref='vulnerability', lazy='dynamic')
    

class VulnerabilityVerification(db.Model):
    __tablename__ = 'vulnerability_verifications'
    
    id = db.Column(db.Integer, primary_key=True)
    verification_tool = db.Column(db.String(100), nullable=False)
    tool_description = db.Column(db.Text, nullable=True)
    verification_time = db.Column(db.DateTime, default=datetime.utcnow)
    result = db.Column(db.Boolean, nullable=False)
    details = db.Column(db.Text, nullable=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey('vulnerabilities.id'), nullable=False)


class DataValidation(db.Model):
    __tablename__ = 'data_validations'
    
    id = db.Column(db.Integer, primary_key=True)
    data_hash = db.Column(db.String(64), nullable=False)
    validation_type = db.Column(db.String(50), nullable=False)
    validation_time = db.Column(db.DateTime, default=datetime.utcnow)
    is_valid = db.Column(db.Boolean, nullable=False)
    proof = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user = db.relationship('User', backref='validations')


class MaintenanceAudit(db.Model):
    __tablename__ = 'maintenance_audits'
    
    id = db.Column(db.Integer, primary_key=True)
    audit_type = db.Column(db.String(50), nullable=False)
    target = db.Column(db.String(255), nullable=False)
    audit_time = db.Column(db.DateTime, default=datetime.utcnow)
    findings = db.Column(db.Text, nullable=True)
    recommendations = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user = db.relationship('User', backref='audits')
