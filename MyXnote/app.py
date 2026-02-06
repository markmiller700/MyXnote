from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin

from flask_wtf import FlaskForm

from wtforms import StringField, PasswordField, TextAreaField, SubmitField
from wtforms.validators import InputRequired, Length

from werkzeug.security import generate_password_hash, check_password_hash
from models import get_engine, get_session, User, Note, Base

from sqlalchemy import select
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET', 'change-this-secret')

# Database
engine = get_engine()
Base.metadata.create_all(engine)

# Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# -------------- USER CLASS ----------
class FLUser(UserMixin):
    def __init__(self, user_obj):
        self.id = str(user_obj.id)
        self.username = user_obj.username
        self.is_admin = user_obj.is_admin


@login_manager.user_loader
def load_user(user_id):
    session = get_session(engine)
    stmt = select(User).where(User.id == int(user_id))
    user = session.execute(stmt).scalars().first()
    session.close()
    if user:
        return FLUser(user)
    return None


# ---------- FORMS ----------
class RegisterForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=3, max=80)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=4, max=200)])


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired()])
    password = PasswordField('password', validators=[InputRequired()])


class NoteForm(FlaskForm):
    title = StringField('title', validators=[InputRequired(), Length(min=1, max=150)])
    content = TextAreaField('content')


class EmptyForm(FlaskForm):
    submit = SubmitField('Submit')


# ---------- ROUTES ----------
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        session = get_session(engine)
        stmt = select(User).where(User.username == username)
        exists = session.execute(stmt).scalars().first()
        if exists:
            flash('Username already taken', 'danger')
            session.close()
            return redirect(url_for('register'))
        hashed = generate_password_hash(password)
        new = User(username=username, password=hashed, is_admin=False)
        session.add(new)
        session.commit()
        session.close()
        flash('Registered successfully. Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        session = get_session(engine)
        stmt = select(User).where(User.username == username)
        user = session.execute(stmt).scalars().first()
        session.close()
        if user and check_password_hash(user.password, password):
            login_user(FLUser(user))
            flash('تم تسجيل الدخول بنجاح', 'success')
            return redirect(url_for('admin_panel') if user.is_admin else url_for('dashboard'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out', 'info')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    session = get_session(engine)
    notes = session.query(Note).filter(Note.owner_id == int(current_user.id)).order_by(Note.created_at.desc()).all()
    form = EmptyForm()
    session.close()
    return render_template('dashboard.html', notes=notes, form=form)


@app.route('/note/new', methods=['GET', 'POST'])
@login_required
def note_new():
    form = NoteForm()
    if form.validate_on_submit():
        session = get_session(engine)
        note = Note(title=form.title.data.strip(), content=form.content.data, owner_id=int(current_user.id))
        session.add(note)
        session.commit()
        session.close()
        flash('Note created', 'success')
        return redirect(url_for('dashboard'))
    return render_template('note_edit.html', form=form, new=True)


@app.route('/note/<int:note_id>/edit', methods=['GET', 'POST'])
@login_required
def note_edit(note_id):
    session = get_session(engine)
    note = session.query(Note).filter(Note.id == note_id).first()
    if not note or note.owner_id != int(current_user.id):
        session.close()
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    form = NoteForm(obj=note)
    if form.validate_on_submit():
        note.title = form.title.data.strip()
        note.content = form.content.data
        session.commit()
        session.close()
        flash('Note updated', 'success')
        return redirect(url_for('dashboard'))
    session.close()
    return render_template('note_edit.html', form=form, new=False)


@app.route('/note/<int:note_id>/delete', methods=['POST'])
@login_required
def note_delete(note_id):
    form = EmptyForm()
    if not form.validate_on_submit():
        flash('Bad Request', 'danger')
        return redirect(url_for('dashboard'))
    session = get_session(engine)
    note = session.query(Note).filter(Note.id == note_id).first()
    if not note or note.owner_id != int(current_user.id):
        session.close()
        flash('Note not found or access denied', 'danger')
        return redirect(url_for('dashboard'))
    session.delete(note)
    session.commit()
    session.close()
    flash('Note deleted', 'info')
    return redirect(url_for('dashboard'))


# ---------- ADMIN PANEL ----------
@app.route('/admin')
@login_required
def admin_panel():
    if not current_user.is_admin:
        flash('Admins only', 'danger')
        return redirect(url_for('dashboard'))
    session = get_session(engine)
    users = session.query(User).all()
    notes = session.query(Note).order_by(Note.created_at.desc()).all()
    form = EmptyForm()
    session.close()
    return render_template('admin.html', users=users, notes=notes, form=form)


@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    form = EmptyForm()
    if not form.validate_on_submit():
        flash('Bad Request', 'danger')
        return redirect(url_for('admin_panel'))
    if not current_user.is_admin:
        flash('Admins only', 'danger')
        return redirect(url_for('dashboard'))
    if int(current_user.id) == user_id:
        flash('لا يمكنك حذف حسابك الخاص', 'danger')
        return redirect(url_for('admin_panel'))
    session = get_session(engine)
    user = session.query(User).filter(User.id == user_id).first()
    if not user:
        session.close()
        flash('المستخدم غير موجود', 'danger')
        return redirect(url_for('admin_panel'))
    session.query(Note).filter(Note.owner_id == user_id).delete()
    session.delete(user)
    session.commit()
    1
    session.close()
    flash(f'تم حذف المستخدم "{user.username}" وجميع ملاحظاته بنجاح', 'success')
    return redirect(url_for('admin_panel'))
if __name__ == '__main__':
    app.run(debug=True)
