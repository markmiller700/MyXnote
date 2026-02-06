from models import Base, get_engine, get_session, User
from werkzeug.security import generate_password_hash

engine = get_engine()
Base.metadata.create_all(engine)
session = get_session(engine)

# Create default admin if not exists
if not session.query(User).filter_by(username="admin").first():
    admin = User(username='admin', password=generate_password_hash('adminpass'), is_admin=True)
    session.add(admin)
    session.commit()
    print("Created admin user -> username: admin , password: adminpass")
else:
    print("Admin already exists")

session.close()
