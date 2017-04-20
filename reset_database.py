from serv1 import db
db.drop_all()
db.session.commit()
db.create_all()
db.session.commit()

