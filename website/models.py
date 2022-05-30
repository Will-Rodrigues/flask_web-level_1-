from . import db
from flask_login import UserMixin


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(150))
    email = db.Column(db.String(150), unique=True)
    pais = db.Column(db.String(150))
    estado = db.Column(db.String(150))
    municipio = db.Column(db.String(150))
    cep = db.Column(db.String(150))
    rua = db.Column(db.String(150))
    numero_endereco = db.Column(db.String(150))
    complemento_endereco = db.Column(db.String(150))
    cpf = db.Column(db.String(11), unique=True)
    pis_nit = db.Column(db.String(12), unique=True)
    senha = db.Column(db.String(150))
