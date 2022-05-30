from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user


auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        #Tive que deixar password porque a autenticação do flash não reconheceu o nome 'senha'
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.senha, password):
                flash('Entrou com sucesso', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Senha incorreta', category='error')
        else:
            flash('Esse e-mail não está cadastrado', category='error')

    return render_template("login.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        nome = request.form.get('nome')
        email = request.form.get('email')
        pais = request.form.get('pais')
        estado = request.form.get('estado')
        municipio = request.form.get('municipio')
        cep = request.form.get('cep')
        rua = request.form.get('rua')
        numero_endereco = request.form.get('numero_endereco')
        complemento_endereco = request.form.get('complemento_endereco')
        cpf = request.form.get('cpf')
        pis_nit = request.form.get('pis_nit')
        senha = request.form.get('senha')
        senha2 = request.form.get('senha')

        user_email = User.query.filter_by(email=email).first()
        user_cpf = User.query.filter_by(cpf=cpf).first()
        user_pis_nit = User.query.filter_by(pis_nit=pis_nit).first()

        if user_email:
            flash('E-mail já cadastrado', category='error')
        elif user_cpf:
            flash('CPF já cadastrado', category='error')
        elif user_pis_nit:
            flash('PIS ou NIT já cadastrado', category='error')
        elif len(nome) < 2 or len(nome) > 150:
            flash('Nome inválido - Nome precisa ter mais que 2 letras e menos que 150', category='error')
        elif len(email) < 4:
            flash('Email deve ter mais do que 3 letras.', category='error')
        elif len(cep) != 8:
            flash('CEP deve conter 8 digitos', category='error')
        elif len (cpf) != 11:
            flash('CPF deve conter 11 dígitos', category='error')
        elif senha != senha2:
            flash('Senhas não combinam', category='error')
        elif len(senha) < 6:
            flash('A senha deve ter mais do que 5 caracteres', category='error')
        else:
            new_user = User(nome=nome, email=email, pais=pais, estado=estado, municipio=municipio, cep=cep, rua=rua, numero_endereco=numero_endereco, complemento_endereco=complemento_endereco, cpf=cpf, pis_nit=pis_nit, senha=generate_password_hash( senha, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Conta criada com sucesso', category='success')
            return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)

@auth.route('/cadastro', methods=['GET', 'POST'])
@login_required
def cadastro():
    if request.method == 'POST':
        user = User.query.get(int(current_user.id))
        db.session.delete(user)
        db.session.commit()
        flash("Conta excluída com sucesso", category='sucess')
        return redirect(url_for('auth.login'))

    return render_template("cadastro.html", user=current_user)