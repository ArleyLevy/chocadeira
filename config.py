from flask import Blueprint,render_template, current_app, request, redirect, url_for, flash
from flask_login import login_required
from mysql import mysql
from werkzeug.security import generate_password_hash, check_password_hash
import re
import paho.mqtt.client as mqtt
import logging
import requests

def validate_email(email: str) -> bool:
    """Valida o formato do e-mail."""
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_regex, email) is not None

def validate_password(password: str) -> bool:
    """Valida a força da senha."""
    return (
        len(password) >= 8 and 
        any(char.isupper() for char in password) and
        any(char.islower() for char in password) and
        any(char.isdigit() for char in password)
    )

# Criando o Blueprint
config_dashboard = Blueprint('config', __name__)

@config_dashboard.route('/config')
@login_required
def config_dash():
    broker = current_app.config['BROKER']
    id = current_app.config['USER_ID']
    email =current_app.config['EMAIL']
    return render_template('teste.html', broker=broker, current_id=id, email=email)

@config_dashboard.route('/config_senha', methods=['POST'])
@login_required
def config_senha():
    password_hash = request.form.get('nome')
    nova_senha = request.form.get('nome1')
    nova_senha1 = request.form.get('nome2')
    email = current_app.config['EMAIL']
    
    if not validate_password(nova_senha):
        flash('Senha fraca. Use pelo menos 8 caracteres com maiúsculas, minúsculas e números.', 'warning')
        return redirect(url_for('config.config_dash'))
    
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, email, password_hash, mqtt_broker, mqtt_username, mqtt_password, mqtt_port FROM users WHERE email = %s", (email,))
       
    user_data = cur.fetchone()
    
    hashed_password = generate_password_hash(nova_senha)

    if user_data and check_password_hash(user_data[2], password_hash):
        if nova_senha1 == nova_senha:
            cur.execute("""
                UPDATE users 
                SET password_hash = %s, reset_code = NULL
                WHERE LOWER(email) = LOWER(%s)
            """, (hashed_password, email))
            mysql.connection.commit()
            flash("Senha redefinida com sucesso!")
            return redirect(url_for('config.config_dash'))
        else:
            flash("Confirmação de nova senha errada!", 'warning')
            return redirect(url_for('config.config_dash'))
            
    else:
        flash("Senha antiga incorreta!", 'error')
        return redirect(url_for('config.config_dash'))
    
@config_dashboard.route('/config_broker', methods=['POST'])
@login_required
def config_broker():
    broker = current_app.config['BROKER']
    password = current_app.config['PASSWORD']
    port = int(current_app.config['PORT'])
    user = current_app.config['USER']
    email = current_app.config['EMAIL']

    broker_ = request.form.get('broker')
    user_ = request.form.get('user')
    password_ = request.form.get('password')
    port_ = int(request.form.get('port'))

    if broker_ == broker and password_ == password and port_ == port and user_ == user:
        flash("Não pode alterar um broker MQTT já existente", 'warning')
        return redirect(url_for('config.config_dash'))
    else:   
        def verify_broker():
            client = mqtt.Client()
            client.username_pw_set(user_, password_)

            try:
                logging.info(f"Conectando ao broker MQTT em {broker_}:{port_}...")
                client.connect(broker_, port_, keepalive=5)
                client.disconnect()
                logging.info("Conexão ao broker MQTT bem-sucedida.")
                return True
            except Exception as e:
                logging.error(f"Erro ao conectar ao broker MQTT: {e}")
                return False

        if not verify_broker():
            flash("Verifique as credenciais do broker. Não foi possível se conectar!", "error")
            return redirect(url_for('config.config_dash'))
        
        cur = mysql.connection.cursor()
        try:
            cur.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cur.fetchone():
                cur.execute("""
                    UPDATE users 
                    SET mqtt_broker = %s, mqtt_username = %s, mqtt_password = %s, mqtt_port = %s, reset_code = NULL
                    WHERE LOWER(email) = LOWER(%s)
                """, (broker_, user_, password_, int(port_), email))
                mysql.connection.commit()
                flash("Broker MQTT atualizado com sucesso.", "success")
            else:
                flash("Usuário não encontrado.", "error")
        except Exception as e:
            logging.error(f"Erro ao atualizar o banco de dados: {e}")
            flash("Erro ao atualizar o broker no banco de dados.", "error")
        finally:
            cur.close()

        return redirect(url_for('config.config_dash'))
    
@config_dashboard.route('/config_email', methods=['POST'])
@login_required
def config_email(): 
    apiemail = current_app.config['EMAIL_API']
    email = current_app.config['EMAIL']
    email_ =  request.form.get('email')
    email__ =  request.form.get('name__')
    
    if email == email__:
        flash("O e-mail novo não pode ser o mesmo que o antigo.", "error")
        return redirect(url_for('config.config_dash'))
    elif email_ != email__:
        flash("A confirmação do e-mail é diferente!.", "error")
        return redirect(url_for('config.config_dash'))  
    elif not validate_email(email):
        flash('E-mail inválido. Por favor, insira um e-mail válido.', 'error')
        return redirect(url_for('config.config_dash'))
    else:  
        #Verificar se o e-mail existe
        API_URL = f"https://emailvalidation.abstractapi.com/v1/?api_key={apiemail}&email={email_}"
        try:
            response = requests.get(API_URL, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('deliverability') != "DELIVERABLE":
                    flash('O e-mail fornecido não pode ser entregue.', 'error')
                    return redirect(url_for('config.config_dash'))
            else:
                flash('Serviço de validação de e-mail indisponível.', 'warning')
        except requests.RequestException:
            flash('Erro ao validar e-mail. Tente novamente mais tarde.', 'error')
            return redirect(url_for('config.config_dash'))
        
        try:
            cur = mysql.connection.cursor()
            cur.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cur.fetchone():
                cur.execute("""
                    UPDATE users 
                    SET email = %s, reset_code = NULL, verification_code = NULL
                    WHERE LOWER(email) = LOWER(%s)
                """, (email_, email))
                mysql.connection.commit()
                flash("E-mail atualizado com sucesso!", "success")
        except Exception as e:
            logging.error(f"Erro ao atualizar o banco de dados: {e}")
            flash("Erro ao atualizar o e-mail no banco de dados.", "error")
        finally:
            cur.close()

        return redirect(url_for('config.config_dash'))
                