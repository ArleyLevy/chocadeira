from flask import Flask, render_template, request, jsonify, redirect, url_for, Response, stream_with_context,flash
from flask_mysqldb import MySQL
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import json
import paho.mqtt.client as mqtt
import os
import time
import requests
import logging
from typing import Optional
import re
from flask_limiter import Limiter
from werkzeug.security import generate_password_hash, check_password_hash
from config import config_dashboard
from mysql import mysql
from datetime import timedelta
from flask import g
import uuid

app = Flask(__name__)

# Enhanced Configuration
class Config:
    MYSQL_HOST = 'mysql-3b04c61f-arleylevymec-1a1d.b.aivencloud.com'
    MYSQL_USER = 'avnadmin'
    MYSQL_PASSWORD = 'AVNS_kG4Wc5R82dPPUhIZxaL'
    MYSQL_DB = 'sql10752888'
    SECRET_KEY = 'a8Oi1923jaha1o1iJASJSAJ'
    SESSION_PERMANENT = True
    EMAIL_VALIDATION_API_KEY = '9e22da46e85c4bab9684168eb8acd81e'
    MYSQL_PORT = 12413
    
app.config.from_object(Config)

#repassar valores globais para o config.py
app.config['MYSQL_PORT'] = Config.MYSQL_PORT
app.config['EMAIL_API'] = Config.EMAIL_VALIDATION_API_KEY
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Inicialização de módulos
mysql.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Estado global dos LEDs por usuário
led_states = {}
pin_states = {}
user_temperatures = {} 
user_tempmaxmin = {}
esp_status = {}  # user_id -> timestamp da última temperatura


# Classe para representar o usuário
class User(UserMixin):
    def __init__(self, id, email, mqtt_broker, mqtt_username, mqtt_password, mqtt_port):
        self.id = id
        self.email = email
        self.broker = mqtt_broker
        self.mqtt_user = mqtt_username
        self.mqtt_password = mqtt_password
        self.mqtt_port = mqtt_port

    def get_mqtt_credentials(self) -> dict:
        """Retorna as credenciais MQTT de forma segura."""
        return {
            'mqtt_broker': self.broker,
            'mqtt_user': self.mqtt_user,
            'mqtt_port': self.mqtt_port
        }
        
# Gerencia usuários conectados
@login_manager.user_loader
def load_user(user_id: str) -> Optional[User]:
    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT 
                id, email, mqtt_broker, 
                mqtt_username, mqtt_password, mqtt_port 
            FROM users 
            WHERE id = %s
        """, (user_id,))
        user_data = cur.fetchone()
        
        if user_data:
            return User(*user_data)
        return None
    except Exception as e:
        logging.error(f"Erro ao carregar usuário: {e}")
        return None
    
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
    
# Configuração de limites de requisições
limiter = Limiter(
    app,
    default_limits=["100 per day", "30 per hour"]
)

app.register_blueprint(config_dashboard )

@app.route('/tutorial')
def tutorial():
    return render_template('tutorial.html')

# Página inicial (redireciona para login ou dashboard)
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/recuperar_senha', methods=['GET'])
def recuperar_senha():
    return render_template('recuperar_senha.html')

@app.route('/procurar_email', methods=['POST'])
def procurar_email():
    email = request.form.get('email')  # Obtém o e-mail enviado via POST
    
    if not email:
        return jsonify({"erro": "O e-mail não foi fornecido"}), 400

    import re
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({"erro": "E-mail inválido"}), 400

    try:
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE LOWER(email) = LOWER(%s)", (email,))
        resultado = cursor.fetchone()

        if resultado:
            from apimsg import enviar_cod
            from gerados import gerar_sequencia

            seq = gerar_sequencia()

            # Salvar o código no banco, associado ao e-mail
            cursor.execute("""
                UPDATE users 
                SET verification_code = %s 
                WHERE LOWER(email) = LOWER(%s)
            """, (seq, email))
            mysql.connection.commit()

            mensagem = f"O seu código de verificação é: {seq}."
            enviar_cod(email, mensagem)

            cursor.close()
            return jsonify({"encontrado": True, "mensagem": "Código de verificação enviado com sucesso!"}), 200
        else:
            cursor.close()
            return jsonify({"encontrado": False, "mensagem": "E-mail não encontrado"}), 404

    except Exception as e:
        return jsonify({"erro": str(e)}), 500


@app.route('/validar_codigo', methods=['POST'])
def validar_codigo():
    email = request.form.get('email')
    codigo = request.form.get('codigo')

    if not email or not codigo:
        return jsonify({"erro": "E-mail ou código não fornecido"}), 400

    try:
        cursor = mysql.connection.cursor()
        cursor.execute("""
            SELECT * FROM users 
            WHERE LOWER(email) = LOWER(%s) AND verification_code = %s
        """, (email, codigo))
        resultado = cursor.fetchone()

        if resultado:
            from apimsg import enviar_cod
            from gerados import gerar_sequencia48

            seq48 = gerar_sequencia48()

            # Salvar seq48 no banco, associado ao e-mail
            cursor.execute("""
                UPDATE users 
                SET reset_code = %s, verification_code = NULL
                WHERE LOWER(email) = LOWER(%s)
            """, (seq48, email))
            mysql.connection.commit()

            mensagem = f"Para redefinir sua senha, acesse o link: https://esp32-p677.onrender.com/alterar_senha/{seq48}"
            enviar_cod(email, mensagem)

            cursor.close()
            return jsonify({"validado": True, "mensagem": "Link de redefinição enviado com sucesso!"}), 200
        else:
            cursor.close()
            return jsonify({"validado": False, "mensagem": "Código inválido ou e-mail não encontrado"}), 404

    except Exception as e:
        return jsonify({"erro": str(e)}), 500

@app.route('/alterar_senha/<seq48>', methods=['GET', 'POST'])
def alterar_senha(seq48):
    if request.method == 'GET':
        # Renderiza uma página HTML para redefinir a senha
        return render_template('alterar_senha.html', seq48=seq48)

    elif request.method == 'POST':
        # Lógica para alterar a senha (como já implementado)
        try:
            dados = request.get_json()
            email = dados.get('email')
            nova_senha = dados.get('nova_senha')

            if not email or not nova_senha:
                return jsonify({"erro": "E-mail e nova senha são obrigatórios"}), 400 
                   
            if not validate_password(nova_senha):
                return jsonify({"erro": "Senha fraca. Use pelo menos 8 caracteres com maiúsculas, minúsculas e números."}), 400

            # Verifica se o seq48 é válido e pertence ao e-mail fornecido
            cursor = mysql.connection.cursor()
            cursor.execute("""
                SELECT * FROM users 
                WHERE LOWER(email) = LOWER(%s) AND reset_code = %s
            """, (email, seq48))
            resultado = cursor.fetchone()

            if not resultado:
                return jsonify({"erro": "Código de redefinição inválido ou expirado"}), 400
            
            hashed_password = generate_password_hash(nova_senha)

            # Atualiza a senha no banco
            cursor.execute("""
                UPDATE users 
                SET password_hash = %s, reset_code = NULL
                WHERE LOWER(email) = LOWER(%s)
            """, (hashed_password, email))
            mysql.connection.commit()

            if cursor.rowcount > 0:
                return jsonify({"mensagem": "Senha alterada com sucesso"}), 200
            else:
                return jsonify({"erro": "E-mail não encontrado"}), 404

        except Exception as e:
            return jsonify({"erro": f"Erro interno: {str(e)}"}), 500
        
@app.route('/login')
def loginrender():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    else:
        return render_template('login.html')

# Página de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']  # Mudei de password_hash para password

        cur = mysql.connection.cursor()
        cur.execute("SELECT id, email, password_hash, mqtt_broker, mqtt_username, mqtt_password, mqtt_port FROM users WHERE email = %s", (email,))
    
        user_data = cur.fetchone()

        if user_data and check_password_hash(user_data[2], password):  # Usando check_password_hash para verificar
            user = User(
                id=user_data[0],
                email=user_data[1],
                mqtt_broker=user_data[3],
                mqtt_username=user_data[4],
                mqtt_password=user_data[5],
                mqtt_port=user_data[6]
            )

            login_user(user, remember=True)

            # Criar e conectar cliente MQTT
            user_client = create_new_client(user.id, user.broker, user.mqtt_port, user.mqtt_user, user.mqtt_password)
            if user_client is None:
                logout_user()  # Desloga o usuário caso o cliente MQTT falhe
                flash("Falha ao conectar ao broker MQTT.", "error")
                return render_template('login.html')

            flash('Login efetuado com sucesso!', 'sucess')
            return redirect(url_for('dashboard'))
        else:
            flash("Credenciais inválidas.", "error")  # Adicionei uma mensagem flash para melhor UX
            return render_template('login.html'), 401

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def register():
    if request.method == 'POST':
        # Validações de entrada
        email = request.form.get('email', '').strip()
        password_hash = request.form.get('password_hash', '')
        mqtt_broker = request.form.get('mqtt_broker', '')
        mqtt_username = request.form.get('mqtt_username', '')
        mqtt_password = request.form.get('mqtt_password', '')
        mqtt_port = request.form.get('mqtt_port', '')

        # Validações aprimoradas
        if not validate_email(email):
            flash('E-mail inválido. Por favor, insira um e-mail válido.', 'error')
            return redirect(url_for('register'))

        if not validate_password(password_hash):
            flash('Senha fraca. Use pelo menos 8 caracteres com maiúsculas, minúsculas e números.', 'warning')
            return redirect(url_for('register'))

        # Validação de e-mail externa
        API_KEY = Config.EMAIL_VALIDATION_API_KEY
        API_URL = f"https://emailvalidation.abstractapi.com/v1/?api_key={API_KEY}&email={email}"

        try:
            response = requests.get(API_URL, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('deliverability') != "DELIVERABLE":
                    flash('O e-mail fornecido não pode ser entregue.', 'error')
                    return redirect(url_for('register'))
            else:
                flash('Serviço de validação de e-mail indisponível.', 'warning')
        except requests.RequestException:
            flash('Erro ao validar e-mail. Tente novamente mais tarde.', 'error')
            return redirect(url_for('register'))

        # Hash da senha antes de salvar
        hashed_password = generate_password_hash(password_hash)

        # Verificação do broker MQTT com timeout
        def verify_broker():
                client = mqtt.Client()
                client._sock = None
                client.username_pw_set(mqtt_username, mqtt_password)
                try:
                    logging.info(f"Conectando ao broker MQTT em {mqtt_broker}:{mqtt_port}...")
                    client.connect(mqtt_broker, int(mqtt_port), keepalive=5)  # Definir keepalive para 5 segundos
                    client.disconnect()
                    logging.info("Conexão ao broker MQTT bem-sucedida.")
                    return True
                except mqtt as mqtt_err:
                    logging.error(f"Erro MQTT: {mqtt_err}")
                    return False
                except Exception as e:
                    logging.error(f"Erro ao conectar ao broker MQTT: {e}")
                    return False

        if not verify_broker():
            flash("Verfique as credenciais do broker, não foi possível se conectar!.", "error")
            return redirect(url_for('register'))

        # Inserção no banco de dados com tratamento de duplicatas
        try:
            cur = mysql.connection.cursor()
            cur.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cur.fetchone():
                flash('Este e-mail já está cadastrado.', 'warning')
                return redirect(url_for('register'))

            cur.execute("""
                INSERT INTO users 
                (email, password_hash, mqtt_broker, mqtt_username, mqtt_password, mqtt_port) 
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (email, hashed_password, mqtt_broker, mqtt_username, mqtt_password, int(mqtt_port)))
            mysql.connection.commit()

            # Envio de e-mail de boas-vindas
            from apimsg import enviar_email
            mensagem = (
                "Bem-vindo à plataforma de Controle de LEDs! "
                "Seu cadastro foi realizado com sucesso. "
                "Acesse o tutorial para começar."
            )
            enviar_email(email, mensagem)

            flash('Registro concluído com sucesso!', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            logging.error(f"Erro no registro: {e}")
            flash('Erro interno. Tente novamente.', 'error')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    print(f"Broker: {current_user.broker}, ID: {current_user.id}")  # Aqui o current_user já está configurado
    app.config['BROKER'] = current_user.broker
    app.config['USER_ID'] = current_user.id
    app.config['EMAIL'] = current_user.email
    app.config['PORT'] = current_user.mqtt_port
    app.config['USER'] = current_user.mqtt_user
    app.config['PASSWORD'] = current_user.mqtt_password

    print(user_tempmaxmin.get(current_user.id, {}))

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT temp_max, temp_min FROM temperaturas WHERE user_id = %s", (current_user.id,))
    row = cursor.fetchone()
    cursor.close()

    if row:
        temp_max, temp_min = row
    else:
        temp_max = temp_min = "Sem dados"

    
    return render_template(
        'dashboard.html',
        broker1=current_user.broker,
        user_id=current_user.id,
        user_temps={"tempmax": temp_max, "tempmin": temp_min}
    )
    
@app.route('/pin_update', methods=['POST'])
@login_required
def update_pin():
    try:
        ledx = request.form.get('led')  # Obtendo o led selecionado
        pin = request.form.get('pin')  # Obtendo o pino selecionado
        
        # Verificando se o valor de LED e PIN são válidos
        if ledx == "nada" or pin == "nada":
            flash('Selecione um led e um pino válido!', 'warning')
            return redirect(url_for('config.config_dash'))

        # Aqui, o PIN é convertido em inteiro, se necessário
        pin = int(pin)

        # Verificando o usuário
        if int(current_user.id) != int(request.form.get('user_id')):
            return "Ação não autorizada.", 403

        # Publica o comando no broker MQTT
        topic = f"home/{current_user.id}/esp32/pin"
        message = f"{ledx}:{pin}"
        user_client = mqtt_clients.get(current_user.id)
        if user_client:
            if user_client.is_connected():
                user_client.publish(topic, message)
                print(f"Publicado no tópico {topic}: {message}")
                flash(f'A led {int(ledx[3:]) + 1} está configurada para o pino {pin}!', 'success')
                # Atualiza o estado global
                if current_user.id not in pin_states:
                    pin_states[current_user.id] = {}
                pin_states[current_user.id][ledx] = pin
                return redirect(url_for('config.config_dash'))
            else:
                print(f"Erro: Cliente MQTT não conectado para o usuário {current_user.id}.")
                return "Cliente MQTT não conectado.", 500
        else:
            print(f"Erro: Cliente MQTT não configurado para o usuário {current_user.id}.")
            return "Cliente MQTT não configurado.", 500


    except Exception as e:
        print(f"Erro no /pin_update: {e}")
        return str(e), 500
 

@app.route('/update_led', methods=['POST'])
@login_required
def update_led():
    try:
        data = request.get_json()
        if not data:
            return "Payload inválido.", 400

        user_id = data.get('user_id')
        if int(user_id) != current_user.id:
            return "Ação não autorizada.", 403

        led = data.get('led')
        status = int(data.get('status'))

        # Publica o comando no broker MQTT
        topic = f"home/{current_user.id}/esp32/leds"
        message = f"{led}:{status}"
        user_client = mqtt_clients.get(current_user.id)
        if user_client:
            if user_client.is_connected():  # Verifique se o cliente está conectado
                user_client.publish(topic, message)
                print(f"Publicado no tópico {topic}: {message}")
            else:
                print(f"Erro: Cliente MQTT não conectado para o usuário {current_user.id}.")
                return "Cliente MQTT não conectado.", 500
        else:
            print(f"Erro: Cliente MQTT não configurado para o usuário {current_user.id}.")
            return "Cliente MQTT não configurado.", 500

        # Atualiza o estado global
        if current_user.id not in led_states:
            led_states[current_user.id] = {}
        led_states[current_user.id][led] = status

        return '', 204
    except Exception as e:
        print(f"Erro no /update_led: {e}")
        return str(e), 500

# Ajuste no método led_updates
@app.route('/led_updates')
@login_required
def led_updates():
    @stream_with_context
    def stream():
        user_id = current_user.id
        while True:
            if user_id in led_states:
                for led, status in led_states[user_id].items():
                    yield f"data: {json.dumps({'user_id': user_id, 'led': led, 'status': status})}\n\n"
            time.sleep(1)  # Evita uso excessivo de CPU

    return Response(stream(), content_type='text/event-stream')

@app.route('/temperature')
@login_required
def get_temperature():
    """Retorna a última temperatura recebida via MQTT para um usuário específico."""
    user_id = str(current_user.id)  # Garantindo que a chave bate no dicionário
    temperature = user_temperatures.get(user_id, "N/A") # Garante que user_id seja string

    # Depuração: verifica se a temperatura foi salva corretamente
    print(f"📡 Buscando temperatura para user_id {user_id}")

    temperature = user_temperatures.get(user_id, "N/A")

    # Depuração: mostra o que está sendo retornado
    print(f"📡 Temperatura encontrada: {temperature}")

    return jsonify({"user_id": user_id, "temperature": temperature})

@app.route('/set_temperature', methods=['POST'])
@login_required
def set_temperature():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Payload inválido."}), 400
        
        if "temp_max" not in data or "temp_min" not in data:
            return jsonify({"error": "Campos 'temp_max' e 'temp_min' são obrigatórios."}), 400

        user_id = data.get('user_id')
        if int(user_id) != current_user.id:
            return jsonify({"error": "Ação não autorizada."}), 403

        temp_max = float(data["temp_max"])
        temp_min = float(data["temp_min"])

        topic_max = f"home/{current_user.id}/esp32/configtemp/tempmax"
        topic_min = f"home/{current_user.id}/esp32/configtemp/tempmin"

        client = mqtt_clients.get(current_user.id)
        if client and client.is_connected():
            client.publish(topic_max, str(temp_max))
            client.publish(topic_min, str(temp_min))
            print(f"Publicado no tópico {topic_max}: {temp_max}")
            print(f"Publicado no tópico {topic_min}: {temp_min}")

            user_tempmaxmin[current_user.id] = {"tempmax": temp_max, "tempmin": temp_min}
            if (
                isinstance(temp_max, (int, float)) and
                isinstance(temp_min, (int, float)) and
                temp_max > 0 and temp_min > 0
            ):
                print(user_tempmaxmin[current_user.id])
            
            cursor = mysql.connection.cursor()
            cursor.execute("""
                INSERT INTO temperaturas (user_id, temp_max, temp_min)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE temp_max = VALUES(temp_max), temp_min = VALUES(temp_min)
            """, (current_user.id, temp_max, temp_min))
            mysql.connection.commit()
            cursor.close()

            return jsonify({
                "success": True,
                "message": "Temperaturas atualizadas com sucesso!"
            }), 200

        else:
            print(f"[ERRO] Cliente MQTT não disponível ou desconectado para o usuário {current_user.id}.")
            return jsonify({"error": "Cliente MQTT não disponível ou desconectado."}), 500

    except ValueError:
        return jsonify({"error": "Valor inválido para temperatura!"}), 400
    except Exception as e:
        print(f"Erro no /set_temperature: {e}")
        return jsonify({"error": str(e)}), 500
    
@app.route('/esp_status')
@login_required
def esp_connection_status():
    user_id = str(current_user.id)
    last_seen = esp_status.get(user_id)

    if last_seen is None:
        return jsonify({"status": "offline"})  # Nunca recebeu
    elif time.time() - last_seen > 3:
        return jsonify({"status": "offline"})  # Passaram mais de 10 segundos
    else:
        return jsonify({"status": "online"})


# Desconecta o usuário
@app.route('/logout')
@login_required
def logout():
    user_id = current_user.id

    # Desconectar e remover cliente MQTT do usuário
    user_client = mqtt_clients.pop(user_id, None)
    if user_client:
        user_client.loop_stop()
        user_client.disconnect()
        print(f"Cliente MQTT desconectado para o usuário {user_id}.")

    logout_user()
    return redirect(url_for('login'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('erro404.html'), 404

@login_manager.unauthorized_handler
def unauthorized():
    flash("Você precisa estar logado para acessar esta página.", "warning")
    return redirect(url_for('login'))

@app.before_request
def ensure_mqtt_client():
    if current_user.is_authenticated:
        user_id = current_user.id

        # Já existe um cliente conectado? Se sim, nada a fazer
        if user_id in mqtt_clients and mqtt_clients[user_id].is_connected():
            return

        try:
            # Busca credenciais do usuário logado
            cur = mysql.connection.cursor()
            cur.execute("""
                SELECT mqtt_broker, mqtt_port, mqtt_username, mqtt_password
                FROM users WHERE id = %s
            """, (user_id,))
            result = cur.fetchone()
            cur.close()

            if result:
                broker, port, username, password = result
                print(f"🔄 Criando cliente MQTT on-demand para o usuário {user_id}")
                create_new_client(user_id, broker, port, username, password)
            else:
                print(f"[ERRO] Usuário {user_id} logado mas não encontrado no banco.")
        except Exception as e:
            print(f"[ERRO] Falha ao criar cliente MQTT em before_request: {e}")


# Configuração do MQTT com TLS e sem validação de certificado
mqtt_client = mqtt.Client

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("✅ Conectado ao broker MQTT!")

        user_id = userdata.get("user_id")  # <- Correto aqui!
        if user_id is None:
            print("❌ user_id não fornecido no userdata.")
            return

        # Inscrever-se nos tópicos específicos do usuário
        client.subscribe(f"home/{user_id}/esp32/temperature")
        client.subscribe(f"home/{user_id}/esp32/status")
        client.subscribe(f"home/{user_id}/esp32/request_temp")

        # Adicionar callbacks individuais (tópicos exatos)
        client.message_callback_add(f"home/{user_id}/esp32/temperature", on_message_temperature)
        client.message_callback_add(f"home/{user_id}/esp32/request_temp", on_message_request_temp)

        print(f"📡 Inscrito nos tópicos MQTT do usuário {user_id}!")
    else:
        print(f"❌ Falha ao conectar ao broker MQTT. Código de erro: {rc}")


    
def on_disconnect(client, userdata, rc):
    if rc != 0:  # Somente reconecta se for desconexão inesperada
        print("Cliente desconectado inesperadamente. Tentando reconectar...")
        for attempt in range(3):  # Limitar tentativas de reconexão
            try:
                client.reconnect()
                print("Reconexão bem-sucedida!")
                break
            except Exception as e:
                print(f"Tentativa {attempt + 1} falhou: {e}")
                time.sleep(2)  # Pequeno atraso antes de tentar novamente

def on_message(client, userdata, msg):
    topic = msg.topic
    payload = msg.payload.decode('utf-8')
    print(f"Mensagem recebida no tópico {topic}: {payload}")

    # Identifique o usuário pelo tópico
    try:
        user_id = int(topic.split('/')[1])
    except ValueError:
        print("Erro ao extrair user_id do tópico.")
        return

    # Verifique se é um comando enviado pelo ESP32
    if "commands" in topic:
        process_esp32_command(user_id, payload)
    elif "status" in topic:
        # Atualização de status de LEDs (código já existente)
        led, status = payload.split(':')
        status = float(status)
        if user_id not in led_states:
            led_states[user_id] = {}
        led_states[user_id][led] = status
        print(f"Estado do LED atualizado para o usuário {user_id}: {led} -> {status}")
    elif "temperature" in topic:
        try:
            temperature = float(payload)
            if user_id not in user_temperatures:
                user_temperatures[user_id] = {}
            user_temperatures[user_id] = temperature
            print(f"🌡️ Temperatura atualizada para o usuário {user_id}: {temperature}°C")
        except ValueError:
            print(f"❌ Erro: Payload '{payload}' não é um número válido para temperatura.")


def on_message_temperature(client, userdata, msg):
    topic = msg.topic
    payload = msg.payload.decode().strip()

    print(f"📥 Mensagem recebida no tópico: {topic} | Payload: {payload}")  

    try:
        temperature = float(payload)
        parts = topic.split('/')
        
        if len(parts) < 3:
            print(f"⚠️ Formato inesperado do tópico MQTT: {topic}")
            return
        
        user_id = str(topic.split('/')[1])  # Garantindo que user_id seja string

        user_temperatures[user_id] = temperature
        esp_status[user_id] = time.time()  # <-- Marca o horário da última temperatura recebida

        print(f"✅ Temperatura salva para usuário {user_id}: {temperature}°C")

    except ValueError:
        print(f"❌ Erro: '{payload}' não pôde ser convertido para float.")
    except Exception as e:
        print(f"❌ Erro inesperado ao processar temperatura MQTT: {e}")

def on_message_request_temp(client, userdata, msg):
    try:
        topic = msg.topic
        payload = msg.payload.decode()
        print(f"Payload recebido: {payload}")
        user_id = topic.split('/')[1]

        print(f"🟠 ESP32 do usuário {user_id} solicitou temperaturas ao reiniciar.")

        # AQUI é necessário o contexto da aplicação Flask
        with app.app_context():
            cursor = mysql.connection.cursor()
            cursor.execute("SELECT temp_max, temp_min FROM temperaturas WHERE user_id = %s", (user_id,))
            result = cursor.fetchone()
            cursor.close()

        if result:
            temp_max, temp_min = result
            topic_max = f"home/{user_id}/esp32/configtemp/tempmax"
            topic_min = f"home/{user_id}/esp32/configtemp/tempmin"
            
            mqtt_client = mqtt_clients.get(int(user_id))
            if mqtt_client and mqtt_client.is_connected():
                mqtt_client.publish(topic_max, str(temp_max))
                mqtt_client.publish(topic_min, str(temp_min))
                print(f"✅ Enviadas temp_max={temp_max} e temp_min={temp_min} para o ESP32 do usuário {user_id}")
            else:
                print(f"❌ Cliente MQTT não conectado para o usuário {user_id}")
        else:
            print(f"⚠️ Nenhuma temperatura salva para o usuário {user_id}.")

    except Exception as e:
        print(f"Erro ao processar solicitação de temperatura: {e}")

# Inscrevendo-se no tópico MQTT ao iniciar o Flask
def subscribe_to_temperature(client, user_id):
    topic = f"home/{user_id}/esp32/temperature"
    client.subscribe(topic)
    client.message_callback_add(topic, on_message_temperature)

def process_esp32_command(user_id, payload):
    """Processa comandos recebidos do ESP32."""
    try:
        # Aqui você pode decodificar e executar comandos específicos
        command, *params = payload.split(':')  # Exemplo: "turn_on:led1"
        if command == "turn_on":
            led = params[0]
            print(f"Comando recebido: Ligar {led} para o usuário {user_id}.")
            # Implemente a lógica necessária (atualizar estado, acionar algo, etc.)
        elif command == "turn_off":
            led = params[0]
            print(f"Comando recebido: Desligar {led} para o usuário {user_id}.")
        else:
            print(f"Comando desconhecido recebido: {command}")
    except Exception as e:
        print(f"Erro ao processar comando do ESP32 para o usuário {user_id}: {e}")


def create_new_client(user_id, broker, port, username, password):
    if user_id in mqtt_clients:
        print(f"Cliente MQTT já existe para o usuário {user_id}.")
        return mqtt_clients[user_id]
    

    client_id = f"{user_id}-{uuid.uuid4()}"  # <- Aqui está a mudança!
    client = mqtt.Client(client_id=client_id, userdata={"user_id": user_id})
    client.username_pw_set(username, password)
    client.tls_set()
    client.tls_insecure_set(True)

    client.on_connect = on_connect
    client.on_message = on_message
    client.on_disconnect = on_disconnect

    try:
        client.connect(broker, int(port),  keepalive=60)
        client.loop_start()
        mqtt_clients[user_id] = client
        print(f"Cliente MQTT criado e conectado para o usuário {user_id}.")
        return client
    except Exception as e:
        print(f"Erro ao criar cliente MQTT para o usuário {user_id}: {e}")
        return None

mqtt_client.on_disconnect = on_disconnect  # Adicione este callback
mqtt_client.on_connect = on_connect
mqtt_client.on_message = on_message


# Dicionário para armazenar instâncias do cliente MQTT
mqtt_clients = {}

def start_mqtt():
    with app.app_context():
        cur = mysql.connection.cursor()
        cur.execute("SELECT id, mqtt_broker, mqtt_port, mqtt_username, mqtt_password FROM users")
        users = cur.fetchall()

        for user in users:
            user_id, broker, port, username, password = user
            if user_id not in mqtt_clients:  # Verifique se o cliente já existe
                create_new_client(user_id, broker, port, username, password)
            else:
                print(f"Cliente MQTT já inicializado para o usuário {user_id}.")

# Chama a inicialização do MQTT após a aplicação ser configurada
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    logging.info("Iniciando o servidor Flask...")
    app.run(host='0.0.0.0', port=port)