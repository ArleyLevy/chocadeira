import smtplib
from email.message import EmailMessage
                   
 
def enviar_email(email, mensagem):
    # Configuração da mensagem
    msg = EmailMessage()
    msg['Subject'] = 'Parabéns! Cadastro feito com sucesso em Dashboard de leds!'
    msg['From'] = 'controle.de.leds@gmail.com'
    msg['To'] = email
    msg.set_content(mensagem)

    # Enviar o e-mail
    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as servidor:
            servidor.starttls()  # Inicia o TLS
            servidor.login('controle.de.leds@gmail.com', 'uzxn gcef hcwu jfqn')  # Faz o login com as credenciais do usuário
            servidor.send_message(msg)  # Envia a mensagem configurada
            return print("Sucesso", "Email enviado com sucesso!")
    except smtplib.SMTPAuthenticationError as e:
        # Erro de autenticação
        return print("Erro", f"Erro de autenticação ao enviar o email: {e}")
    except Exception as e:
        # Qualquer outro erro
        return print ("Erro", f"Erro ao enviar o email: {e}")
    
def enviar_cod(email, mensagem):
    # Configuração da mensagem
    msg = EmailMessage()
    msg['Subject'] = 'Código para redefinição de e-mail.'
    msg['From'] = 'controle.de.leds@gmail.com'
    msg['To'] = email
    msg.set_content(mensagem)

    # Enviar o e-mail
    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as servidor:
            servidor.starttls()  # Inicia o TLS
            servidor.login('controle.de.leds@gmail.com', 'uzxn gcef hcwu jfqn')  # Faz o login com as credenciais do usuário
            servidor.send_message(msg)  # Envia a mensagem configurada
            return print("Sucesso", "Email enviado com sucesso!")
    except smtplib.SMTPAuthenticationError as e:
        # Erro de autenticação
        return print("Erro", f"Erro de autenticação ao enviar o email: {e}")
    except Exception as e:
        # Qualquer outro erro
        return print ("Erro", f"Erro ao enviar o email: {e}")