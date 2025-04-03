import random
import string

def gerar_sequencia():
    caracteres = string.ascii_letters + string.digits  # Letras (maiusculas e minusculas) e números
    sequencia = ''.join(random.choice(caracteres) for _ in range(6))  # Gera 6 caracteres aleatórios
    return sequencia

# Gerar e exibir a sequência


def gerar_sequencia48():
    caracteres1 = string.ascii_letters + string.digits  # Letras (maiusculas e minusculas) e números
    sequencia1 = ''.join(random.choice(caracteres1) for _ in range(48))  # Gera 6 caracteres aleatórios
    return sequencia1

# Gerar e exibir a sequência

