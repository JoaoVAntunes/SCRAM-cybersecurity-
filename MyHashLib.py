# ESSA BIBLIOTECA É USADA PARA DEMONSTRAR O MECANISMO SCRAM
# SCRAM: SALTED CHALLENGE RESPONSE MECHANISM

#para teste: rodar a Alice, o Charles e depois o BOB, logar com o Bob e dar enter no Charles, se tudo der certo ele não pode logar e Alice deve reconhecer que é o charles
'''HOW TO TEST:

The MyHashLib.py file has an AtivarMiTM variable that can be True or False.

Test with AtivarMiTM = False. In this scenario, activate only Alice and Bob.
Bob must authenticate to Alice and receive a message signed with HMAC.
Test with AtivarMiTM = True. In this scenario, activate Alice, Charles and then Bob.
Charles will initially act as a passive MiTM and allow Bob to authenticate to Alice. This attempt should work.
Then it will do a replay attack to authenticate itself as Alice pretending to be Bob. This attempt must fail.
Lastly, Charles will send repeated signed messages to Bob. This attempt will work, and correcting it is not part of this summation.'''

import hashlib
import hmac
import os
from base64 import b64encode, b64decode

CHARLES = ('127.0.0.1', 9998)
ALICE = ('127.0.0.1', 9999)

# Após completar os códigos de ALICE e BOB altere ativar_MiTM para True para fazer o ataque de REPETIÇÃO (REPLAY)
# -- Quando ativar o MiTM, você deve executar os programas nessa ordem: CHARLES, ALICE e BOB por último.
ativar_MiTM = True

if ativar_MiTM:
    print('Este cenário está usando MiTM, o cliente está falando com um servidor falso')
else:
    print('Este cenário não tem MiTM, o cliente está falando diretamente com o servidor')



def calculaHASH(msg:str):
    '''
    Calcula o hash de uma string   

    Parameters:
    msg : str (string que será calculado o hash)

    Output:
    tuple: bytes, str
    '''
    m = hashlib.md5()
    m.update(msg.encode())
    return m.digest(), m.hexdigest() 

def geraNonce(tamanho : int):
    '''
    Gera um nonce com tamanho definido em bits

    Parameters:
    tamanho : int (quantidade de bits do nonce)

    Output:
    tuple: bytes, base64
    '''
    embytes = int(tamanho/8)
    nonce = os.urandom(embytes)
    nonceB64 = b64encode(nonce)
    return nonce, nonceB64

def separaMensagem(mensagem : bytes, separador='\n'):
    '''
    Separa em componentes uma mensagem recebida pela rede (em bytes) usando \\n como separador (default)

    Parameters:
    mensagem : bytes (mensagem recebida pela rede)
    separador : str (caractere usado como separador - \\n por default)

    Output:
    list : lista de componentes da mensagem em formato string
    '''    
    msg = mensagem.decode()
    return msg.split('\n')

def formataMensagem(componentes : list, separador='\n'):
    '''
    Junta os componentes de uma mensagem usando \\n como separador (default)

    Parameters:
    componentes : lista (lista de componentes em formato string)
    separador : str (caractere usado como separador - \\n por default)

    Output:
    bytes: mensagem formatada para ser transmitida pela rede
    '''  
    mensagem = "\n".join(componentes)
    return mensagem.encode()

def assinaMensagem(mensagem : str, segredo : str):
    '''
    Cria uma mensagem assinada com HMAC

    Parameters:
    mensagem : str (mensagem que será assinada)
    segredo : str (segredo usado para criar o HMAC)

    Output:
    bytes: mensagem formatada, com assinatura HMAC, pronta para ser transmitida pela rede
    '''  
    meuHMAC = hmac.HMAC(segredo.encode(), mensagem.encode(), hashlib.md5 )
    digest = meuHMAC.hexdigest() # esse resultado e uma string
    return formataMensagem(['HMAC', mensagem, digest])



def verificaMensagem(data : bytes, segredo : str):
    '''
    Verifica uma mensagem assinada com HMAC recebida pela rede

    Parameters:
    data : bytes (mensagem assinada com HMAC recebida pela rede)
    segredo : str (segredo usado para verificar o HMAC)

    Output:
    bool: True se o HMAC verificar a mensagem corretamente caso contrário False
    ''' 
    tipo, mensagem, digest = separaMensagem(data)   
    if tipo != 'HMAC': raise Exception('MENSAGEM INVÁLIDA')

    meuHMAC = hmac.HMAC(segredo.encode(), mensagem.encode(), hashlib.md5 )
    localdigest = meuHMAC.hexdigest()

    if digest == localdigest:
        return True
    else:
        return False
    

# Use essa porção do código para testar as funções da biblioteca

if __name__ == "__main__":
   
    hash, strhash = calculaHASH('segredo')
    cs, cs64 = geraNonce(128)

    hash_bytes, hash_string = calculaHASH('segredo' + cs64.decode())
    print(hash_string)

    print(formataMensagem(['HELLO','BOB']))

    print(separaMensagem(b'HELLO\nBOB'))

    msgassinada = assinaMensagem('teste','segredo')

    print(verificaMensagem(msgassinada, 'segredo'))
    print(verificaMensagem(msgassinada, 'nao sei o segredo'))

#-----------------------------------------------------------------------
'''
print("Casdastro da senha")
#esse sal ela gera e manda para BOB
print("Alice gera o Salt para BOB")

# "_" é pra acessar o segundo valor
_, salt = geraNonce(128)
print("Salt para usario BOB: ", salt)

print("Bob calcula a senha salgada")
#O nonce é base64, então temos que dar decode para concatenar na string, base64 é mais fácil de converter para string do que byte, logo uso decode no sal
#fazer a seguinte instrução para todas as senhas
_, senha_salgada = calculaHASH('SEGREDO' + salt.decode())

print("Senha salgada de BOB", senha_salgada)

#para MOE agora
print("Alice gera o Salt para MOE")

# "_" é pra acessar o segundo valor
_, salt = geraNonce(128)
print("Salt para usario MOE: ", salt)

print("MOE calcula a senha salgada")
#O nonce é base64, então temos que dar decode para concatenar na string, base64 é mais fácil de converter para string do que byte, logo uso decode no sal
#fazer a seguinte instrução para todas as senhas
_, senha_salgada = calculaHASH('SEGREDO' + salt.decode())

print("Senha salgada de MOE", senha_salgada)


#as senhas salgadas serão diferentes para cada usuário mesmo se eles usem a mesma senha sem sal, para o servidor elas se diferem
'''