#!/usr/bin/env python3
import websocket,json,time,sys
T=open('target.txt').read().strip();title=sys.argv[1] if len(sys.argv)>1 else 'test';comment=sys.argv[2] if len(sys.argv)>2 else 'hello'
ws=websocket.create_connection(f'ws://{T}/ws',origin=f'http://{T}',timeout=10)
ws.send(json.dumps({'type':'CLAIM'}));r=json.loads(ws.recv());print(r)
ws.send(json.dumps({'type':'SUBMIT','nonce':r['nonce'],'title':title,'comment':comment}));print(ws.recv());ws.close()
