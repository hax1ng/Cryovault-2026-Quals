#!/usr/bin/env python3
from redis_inject import send
import sys
_,r=send(tuple(sys.argv[1:]))
print('\n---decoded---')
print(r.json().get('preview',''))
