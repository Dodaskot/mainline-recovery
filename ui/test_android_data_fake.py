import json, sys
args=sys.argv[1:]
with open('/tmp/a22x-ad-ui-test/calls','a') as f: f.write(json.dumps(args)+'\n')
t='a'*64
if args==['--fixture','/tmp/a22x-ad-ui-test','inspect']:
    out=dict(ok=True,operation='inspect',can_backup=False,mounted=False,ce_authenticated=False,read_only=True,write_supported=False,volume_token=t,destination='/media/0/A22xDataBackups',reason='LOCKED')
elif args==['--fixture','/tmp/a22x-ad-ui-test','backup','--expected-volume-token',t,'--confirm']:
    out=dict(ok=True,operation='backup',verified=True,archive=dict(volume='userdata',path='/media/0/A22xDataBackups/test.tar.zst',bytes=1,sha256=t))
elif args==['--fixture','/tmp/a22x-ad-ui-test','verify','--expected-volume-token',t,'--path','/media/0/A22xDataBackups/test.tar.zst','--expected-sha256',t]:
    out=dict(ok=True,operation='verify',verified=True,archive=dict(volume='userdata',path='/media/0/A22xDataBackups/test.tar.zst',bytes=1,sha256=t))
else: out=dict(ok=False,error=dict(code='BAD_ARGS',message='unexpected arguments'))
print(json.dumps(out))
