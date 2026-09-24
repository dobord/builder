"""Disposable native mstsc test: a loopback-only QEMU guest runs the Linux server in Docker."""
import ctypes, functools, hashlib, http.server, json, os, secrets, shutil, subprocess
import threading, time, traceback, urllib.request
from ctypes import wintypes as W
from pathlib import Path
ROOT = Path(os.environ['RUNNER_TEMP'])/'native-private'
ROOT.mkdir(exist_ok=True)
LOG = (ROOT/'fixture.log').open('w', encoding='utf-8')
REPORT = {'native_pass':False, 'stage':'initialization'}
PROCS = []
ENV = {k:v for k,v in os.environ.items() if k not in ('GH_TOKEN','BUILDER_INPUT_PRIVATE_KEY','SOURCE_READ_TOKEN')}
KEY = ROOT/'guest-key'
SSH = ['ssh','-i',str(KEY),'-p','3222','-o','StrictHostKeyChecking=accept-new','-o',f'UserKnownHostsFile={ROOT / "known-hosts"}','-o','BatchMode=yes','-o','ConnectTimeout=5','ubuntu@127.0.0.1']
def run(args, *, data=None, timeout=180, check=True, capture=False):
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE if capture else LOG, stderr=LOG, timeout=timeout, env=ENV)
    if check and result.returncode:
        raise RuntimeError('Command failed: '+Path(args[0]).name+' code '+str(result.returncode))
    return result
def shell(code, **kw):
    return run(SSH+['bash','-se'],data=code.encode(),**kw)
def ps(code, **kw):
    return run(['pwsh','-NoProfile','-NonInteractive','-Command',code],**kw)
def download(url, path, expected=None, algorithm='sha256'):
    with urllib.request.urlopen(url,timeout=120) as response, path.open('wb') as output:
        shutil.copyfileobj(response, output, 1024*1024)
    with path.open('rb') as stream: digest = hashlib.file_digest(stream,algorithm).hexdigest()
    if expected and digest != expected: raise RuntimeError('Downloaded file digest mismatch')
    return digest
def screenshot(name):
    ps("Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; "
       "$r=[Windows.Forms.SystemInformation]::VirtualScreen; $b=New-Object Drawing.Bitmap($r.Width,$r.Height); "
       "$g=[Drawing.Graphics]::FromImage($b); $g.CopyFromScreen($r.Left,$r.Top,0,0,$b.Size); "
       f"$b.Save('{ROOT / name}',[Drawing.Imaging.ImageFormat]::Png); $g.Dispose(); $b.Dispose()",check=False)
def windows():
    u = ctypes.windll.user32
    result=[]
    cbtype=ctypes.WINFUNCTYPE(W.BOOL,W.HWND,W.LPARAM)
    @cbtype
    def visit(hwnd,_):
        if u.IsWindowVisible(hwnd):
            n=u.GetWindowTextLengthW(hwnd)
            title=ctypes.create_unicode_buffer(n+1); u.GetWindowTextW(hwnd,title,n+1)
            if title.value: result.append({'hwnd':int(hwnd),'title':title.value})
        return True
    u.EnumWindows(visit,0)
    return result
class Credential(ctypes.Structure):
    _fields_=[('Flags',W.DWORD),('Type',W.DWORD),('TargetName',W.LPWSTR),('Comment',W.LPWSTR),('LastWritten',W.FILETIME),('CredentialBlobSize',W.DWORD),('CredentialBlob',ctypes.POINTER(ctypes.c_ubyte)),('Persist',W.DWORD),('AttributeCount',W.DWORD),('Attributes',ctypes.c_void_p),('TargetAlias',W.LPWSTR),('UserName',W.LPWSTR)]
def credential(target,password=None,user='rdpuser'):
    adv=ctypes.WinDLL('advapi32',use_last_error=True)
    if password is None:
        adv.CredDeleteW.argtypes=[W.LPCWSTR,W.DWORD,W.DWORD]
        adv.CredDeleteW(target,2,0)
        return
    raw=password.encode('utf-16-le'); buf=(ctypes.c_ubyte*len(raw)).from_buffer_copy(raw)
    value=Credential(Type=2,TargetName=target,CredentialBlobSize=len(raw),CredentialBlob=buf,Persist=1,UserName=user)
    adv.CredWriteW.argtypes=[ctypes.POINTER(Credential),W.DWORD]
    if not adv.CredWriteW(ctypes.byref(value),0): raise ctypes.WinError(ctypes.get_last_error())
    ctypes.memset(buf,0,len(raw))
try:
    REPORT['stage']='verified-qemu-download'
    installer=ROOT/'qemu.exe'
    download('https://qemu.weilnetz.de/w64/2026/qemu-w64-setup-20260422.exe',installer,'64a43c0d39acddc9d30d290935a312a2b5c4fa62cffe6c27090f2a45ca6c8de0f0e8673e1e5117fb116a8742f86df92163531afc23f34758aadfc6d82c1f41a5','sha512')
    qdir=ROOT/'qemu'
    run([str(installer),'/S','/D='+str(qdir)],timeout=300)
    qemu=qdir/'qemu-system-x86_64.exe'; image_tool=qdir/'qemu-img.exe'
    if not qemu.exists(): raise RuntimeError('QEMU installer did not produce the expected executable')
    REPORT['qemu_version']=run([str(qemu),'--version'],capture=True).stdout.decode(errors='replace')
    installer.unlink()
    REPORT['stage']='verified-cloud-image-download'
    base='https://cloud-images.ubuntu.com/noble/current/'
    with urllib.request.urlopen(base+'SHA256SUMS',timeout=60) as response: sums=response.read().decode()
    (ROOT/'cloud-SHA256SUMS').write_text(sums)
    expected=next(line.split()[0] for line in sums.splitlines() if line.split()[-1].lstrip('*')=='noble-server-cloudimg-amd64.img')
    disk=ROOT/'guest.qcow2'; REPORT['cloud_sha256']=download(base+'noble-server-cloudimg-amd64.img',disk,expected)
    run([str(image_tool),'resize',str(disk),'32G'])
    run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(KEY)])
    seed=ROOT/'seed'; seed.mkdir()
    (seed/'meta-data').write_text('instance-id: frdpd-native-test\nlocal-hostname: native-test\n')
    public=(ROOT/'guest-key.pub').read_text().strip()
    (seed/'user-data').write_text('#cloud-config\nssh_authorized_keys:\n  - '+public+'\nssh_pwauth: false\npackage_update: true\npackages:\n  - docker.io\nruncmd:\n  - systemctl enable --now docker\n')
    (seed/'vendor-data').write_text('')
    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self,*args): pass
    http=http.server.ThreadingHTTPServer(('127.0.0.1',8000),functools.partial(Quiet,directory=str(seed)))
    threading.Thread(target=http.serve_forever,daemon=True).start()
    REPORT['stage']='guest-boot'
    serial=ROOT/'serial.log'
    command=[str(qemu),'-accel','tcg,thread=multi','-machine','q35','-cpu','max','-smp','2','-m','4096','-drive',f'file={disk},if=virtio,format=qcow2','-display','none','-monitor','none','-serial','file:'+str(serial),'-netdev','user,id=n0,hostfwd=tcp:127.0.0.1:3222-:22,hostfwd=tcp:127.0.0.1:3390-:3389','-device','virtio-net-pci,netdev=n0','-smbios','type=1,serial=ds=nocloud;s=http://10.0.2.2:8000/']
    vm=subprocess.Popen(command,stdout=LOG,stderr=LOG,env=ENV); PROCS.append(vm)
    for _ in range(180):
        if vm.poll() is not None: raise RuntimeError('QEMU exited during guest startup')
        result=run(SSH+['true'],check=False,timeout=10)
        if not result.returncode: break
        time.sleep(3)
    else: raise RuntimeError('SSH bootstrap timeout')
    shell('sudo cloud-init status --wait; sudo docker info >/dev/null\n',timeout=900)
    http.shutdown()
    REPORT['stage']='docker-runtime-import'
    image=ROOT/'native-rootfs.tar.gz'
    run(['scp','-i',str(KEY),'-P','3222','-o','StrictHostKeyChecking=yes','-o',f'UserKnownHostsFile={ROOT / "known-hosts"}',str(image),'ubuntu@127.0.0.1:/home/ubuntu/native-rootfs.tar.gz'],timeout=600)
    shell('sudo docker import /home/ubuntu/native-rootfs.tar.gz frdpd-native:fixed >/dev/null; rm /home/ubuntu/native-rootfs.tar.gz\n',timeout=600)
    image.unlink()
    password='Rdp!'+secrets.token_hex(16)
    envfile='FRDP_IDENTITY_PROVIDER=local\nFRDP_TEST_USER=rdpuser\nFRDP_TEST_PASSWORD='+password+'\nFRDP_CLASSIC_USER=rdpclassic\nFRDP_CLASSIC_PASSWORD='+secrets.token_hex(20)+'\nFRDP_E2E_LAYERED_POLICY=1\nFRDP_DISPLAY_BACKEND=xorg-dummy\n'
    shell("umask 077; cat > /home/ubuntu/server.env <<'END_TEST_ENV'\n"+envfile+"END_TEST_ENV\nsudo docker run -d --name server --hostname frdpd.layered.test --cap-add SYS_PTRACE -p 3389:3389 --env-file /home/ubuntu/server.env --entrypoint bash frdpd-native:fixed /opt/frdp-e2e/scripts/frdpd-entrypoint.sh\nrm /home/ubuntu/server.env\n",timeout=180)
    REPORT['stage']='server-health'
    shell('for i in $(seq 1 120); do if sudo docker exec server bash /opt/frdp-e2e/scripts/frdpd-healthcheck.sh; then exit 0; fi; sleep 1; done; exit 1\n',timeout=240)
    cert=shell('sudo docker exec server cat /etc/frdpd/tls.crt\n',capture=True).stdout
    (ROOT/'server.crt').write_bytes(cert)
    ps(f"$c=Import-Certificate -FilePath '{ROOT/'server.crt'}' -CertStoreLocation Cert:\\CurrentUser\\Root; $c.Thumbprint | Set-Content '{ROOT/'server-thumb.txt'}'")
    credential('TERMSRV/localhost',password); credential('TERMSRV/localhost:3390',password)
    del password,envfile
    REPORT['stage']='native-client'
    rdp=ROOT/'remoteapp.rdp'
    rdp.write_text('full address:s:localhost:3390\nusername:s:rdpuser\nremoteapplicationmode:i:1\nremoteapplicationprogram:s:||xcalc\nremoteapplicationname:s:FRDP xcalc\nalternate shell:s:||xcalc\nprompt for credentials:i:0\nauthentication level:i:2\nenablecredsspsupport:i:1\nredirectclipboard:i:0\nredirectprinters:i:0\nredirectcomports:i:0\nredirectsmartcards:i:0\naudiomode:i:2\nremoteapplicationexpandcmdline:i:0\nremoteapplicationexpandworkingdir:i:0\ndisableconnectionsharing:i:1\n',encoding='utf-16')
    ps(f"$c=New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=Disposable RemoteApp test' -CertStoreLocation Cert:\\CurrentUser\\My; Export-Certificate -Cert $c -FilePath '{ROOT/'signer.cer'}' | Out-Null; Import-Certificate -FilePath '{ROOT/'signer.cer'}' -CertStoreLocation Cert:\\CurrentUser\\Root | Out-Null; Import-Certificate -FilePath '{ROOT/'signer.cer'}' -CertStoreLocation Cert:\\CurrentUser\\TrustedPublisher | Out-Null; $c.Thumbprint | Set-Content '{ROOT/'signer-thumb.txt'}'; & rdpsign /sha256 $c.Thumbprint '{rdp}'; if ($LASTEXITCODE -ne 0) {{exit $LASTEXITCODE}}")
    ps("wevtutil sl Microsoft-Windows-TerminalServices-RDPClient/Operational /e:true",check=False)
    before=windows(); (ROOT/'windows-before.json').write_text(json.dumps(before))
    client=subprocess.Popen([str(Path(os.environ['WINDIR'])/'System32'/'mstsc.exe'),str(rdp)],env=ENV); PROCS.append(client)
    seen=[]
    for tick in range(30):
        time.sleep(2)
        current=windows(); seen.append({'seconds':2*(tick+1),'windows':current})
        if tick in (1,4,9,19,29): screenshot(f'native-{tick}.png')
        matches=[w for w in current if 'FRDP xcalc' in w['title'] or w['title'].lower()=='xcalc']
        if matches:
            REPORT['remoteapp_window']=matches[0]
            screenshot('native-remoteapp.png')
            break
    (ROOT/'windows-timeline.json').write_text(json.dumps(seen,indent=2))
    REPORT['stage']='evidence'
    data=shell('sudo docker logs server 2>&1\n',capture=True,check=False).stdout
    (ROOT/'server.log').write_bytes(data)
    REPORT['exec_result_success']=b'exec_result=0' in data
    REPORT['frame_ack']=b'first RDPGFX client frame acknowledgement received' in data
    REPORT['native_pass']=bool(REPORT.get('remoteapp_window')) and REPORT['exec_result_success'] and REPORT['frame_ack']
except Exception as exc:
    REPORT['error_type']=type(exc).__name__
    REPORT['error']=str(exc)
    traceback.print_exc(file=LOG)
finally:
    try:
        if KEY.exists():
            data=shell('sudo docker logs server 2>&1; sudo docker stop -t 5 server >/dev/null 2>&1 || true\n',capture=True,check=False,timeout=45).stdout
            (ROOT/'server-final.log').write_bytes(data)
    except Exception: pass
    try:
        screenshot('native-final.png')
        ps(f"Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-TerminalServices-RDPClient/Operational';StartTime=(Get-Date).AddHours(-1)}} -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,Message | ConvertTo-Json -Depth 4 | Set-Content '{ROOT/'windows-events.json'}'",check=False)
        for stem in ('server','signer'):
            file=ROOT/(stem+'-thumb.txt')
            if file.exists():
                thumb=file.read_text(encoding='utf-8-sig').strip()
                if all(c in '0123456789ABCDEFabcdef' for c in thumb):
                    ps(f"foreach($s in @('Root','My','TrustedPublisher')) {{Remove-Item ('Cert:\\CurrentUser\\'+$s+'\\{thumb}') -ErrorAction SilentlyContinue}}",check=False)
        credential('TERMSRV/localhost'); credential('TERMSRV/localhost:3390')
    except Exception: pass
    for proc in reversed(PROCS):
        if proc.poll() is None:
            proc.terminate()
            try: proc.wait(timeout=15)
            except subprocess.TimeoutExpired: proc.kill()
    for name in ('guest-key','guest.qcow2','native-rootfs.tar.gz','remoteapp.rdp','signer.cer'):
        (ROOT/name).unlink(missing_ok=True)
    shutil.rmtree(ROOT/'qemu',ignore_errors=True)
    (ROOT/'result.json').write_text(json.dumps(REPORT,indent=2))
    LOG.close()
raise SystemExit(0 if REPORT['native_pass'] else 1)
