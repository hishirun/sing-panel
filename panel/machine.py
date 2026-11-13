"""Host metrics and individual NIC samples; missing counters remain unknown."""
import os,platform,shutil,socket,time,threading
from pathlib import Path
_lock=threading.Lock();_previous=None

def snapshot(directory):
    global _previous
    now=time.monotonic();cpu=None;memory=None;uptime=None;rx=None;tx=None;received=None;sent=None;interfaces=[];boot=''
    try:
        boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        values=[int(v) for v in Path('/proc/stat').read_text().splitlines()[0].split()[1:9]]
        total=sum(values);idle=values[3]+values[4]
        default=set()
        try:
            for line in Path('/proc/net/route').read_text().splitlines()[1:]:
                fields=line.split()
                if fields[1]=='00000000':default.add(fields[0])
        except (OSError,IndexError):pass
        try:
            for line in Path('/proc/net/ipv6_route').read_text().splitlines():
                fields=line.split()
                if len(fields)>=10 and fields[0]=='0'*32 and fields[1]=='00':default.add(fields[-1])
        except OSError:pass
        for line in Path('/proc/net/dev').read_text().splitlines()[2:]:
            name,raw=line.split(':',1);name=name.strip()
            if name=='lo':continue
            v=raw.split();billable=(Path('/sys/class/net',name,'device').exists() or name in default) and not name.startswith(('docker','veth','br-','virbr','tun','tap','wg','tailscale','cni','flannel','kube','zt'))
            interfaces.append(dict(name=name,rx_total=int(v[0]),tx_total=int(v[8]),rx=None,tx=None,billable=billable))
        received=sum(i['rx_total'] for i in interfaces if i['billable']);sent=sum(i['tx_total'] for i in interfaces if i['billable'])
        with _lock:
            if _previous:
                stamp,oldtotal,oldidle,oldrx,oldtx,oldifs,oldboot=_previous
                if boot==oldboot and total>oldtotal:cpu=round(max(0,min(100,100*(1-(idle-oldidle)/(total-oldtotal)))),1)
                if now>stamp and boot==oldboot:
                    rx=max(0,(received-oldrx)/(now-stamp));tx=max(0,(sent-oldtx)/(now-stamp))
                    for interface in interfaces:
                        old=oldifs.get(interface['name'])
                        if old:
                            interface['rx']=max(0,(interface['rx_total']-old[0])/(now-stamp))
                            interface['tx']=max(0,(interface['tx_total']-old[1])/(now-stamp))
            _previous=(now,total,idle,received,sent,{i['name']:(i['rx_total'],i['tx_total']) for i in interfaces},boot)
        mem={line.split(':')[0]:int(line.split()[1])*1024 for line in Path('/proc/meminfo').read_text().splitlines()}
        memory={'total':mem['MemTotal'],'used':mem['MemTotal']-mem['MemAvailable'],'percent':round(100*(1-mem['MemAvailable']/mem['MemTotal']),1)}
        uptime=float(Path('/proc/uptime').read_text().split()[0])
    except (OSError,ValueError,KeyError,IndexError):pass
    disk=shutil.disk_usage(directory)
    return dict(hostname=socket.gethostname(),os=platform.system(),arch=platform.machine(),boot_id=boot,sampled_at=time.time(),interfaces=interfaces,rx_total=received,tx_total=sent,cpu=cpu,memory=memory,uptime=uptime,rx=rx,tx=tx,cores=os.cpu_count(),load=[round(v,2) for v in os.getloadavg()],disk={'used':disk.used,'total':disk.total,'percent':round(disk.used/disk.total*100,1)})
