"""Non-blocking Linux host samples; unavailable metrics are never reported as zero."""
import os,shutil,time,threading
from pathlib import Path
_lock=threading.Lock();_previous=None

def snapshot(directory):
    global _previous
    now=time.monotonic();cpu=None;memory=None;uptime=None;rx=None;tx=None
    try:
        values=[int(v) for v in Path('/proc/stat').read_text().splitlines()[0].split()[1:9]]
        total=sum(values);idle=values[3]+values[4]
        interfaces=[line.split(':',1)[1].split() for line in Path('/proc/net/dev').read_text().splitlines()[2:] if line.split(':')[0].strip()!='lo']
        received=sum(int(v[0]) for v in interfaces);sent=sum(int(v[8]) for v in interfaces)
        with _lock:
            if _previous:
                stamp,oldtotal,oldidle,oldrx,oldtx=_previous
                if total>oldtotal:cpu=round(100*(1-(idle-oldidle)/(total-oldtotal)),1)
                if now>stamp:rx=max(0,(received-oldrx)/(now-stamp));tx=max(0,(sent-oldtx)/(now-stamp))
            _previous=(now,total,idle,received,sent)
        mem={line.split(':')[0]:int(line.split()[1])*1024 for line in Path('/proc/meminfo').read_text().splitlines()}
        memory={'total':mem['MemTotal'],'used':mem['MemTotal']-mem['MemAvailable'],'percent':round(100*(1-mem['MemAvailable']/mem['MemTotal']),1)}
        uptime=int(float(Path('/proc/uptime').read_text().split()[0]))
    except (OSError,ValueError,KeyError,IndexError):pass
    disk=shutil.disk_usage(directory)
    return dict(cpu=cpu,memory=memory,uptime=uptime,rx=rx,tx=tx,cores=os.cpu_count(),load=[round(v,2) for v in os.getloadavg()],disk={'used':disk.used,'total':disk.total,'percent':round(disk.used/disk.total*100,1)})
