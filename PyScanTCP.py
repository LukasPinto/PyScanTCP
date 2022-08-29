#!/usr/bin/python3
import sys,psutil
import socket
from threading import Thread
import numpy as np
import argparse
from pwn import *
import signal
def def_handler(sig,frame):
    print( "[-] saliendo......")    
    current_system_pid = os.getpid()
    ThisSystem = psutil.Process(current_system_pid)
    ThisSystem.terminate()
signal.signal(signal.SIGINT,def_handler)
#parseo de argumentos
parser = argparse.ArgumentParser(prog='PyScantPort')
parser.add_argument("-i","--ip-scan",help="Ip del host a escanear",type=str,required=True)
parser.add_argument("-p","--port-range",help="Debe ingresar un puerto, un rango (min-max) o una cantidad de puertos (1,2,3)")
parser.add_argument("-t","--threads",help="Cantidad de hilos,default 150",default=150,type=int)
args = parser.parse_args()

if args.port_range != None:

    if len(args.port_range) >0:
        try:
            if '-' in args.port_range and not (',' in args.port_range) and len(args.port_range.split('-'))<3 and not (int(args.port_range.split('-')[0])>=int(args.port_range.split('-')[1])):
                min_port = int(args.port_range.split('-')[0])
                max_port = int(args.port_range.split('-')[1])
                ports = list(range(min_port,max_port+1))
            elif ',' in args.port_range and not ('-' in args.port_range):
                min_port = 1
                max_port = len(args.port_range.split(','))
                ports = args.port_range.split(',')
            elif args.port_range.isdigit():
                ports = args.port_range.split(' ')
                min_port=1
                max_port=1
            else:
                print("Debe ingresar un puerto, un rango (min-max) o una cantidad de puertos (1,2,3)") 
                sys.exit(1)        
        except ValueError:
            print("Debe ingresar un puerto, un rango (min-max) o una cantidad de puertos (1,2,3)") 
            sys.exit(1) 

    else:
        min_port = 1
        max_port = 65535
        ports=list(range(min_port,max_port+1))
else:
    min_port = 1
    max_port = 65535
    ports=list(range(min_port,max_port+1))

#variables globales
ip_scan = args.ip_scan
n_threads = args.threads
array_chunk = np.array_split(ports,n_threads)
thread_list = []
cont=0
global LOCK
global progress
LOCK = threading.Lock()
progress =min_port-1
found_ports=[]
def threaded_process(items_chunk):
    try:
        for port in items_chunk:
            global progress
            global found_ports
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((ip_scan,int(port)))
            LOCK.acquire()
            progress+=1
            LOCK.release()
            p1.status('[%s / %s]'% (progress, max_port))
            #p1.status('[%s / %s]'% (progress, max_port))
            if result == 0:
                log.info('PORT - %s OPEN ' % port)
                LOCK.acquire()
                found_ports.append(port)
                LOCK.release()
            s.close()
    except Exception as e:
        print('algo ocurrio mal saliendo...',e)
        sys.exit(1)

if __name__ == "__main__":
    log.info("Iniciando Enumeracion.......")
    p1 = log.progress('Escaneando ')
    for thr in array_chunk:
        thread = Thread(target=threaded_process,args=(thr,))
        thread_list.append(thread)
        thread_list[len(thread_list)-1].start()
        cont+=1
    for thread in thread_list:
        thread.join()
    p1.success('Escaneo Finalizado [%s / %s]' % (progress,max_port))
    print('[+] Puertos encontados : ',end='')
    clip =''
    found_ports.sort()
    if len(found_ports) > 0:
        for port in found_ports:
            if found_ports.index(port) == 0:
                print('%s' % port,end='')
                clip = str(port)
            elif found_ports.index(port) > 0:
                print(',%s' % port,end='')
                clip=str(clip)+','+str(port)
    os.system('echo -n "%s" | xclip -sel clip'% clip.strip('\n'))
    print()
    log.info("Puertos copiados a la clipbload")
