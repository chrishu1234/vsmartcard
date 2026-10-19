"""Unmodified Java JMRTD TA reader -> actual APK engine (loopback only)."""
from pathlib import Path
import os,subprocess
ROOT=Path(__file__).resolve().parents[1]
CACHE=Path.home()/'.gradle/caches/modules-2/files-2.1'
CLASSES=ROOT/'build/standalone-verification'
JAVA_HOME=Path(os.environ.get('JAVA_HOME',r'C:\Program Files\Eclipse Adoptium\jdk-17.0.19.10-hotspot'))
JAVA=str(JAVA_HOME/'bin/java.exe');JAVAC=str(JAVA_HOME/'bin/javac.exe')
def artifact(p):
    files=list((CACHE/p).glob('*/*.jar'));assert len(files)==1,p;return str(files[0])
old=artifact('org.bouncycastle/bcprov-jdk14/1.46')
jars=[artifact(p) for p in ['org.jmrtd/jmrtd/0.8.9','net.sf.scuba/scuba-smartcards/0.0.21','org.bouncycastle/bcprov-jdk18on/1.86','org.bouncycastle/bcutil-jdk18on/1.86','org.bouncycastle/bcpkix-jdk18on/1.79','org.ejbca.cvc/cert-cvc/1.4.13']]
cp=os.pathsep.join([str(CLASSES),*jars])
sources=ROOT/'app/src/main/java/com/vsmartcard/acardemulator/emulators'
subprocess.run([JAVAC,'-encoding','UTF-8','-cp',old,'-d',str(CLASSES),str(sources/'Emulator.java'),*map(str,(sources/'mrtd').glob('*.java')),str(ROOT/'verification/StandaloneCardServer.java')],check=True)
subprocess.run([JAVAC,'-encoding','UTF-8','-cp',cp,'-d',str(CLASSES),str(ROOT/'verification/StandaloneReaderOracle.java'),str(ROOT/'verification/StandaloneTAReaderOracle.java')],check=True)
count=0
for kind in ['ec','rsa']:
 for fmt in ['TD1','TD2','TD3']:
  for mode in ['BAC','PACE']:
   for profile in ['valid','dg3','expired','untrusted','bad-cert','wrong-key']:
    card=subprocess.Popen([JAVA,'-cp',os.pathsep.join([str(CLASSES),str(ROOT/'app/src/main/resources'),old]),'StandaloneCardServer',fmt,mode,'Valid','plain','plain','security','Valid','false','9000','biometric','true',kind],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
     port=card.stdout.readline().strip();assert port.isdigit(),card.stderr.read()
     result=subprocess.run([JAVA,'-cp',cp,'StandaloneTAReaderOracle',port,fmt,mode,kind,profile,str(ROOT/'app/src/main/resources/mrtd')],capture_output=True,text=True,timeout=30)
     print(result.stdout,end='',flush=True)
     if result.returncode:raise RuntimeError(result.stderr)
     card.wait(timeout=5);assert card.returncode==0,card.stderr.read();count+=1
    finally:
     if card.poll() is None:card.terminate();card.wait(timeout=5)
print(f'Original Java TA interoperability: {count} passed')
