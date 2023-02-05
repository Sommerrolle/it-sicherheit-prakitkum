# Dokumentation des IT-Sicherheit-Praktikums WiSe22/23 - Angreifer-Gruppe

Gruppenmitglieder: Cuong Vo Ta, Max Mischinger, Florian Reiner

# 1. Einleitung
Ziel des IT-Sicherheit-Praktikums im WiSe22/23 war es, eine Toolchain aufzubauen, die den Netzwerkverkehr von Smart Home-Komponenten automatisch aufzeichnet, labelt und klassifiziert. Die Angreifer-Gruppe war dabei dafür zuständig, Angriffe auf die IoT Geräte im Netzwerk zu simulieren und die Netzwerkpakete der Angriffe so zu kennzeichnen, dass diese am Access-Point klassifiziert werden können.

![Aufbau des Netzwerks](assets/aufbau.png)

Hier ist der Aufbau des Netzwerks für das Praktikum zu sehen.

## 1.1 Das Projekt
Das vorliegende Projekt beinhaltet ein run-Skript, das nacheinander verschiedene Netzwerkscans und Angriffe auf IoT-Geräte im Netzwerk durchführt. Die Scans und Angriffe sind dabei modular aufgebaut, so dass sie einfach erweitert werden können und neue Scanmethoden und Angriffe einfach implementiert werden können.

![Aufbau des Projekts](assets/aufbau_projekt.png)

Hier ist der Aufbau der Angriffe auf die IoT-Geräte im Netzwerk zu sehen. Das Netzwerk wird erst auf verbundene Hosts gescannt. Für jeden Host werden anschließend mit Hilfe von Metasploit Modulen verschiedene Angriffe durchgeführt.
## 1.2 Kali Linux

Kali Linux ist eine Open Source, Debian-basierte Linux Distribution, die speziell für IT-Sicherheitsaufgaben wie Penetrations-Tests, Sicherheitsanalyse von IT-Systemen und digitaler Forensik entwickelt wird. Es hat bereits viele Tools, wie Nmap und Metasploit vorinstalliert, weswegen wir uns für diese Distribution für den Angreifer-PC entschieden haben.

## 1.3 Metasploit

# 2. Installation
Benötigte Software:

 * [Nmap](https://nmap.org/)
 * [Metasploit](https://www.metasploit.com/)
 * [Wireshark](https://www.wireshark.org/) (Empfohlen, um den erzeugten Netzwerkverkehr zu kontrollieren)
 * Python (Version 3.10 oder höher)

Es wird empfohlen, die Angriffe in einer Kali Linux Installation auszuführen. Kali Linux ist eine Linux Distribution, die für die Bereiche Sicherheitsforschung und Penetrationstests angepasst ist und alle benötigten Programme von Haus aus enthält.

Benötigte Python Pakete:

* [python-nmap](https://pypi.org/project/python-nmap/)>=0.7.1
* [netifaces](https://pypi.org/project/netifaces/)>=0.11.0
* [pymetasploit3](https://pypi.org/project/pymetasploit3/)>=1.0.3
* [pyshark](https://pypi.org/project/pyshark/)>=0.5.3
* [scapy](https://pypi.org/project/scapy/)>=2.5.0

Die Python Packages können mit der beiliegenden `requirements.txt` installiert werden:

`sudo pip3 install -r requirements.txt`

Da das Skript mit root-Rechten gestartet werden muss, müssen die Python Pakete auch für den root User installiert werden.

# 3. Durchführung des Angriffs
Bevor die Angriffe ausgeführt werden können, muss Metasploit als Deamon gestartet werden. Das geschieht über diesen Befehl:

`msfrpcd -P your_password`

Das verwendete Passwort muss in `src/settings.py` in die Konstante `METASPLOIT_PASSWORD` eingetragen werden

Anschließend kann das run-Skript kann mit folgendem Befehl aus dem Projektverzeichnis heraus gestartet werden:

`sudo python src/run.py`

Dabei muss das run-Skript mit root-Rechten ausgeführt werden, damit die Bibliotheken die nötigen Rechte für Netzwerkscans und zum Verschicken von Netzwerkpaketen haben.

In der vorliegenden Version werden im run-Skript die in Kapitel 4 beschriebenen Angriffe der Reihe nach ausgeführt. Der Name des Netzwerkadapters, über welche die Angriffe laufen sollen, kann über die Konstante `NETWORK_ADAPTER_NAME` in `src/seetings.py` gesetzt werden und sollte den Namen des Netzwerkadapters, die mit dem Netzwerk verbunden ist, in dem auch die IoT-Geräte verbunden sind, als String beinhalten.

Alle Angriffe werden für alle Geräte, die mit dem Netzwerk des angegebenen Netzwerkadapters verbunden sind. Deshalb muss darauf geachtet werden, dass der richtige Netzwerkadapter angegeben wurde und sich in dem Netzwerk nur Geräte befinden, die für Testzwecke angegriffen werden dürfen.

Das run-Skript versendet vor und nach jedem Angriff start- und stop-Packete, mit denen der durch die Angriffe erzeugte Netzwerkverkehr am Access-Point klassifiziert werden kann.

# 4. Module
## 4.1 Scanner
### 4.1.1 Nmap-Scan
## 4.2 Angriffe
Die Angriffsmodule benutzen Metasploit, um Angriffe auf verbundene Geräte im Netzwerk durchzuführen.

### 4.2.1 TCP-PortScan
### 4.2.2 Denial-Of-Service (DOS)
### 4.2.3 Wortlisten Angriffe
## 4.3 Klassifizierungs-Pakete
Um den Netzwerkverkehr, der durch die Scans und Angriffe erzeugt wird, am Access-Point klassifizieren zu können, werden UDP Pakete erzeugt und verschickt, die jeweils den Beginn und das Ende eines Scans oder Angriffs kennzeichnen. Die Pakete beinhalten als Payload einen JSON-kodierten String, der die nötigen Informationen zur Klassifizierung der Netzwerkpakete enthält. Der Payload ist folgendermaßen aufgebaut:

```json
{
    "attack": "test",
    "target": "192.168.1.100",
    "mac": "01:23:45:67:89:AB",
    "type": "start",
    "time": 1234567890000
}
```
Im Feld `attack` steht der Name der ausgeführten Attacke. In den Feldern `target` und `mac` sind die IP-Adresse und die MAC-Adresse des angegriffenen Ziels kodiert. In `target` steht `"start"` oder `"stop"` womit der Beginn bzw. das Ende eines Angriffs angezeigt wird. Im Feld `time` wird schließlich der aktuelle Unix timestamp in Millisekunden kodiert.

Im run-Skript werden die start- und stop-Pakete über den Kontextmanager `AttackNoticePackets` eingebunden, der  als Argumente den Namen des Angriffs, die IP-Adresse (bei Angriffen ohne konkretes Ziel steht hier die IP-Adresse des Access-Points) des Ziels und die MAC-Adresse des Ziels (wenn dieses Argument leer ist, wird die MAC-Adresse des angreifenden Rechners benutzt; z.B. bei Netzwerkscans, die kein eindeutiges Ziel haben) übergeben bekommt.

# 5 Neue Angriffe
Um einen neuen Angriff ins run-Skript einzubinden, kann die Funktion, die den Angriff triggert, an einer sinnvollen Stelle hinzugefügt werden. Dabei sollte vorher die Klasse `AttackNoticePackets` initialisiert werden, damit die nötigen start- und stop-Pakete korrekt versendet werden. Folgendes Beispiel zeigt, wie ein neuer Angriff auf einen verbundenen Host ins run-Skript eingefügt werden kann:

```python
with AttackNoticePackets("new_attack", connected_ip[0], connected_ip[1]):
    run_new_attack(*args)
```

# Weiterführende Links
* [Kali Linux](https://www.kali.org/)
* [Metasploit Module Library](https://www.infosecmatter.com/metasploit-module-library/)

# Feedback
* Kontextbilder mit reinhauen
* Diagramm? Acitivity / Flow chart iwas

