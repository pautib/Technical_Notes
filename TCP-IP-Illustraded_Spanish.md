# Resumen de 'TCP/IP Illustrated: The Protocols'

## Índice de comandos Linux por capítulo

| Capítulo | Comando                         | Función principal                                                                 |
|----------|----------------------------------|------------------------------------------------------------------------------------|
| 2        | `ifconfig`, `ip a`               | Muestra las interfaces de red y sus IPs                                           |
| 3        | `ping <IP>`                      | Comprueba conectividad y latencia usando ICMP Echo                               |
| 4        | `traceroute <IP>`                | Muestra el camino (hops) hasta un host                                            |
| 6        | `ip route`, `route -n`           | Ver rutas IP configuradas en la tabla de enrutamiento                            |
| 7        | `ping -t <ttl> <IP>`             | Prueba el tiempo de vida (TTL) y latencia                                         |
| 9        | `tcpdump`, `wireshark`           | Sniffea paquetes de red                                                           |
| 11       | `arp -a`, `ip neigh`             | Muestra la tabla ARP local                                                        |
| 12       | `tcpdump -i <iface> arp`         | Muestra tráfico ARP en una interfaz                                               |
| 13       | `dig`, `nslookup`, `host`        | Consulta registros DNS                                                            |
| 14       | `ss -tuln`, `netstat -an`        | Lista conexiones TCP/UDP y puertos en escucha                                     |
| 15       | `ss -i dst <IP>`                 | Muestra info extendida de conexión TCP hacia un destino                           |
| 16       | `tcpdump -n port 80`             | Captura paquetes en el puerto 80                                                  |
| 17       | `ss`, `lsof -i`                  | Información detallada de sockets y procesos                                       |
| 18       | `iptables`, `nft`                | Control de tráfico y filtrado de paquetes                                         |
| 19       | `ip link`, `ethtool`             | Gestión de interfaces Ethernet                                                    |
| 21       | `nc`, `telnet`                   | Herramientas para testear servicios y conexiones TCP                              |
| 22       | `watch -n 1 ss`                  | Refresca conexiones activas en tiempo real                                        |
| 23       | `tcpdump -X port 80`             | Captura y muestra payloads HTTP                                                   |
| 25       | `ip addr flush`, `ip route flush`| Borra configuraciones de red                                                      |
| 26       | `systemd-resolve --status`       | Muestra el estado del resolutor DNS                                               |
| 27       | `ip -s link`                     | Estadísticas de paquetes de red por interfaz                                      |
| 28       | `ss -tp state established`       | Ver conexiones TCP establecidas                                                   |
| 29       | `snmpwalk`, `snmpget`            | Herramientas SNMP para monitorear dispositivos                                    |


----------

## Capítulo 1: Introducción

El libro presenta los protocolos TCP/IP desde un enfoque práctico con ejemplos reales de red. Define los protocolos clave (TCP, UDP, IP) y herramientas como `tcpdump` y `netstat`. El enfoque será de abajo hacia arriba (desde la capa de enlace hasta la de aplicación).

### ✅ **Definición de TCP/IP**
**TCP/IP** (Transmission Control Protocol / Internet Protocol) es un **conjunto de protocolos de red** que permite la **comunicación entre computadoras a través de redes interconectadas**, como Internet.

Es el **modelo estándar de comunicación** en redes modernas y define **cómo se estructuran, direccionan, transmiten, enrutan y reciben los datos** entre sistemas.

---

### 🔧 **Componentes principales:**
TCP/IP no es un único protocolo, sino una **familia de protocolos** organizados en **4 capas funcionales**:

| Capa           | Función principal                                           | Protocolos destacados              |
|----------------|-------------------------------------------------------------|------------------------------------|
| **Aplicación** | Define cómo las aplicaciones usan la red                    | HTTP, DNS, SMTP, FTP, SSH          |
| **Transporte** | Comunicación de extremo a extremo                          | TCP (fiable), UDP (rápido)         |
| **Internet**   | Direccionamiento y enrutamiento entre redes                | IP, ICMP, ARP                      |
| **Enlace**     | Comunicación dentro de una red local (física o virtual)    | Ethernet, Wi-Fi, PPP               |

---

### 📦 ¿Qué hace cada capa?

| Capa           | Qué hace                                                                                      |
|----------------|-----------------------------------------------------------------------------------------------|
| **Aplicación** | Define **el formato de los datos** y protocolos como HTTP, DNS, SMTP. Las aplicaciones se comunican usando **nombres de dominio**, **sockets** y **puertos**. |
| **Transporte** | TCP o UDP **fragmentan los datos en segmentos**, gestionan conexiones, **garantizan entrega (TCP)** o simplemente envían sin confirmación (UDP). |
| **Internet**   | El protocolo IP **encapsula los segmentos en paquetes**, asigna **direcciones IP** de origen/destino y **enruta los datos** entre redes. |
| **Enlace**     | Se encarga de **entregar los paquetes a través del medio físico o virtual** (Ethernet, Wi-Fi), **resuelve direcciones MAC** con ARP si es necesario. |

---

### 💻 Relevancia práctica para backend

- Comprender **sockets y puertos** te ayuda a diseñar **APIs y microservicios** que se comuniquen correctamente.
- Saber cómo **TCP garantiza la entrega** es clave para:
  - Diseñar lógica de reintentos
  - Entender problemas como **timeouts** y **pérdida de paquetes**
- Conocer **protocolos de aplicación** (DNS, HTTP, SMTP) te permite:
  - Hacer debugging de errores complejos
  - Configurar servicios correctamente

---

### 🧩 Ejemplo real paso a paso (curl a una API)

Supón que ejecutas:  
```bash
curl https://api.ejemplo.com
```

| Capa           | Qué ocurre en ese paso de la comunicación                                                                                 |
|----------------|----------------------------------------------------------------------------------------------------------------------------|
| **Aplicación** | `curl` genera una petición HTTP. Se hace una consulta DNS para resolver `api.ejemplo.com` a una dirección IP.             |
| **Transporte** | Se establece una conexión TCP con el servidor mediante el *three-way handshake* (SYN → SYN-ACK → ACK).                    |
| **Internet**   | IP encapsula los segmentos TCP en paquetes, asigna direcciones IP origen/destino y los enruta entre redes.                |
| **Enlace**     | El paquete IP se encapsula en una trama Ethernet o Wi-Fi.                                                                 |

---

### 🛠️ Herramientas / Comandos útiles

| Herramienta / Comando     | Uso principal                                                  | Capa TCP/IP relacionada        |
|---------------------------|----------------------------------------------------------------|-------------------------------|
| `ping`                    | Verifica conectividad IP mediante ICMP                         | Internet                      |
| `traceroute`              | Muestra la ruta que sigue un paquete hacia su destino          | Internet                      |
| `netstat` / `ss`          | Muestra puertos y conexiones activas                           | Transporte                    |
| `tcpdump` / `wireshark`   | Captura y analiza paquetes en todas las capas del modelo TCP/IP| Todas las capas               |
| `ifconfig` / `ip a`       | Muestra las interfaces de red, direcciones IP y estado         | Enlace / Internet             |
| `arp -a` / `ip neigh`     | Muestra la caché ARP (asociaciones IP ↔ MAC)                   | Enlace                        |
| `host`, `nslookup`, `dig` | Realiza consultas DNS para resolver nombres de dominio         | Aplicación                    |



## 📘 Capítulo 2: Capa de Enlace (Link Layer)

Describe los elementos de una red (hosts, routers, interfaces, direcciones IP, máscaras) y cómo se comunican.


### ✅ **Definición de la Capa de Enlace (Link Layer)**

La **Capa de Enlace**, también llamada **Link Layer** o **Nivel de Enlace de Datos**, es la **primera capa del modelo TCP/IP** y se encarga de **transmitir tramas de datos entre dispositivos directamente conectados** en una red local (LAN).

Su función principal es **encapsular los paquetes IP en tramas** que puedan enviarse a través de un medio físico (como cables Ethernet o señales WiFi) y **asegurar que lleguen correctamente al siguiente nodo** (por ejemplo, un router o switch).

---

### 🧠 Lo esencial que debes saber

- La capa de enlace conecta físicamente tu máquina con la red a través de **Ethernet**, **WiFi**, o interfaces serie (como **PPP**).
- Se encarga de mover **tramas (frames)** entre dispositivos directamente conectados.
- Entrega los datos a la **capa IP** para su procesamiento.
- **MTU (Maximum Transmission Unit):** define el tamaño máximo que puede enviarse sin fragmentación.
- **Loopback (`127.0.0.1`)**: interfaz virtual para pruebas locales, no sale a la red.

---

### 🌐 Protocolos comunes en la capa de enlace

#### 📡 **1. Ethernet (IEEE 802.3)**

✅ **Definición:**  Ethernet es el protocolo más utilizado en redes LAN (Local Area Network). Define cómo los dispositivos **formatean y transmiten tramas de datos** por cable a través de una red física.

🔧 **Características:**

-   Usa direcciones MAC para identificar dispositivos.
    
-   Tiene un MTU típico de **1500 bytes**.
    
-   Funciona con switches y NICs (tarjetas de red).
    
-   Define el formato de trama Ethernet: preámbulo, MAC origen/destino, tipo, datos, y CRC.
    

----------

#### 📶 **2. Wi-Fi (IEEE 802.11)**

✅ **Definición:**  Wi-Fi es una familia de estándares para comunicación de red **inalámbrica** definida por IEEE 802.11. Opera también en la capa de enlace, pero sobre medios **no físicos** (radiofrecuencia).

🔧 **Características:**

-   Direcciones MAC como Ethernet.
    
-   Transmisión por el aire → mayor latencia y posibles interferencias.
    
-   Seguridad gestionada por WPA/WPA2/WPA3.
    
-   MTU típica también de 1500 bytes, aunque puede variar.
    

----------

#### 🔌 **3. PPP (Point-to-Point Protocol)**

✅ **Definición:**  PPP es un protocolo de enlace usado para **comunicaciones punto a punto** entre dos nodos, especialmente en conexiones como módems, túneles VPN o líneas dedicadas.

🔧 **Características:**

-   Encapsula protocolos de capa superior como IP.
    
-   Puede autenticar con PAP/CHAP.
    
-   Muy usado en conexiones **seriales, ADSL, PPPoE**, etc.
    
-   Reemplazó a SLIP por su mayor versatilidad.
    

----------

#### 🧵 **4. SLIP (Serial Line Internet Protocol)**

✅ **Definición:**  SLIP es un protocolo muy simple que permite la **transmisión de datagramas IP** a través de una **línea serial**. Fue utilizado antes de PPP, pero es **obsoleto**.

🔧 **Características:**

-   No tiene control de errores, ni autenticación.
    
-   Solo transmite IP (no múltiple protocolo).
    
-   Usado históricamente con módems.
    
-   Reemplazado completamente por PPP.
    

----------

#### 🌀 **5. Loopback (127.0.0.1)**

✅ **Definición:**  La interfaz **loopback** es una interfaz virtual interna del sistema operativo que **simula una red consigo mismo**. Su IP típica es **127.0.0.1**.

🔧 **Características:**

-   Todo el tráfico enviado a 127.0.0.1 **nunca sale al exterior**.
    
-   Se usa para **pruebas locales, servicios backend y debugging**.
    
-   Las apps suelen escuchar en `localhost` para no exponerse públicamente.
    
-   El rendimiento es muy alto (tráfico no pasa por hardware físico).

---

### 📦 Ejemplo simple

Cuando haces una petición HTTP, los datos de tu navegador viajan así:

`HTTP → TCP → IP → [Enlace]: los datos se encapsulan en una **trama Ethernet**` 

Esa trama contiene:

-   La dirección MAC de destino (por ejemplo, la del router)
    
-   La IP destino dentro del paquete IP encapsulado

---

### 👨‍💻 Relevancia práctica para backend

- **MTU mal configurado** puede causar:
  - Fragmentación IP innecesaria
  - Timeouts o pérdida de paquetes al subir archivos o hacer llamadas HTTP grandes
- Cuando ejecutas tu app en `localhost`, estás usando la **interfaz loopback**.
- Conocer la interfaz física te ayuda a depurar problemas de **latencia o cortes de red** entre servicios que corren en máquinas distintas.

---

### 🛠️ Herramientas / comandos útiles

| Comando                        | Función                                                                    |
|-------------------------------|----------------------------------------------------------------------------|
| `ifconfig` / `ip a`           | Ver interfaces de red y sus direcciones IP                                 |
| `ping -s [tamaño] [destino]`  | Probar el MTU enviando paquetes de tamaño controlado                       |
| `tcpdump -i lo`               | Ver tráfico interno en la interfaz loopback (ej. entre microservicios)     |
| `netstat -i` / `ip link`      | Mostrar estadísticas de red a nivel de interfaz (paquetes, errores, etc.)  |

---

### 🧪 Ejemplos de uso práctico

#### 🔧 `ifconfig` / `ip a`

✅ **Qué hace:**  Muestra las interfaces de red disponibles y sus direcciones IP asignadas.

🧪 **Ejemplo:** `ip a` 

📤 **Salida:**
`1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default inet 127.0.0.1/8 scope host lo`

`3: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> inet 192.168.1.42/24 brd 192.168.1.255  scope  global eth0`

🧠 **Comentario:**
Tipos de salida:
-   `lo` es la interfaz loopback (localhost).
    
-   `eth0` es tu interfaz Ethernet.
    
-   `inet` muestra las direcciones IP asignadas.

Aquí puedes ver que `eth0` tiene asignada la IP `192.168.1.42`. También ves si la interfaz está activa y operativa

🧪 **Ejemplo:** `ifconfig` 

📤 **Salida típica:**
```bash
eth0:  flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu  1500  inet  192.168.1.42  netmask  255.255.255.0  broadcast  192.168.1.255  inet6  fe80::a00:27ff:fe4e:66a1  prefixlen  64  scopeid  0x20<link>  ether  08:00:27:4e:66:a1  txqueuelen  1000  (Ethernet)  RX  packets  10234  bytes  14568000  (13.8  MiB)  RX  errors  0  dropped  0  overruns  0  frame  0  TX  packets  9054 bytes  9834000  (9.3  MiB)  TX  errors  0  dropped  0  overruns  0  carrier  0  collisions  0` 
```

🧠 **Comentario:**

-   La interfaz `eth0` está activa (`UP`) y tiene la IP `192.168.1.42`.
    
-   El campo `ether` muestra la dirección MAC.
    
-   Puedes ver también estadísticas de tráfico y errores en recepción (`RX`) o transmisión (`TX`).
    
-   El `mtu` es 1500, típico de redes Ethernet.

----------

#### 🔧 `ping -s [tamaño] [IP]`

✅ **Qué hace:**  Permite enviar paquetes ICMP de un tamaño específico, útil para probar el **MTU** sin fragmentar.

🧪 **Ejemplo:** `ping -s 1472 -M do 8.8.8.8` 

📤 **Salida:** `64  bytes  from  8.8.8.8: icmp_seq=1 ttl=117 time=12.5 ms`

🧠 **Explicación:**
-   `1472` bytes + `28` de cabecera ICMP/IP = 1500 bytes (típico MTU).
-   `-M do` evita fragmentación para detectar el límite real. Si falla, hay fragmentación o un MTU menor en el camino.

Si el paquete es demasiado grande, la respuesta sería:
 `ping: local error: Message too long, mtu=1500`

----------

#### 🔧 `tcpdump -i lo`

✅ **Qué hace:** Muestra el tráfico que pasa por la interfaz **loopback** (`lo`), es decir, comunicaciones locales en tu propia máquina.

🧪 **Ejemplos:** `sudo tcpdump -i lo` , `sudo tcpdump -i lo port 8080`

📤 **Salida:** `IP  127.0.0.1.56732 > 127.0.0.1.8080: Flags [P.], length 64` 

🧠 **Comentario:**  
Esto muestra que un servicio local (probablemente tu backend en localhost:8080) está recibiendo datos de otro proceso local.

----------

#### 🔧 `netstat -i` / `ip link`

✅ **Qué hace:**  Muestra estadísticas por interfaz: número de paquetes enviados, errores, colisiones, etc.

🧪 **Ejemplo 1 (`netstat -i`):** `netstat -i` 

📤 **Salida:**
```bash
Kernel Interface table
Iface   MTU Met RX-OK RX-ERR TX-OK TX-ERR ...
lo      65536 0   1000     0    1000    0   ...
eth0    1500  0   20000    2    19800   1   ...
```

🧠 **Comentario:**
-   `Iface`: nombre de la interfaz de red (`lo` para loopback, `eth0` para Ethernet).
    
-   `MTU`: tamaño máximo de unidad de transmisión (por ejemplo, 1500 en Ethernet).
    
-   `RX-OK` / `TX-OK`: número de **paquetes recibidos y enviados correctamente**.
    
-   `RX-ERR` / `TX-ERR`: número de **errores en recepción o envío**, como colisiones, paquetes dañados o descartados.
    
-   `lo`: tiene tráfico local entre procesos (ej. microservicios).
    
-   `eth0`: muestra el tráfico real de red, conectado físicamente o vía Wi-Fi.


🧪 **Ejemplo 2 (`ip link`):** `ip link show` 

📤 **Salida:** 

```bash
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00

2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DEFAULT group default qlen 1000
    link/ether 08:00:27:4e:66:a1 brd ff:ff:ff:ff:ff:ff
```

🧠 **Comentario:**  
`ip link show` es ideal para verificar si tu interfaz está activa (`UP`) y si tiene **una MAC válida**, **un MTU correcto**, y **no está en estado DOWN** (caída).

## 📘 Capítulo 3: IP – Internet Protocol

Explica cómo los datos viajan por la red en capas, usando `ping` y `traceroute` para comprobar conectividad. Describe encapsulamiento y cómo una aplicación envía datos.

### 🧠 Lo esencial que debes saber

- **IP (Internet Protocol)** es el núcleo de la comunicación en red. Se encarga de **enrutar paquetes** (datagramas) entre dispositivos, incluso a través de **múltiples redes y routers**.
- Es un protocolo **no confiable y no orientado a conexión**:
  - Puede perder paquetes.
  - Puede entregarlos desordenados o duplicados.
  - No garantiza llegada ni orden.
- Cada paquete IP lleva una **cabecera de 20 bytes**, con campos importantes:

| Campo           | Qué representa                              |
|------------------|---------------------------------------------|
| `Version`        | 4 para IPv4                                 |
| `IHL`            | Longitud del encabezado IP                  |
| `Total Length`   | Tamaño total del paquete IP                 |
| `TTL`            | Límite de saltos para evitar loops          |
| `Protocol`       | 1 = ICMP, 6 = TCP, 17 = UDP                 |
| `Source IP`      | Dirección IP origen                         |
| `Destination IP` | Dirección IP destino                        |

- Soporta **fragmentación** si el paquete excede el **MTU (Maximum Transmission Unit)** de una red intermedia.

---

### 👨‍💻 Relevancia para backend

- Aunque tú uses **TCP o UDP**, todo pasa encapsulado en **IP**.
- Entender IP ayuda a:
  - Diagnosticar **problemas de conectividad, latencia o rutas erróneas**.
  - Identificar **fragmentación de paquetes**, especialmente si manejas archivos grandes o llamadas API pesadas.
  - Usar herramientas como `traceroute`, que dependen de **TTL** para rastrear rutas.
- Es vital cuando trabajas con:
  - Microservicios que se comunican entre regiones/redes.
  - Balanceadores de carga o redes definidas por software.
  - Logs o trazas a nivel de red.

---

### 🛠️ Comandos / herramientas útiles

| Comando / Herramienta            | Función                                                                 |
|----------------------------------|-------------------------------------------------------------------------|
| `ip addr show`                   | Muestra las interfaces de red y sus direcciones IP                     |
| `ip route`                       | Muestra la tabla de enrutamiento del sistema                           |
| `sudo tcpdump -n -i <iface> ip` | Captura paquetes IP y muestra sus encabezados (source/dest/protocolo) |
| `ping -s <tam> -M do <dest>`     | Prueba fragmentación según MTU de red                                  |

---

### 🧪 Ejemplos prácticos

### 🔧 `ip addr show`

✅ **Qué hace:**  Muestra las interfaces activas y sus IPs asociadas.

🧪 **Ejemplo:** ``ip addr show``

📤 **Salida esperada:**
```bash
3: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>
    inet 192.168.1.45/24 brd 192.168.1.255 scope global eth0
```
🧠 **Comentario:**  
Tu interfaz de red `eth0` tiene la IP `192.168.1.45`. Este comando te muestra también el broadcast y la máscara.



### 🔧 `ip route`

✅ **Qué hace:**  Muestra la tabla de rutas, es decir, cómo se enruta el tráfico IP desde tu sistema.

🧪 **Ejemplo:** `ip route` 

📤 **Salida esperada:**
`default via 192.168.1.1 dev eth0 192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.45` 

🧠 **Comentario:**  
Todo el tráfico a Internet se envía al **gateway 192.168.1.1**. La segunda línea indica que la red local está directamente conectada.


### 🔧 `sudo tcpdump -n -i eth0 ip`

✅ **Qué hace:**  Captura tráfico IP en la interfaz seleccionada.

🧪 **Ejemplo:** `sudo tcpdump -n -i eth0 ip` 

📤 **Salida simplificada:** `IP  192.168.1.45.54321 > 8.8.8.8.53: UDP, length 32` 

🧠 **Comentario:**  
Este paquete está yendo del puerto `54321` de tu equipo hacia `8.8.8.8` por UDP. Verás muchas de estas líneas cuando hay actividad de red.

### 🔧 `ping -s 2000 -M do 8.8.8.8`

✅ **Qué hace:**  Intenta enviar un paquete de 2000 bytes sin fragmentar, para probar si el MTU es suficiente.

📤 **Respuesta esperada si el MTU es 1500:** 
`ping: local error: Message too long, mtu=1500` 

🧠 **Comentario:**  
Este error indica que **el paquete es más grande que el MTU**, y no puede fragmentarse (porque se usó `-M do`). Es útil para depurar rutas con MTU bajo.


## 📘Capítulo 4: ARP – Address Resolution Protocol

 **ARP (Address Resolution Protocol)** se usa para **resolver direcciones IP en direcciones MAC**, necesarias en redes como Ethernet.

---

### 🧠 Lo esencial que debes saber    
-   Si tu equipo conoce la IP de destino, pero no su MAC, no puede enviarle un paquete directamente en una red local.
    
-   **Funcionamiento básico:**
    
    1.  El host pregunta: **"¿Quién tiene la IP 192.168.1.1?"**
        
    2.  El host con esa IP responde: **"Yo, y mi MAC es a0:ce:c8:41:22:58"**
        
    3.  Se guarda en la **caché ARP** para futuras transmisiones.

---

### 🔄 Tipos especiales de ARP

-   **Proxy ARP:** Una máquina responde por otra (común en redes NAT o VPN).
    
-   **Gratuitous ARP:** Un host anuncia su IP/MAC a la red para detectar conflictos o informar de cambios.

---

### 👨‍💻 Relevancia para backend

-   Fallos misteriosos en la red local (ej. microservicios que no se alcanzan) pueden deberse a problemas de ARP.
    
-   **Conflictos de IP**, como dos máquinas usando la misma, se detectan a veces con Gratuitous ARP.
    
-   Diagnósticos de **"connection refused" o timeouts locales** pueden deberse a:
    
    -   MAC incorrecta en caché.
        
    -   Dispositivo desconectado.
        
    -   Problemas de red bajo nivel.

---

### 🛠️ Comandos / herramientas útiles (en tabla)

| Comando / Herramienta                  | Función                                                                 |
|----------------------------------------|-------------------------------------------------------------------------|
| `ip neigh`                             | Muestra la caché ARP del sistema                                       |
| `sudo ip neigh del <IP> dev <iface>`   | Elimina una entrada ARP específica (para forzar su renovación)        |
| `arping <IP>`                          | Envía una solicitud ARP al destino                                     |
| `sudo tcpdump -n -i <iface> arp`       | Captura tráfico ARP en tiempo real                                     |

---

### 🧪 Ejemplos prácticos

### 🔧 `ip neigh`

✅ **Qué hace:**  
Muestra la **caché ARP**, es decir, qué MAC corresponde a qué IP en la red local.

🧪 **Ejemplo:** `ip neigh` 

📤 **Salida esperada:** `192.168.1.1 dev eth0 lladdr a0:ce:c8:41:22:58 REACHABLE` 

🧠 **Comentario:**  
Significa que `192.168.1.1` (probablemente tu gateway) está accesible y su MAC es `a0:ce:c8:41:22:58`.

### 🔧 `sudo ip neigh del 192.168.1.1 dev eth0`

✅ **Qué hace:**  
Elimina una entrada específica de la caché ARP para que el sistema tenga que **reconsultarla**.

🧠 **Comentario:**  
Útil cuando hay errores de red causados por una **caché ARP corrupta** o IPs mal asignadas.

### 🔧 `arping 192.168.1.1`

✅ **Qué hace:**  
Envía manualmente solicitudes ARP y mide el tiempo de respuesta.

📤 **Respuesta esperada:**
`Unicast reply from  192.168.1.1  [A0:CE:C8:41:22:58]  1.123ms` 

🧠 **Comentario:**  
Sirve para comprobar si un host **en tu red local** está activo y responde correctamente al nivel de enlace.

### 🔧 `sudo tcpdump -n -i eth0 arp`

✅ **Qué hace:**  
Captura y muestra **solicitudes y respuestas ARP** que circulan por la red.

📤 **Salida típica:**

```bash
ARP, Request who-has 192.168.1.1  tell  192.168.1.45, length  28 ARP, Reply 192.168.1.1 is-at a0:ce:c8:41:22:58, length  28
``` 

🧠 **Comentario:**  
Puedes ver cuándo tu equipo solicita la MAC de otra IP y cómo responde el dispositivo correspondiente.

## 📘 Capítulo 5: RARP – Reverse Address Resolution Protocol

### 🧠 Lo esencial que debes saber

- **RARP (Reverse ARP)** es el inverso de ARP: permite que un dispositivo que **conoce su dirección MAC pero no su IP**, solicite su dirección IP a un servidor en la red.
- Fue diseñado para **máquinas sin disco** o sin almacenamiento permanente, como terminales tontos.
- **Funcionamiento:**
  1. El dispositivo envía una solicitud: "Soy MAC XX:XX:XX:XX:XX:XX, ¿qué IP debo usar?"
  2. Un servidor RARP responde con la IP asignada.

---

### 🕰️ RARP es histórico

- Hoy está **obsoleto** y ha sido reemplazado por **BOOTP y DHCP**.
- RARP no puede asignar otras configuraciones como:
  - Gateway
  - DNS
  - Máscara de subred
- Conocerlo ayuda a entender la evolución de los protocolos de configuración de red.

---

### 🔄 Diferencia clave con ARP

| Protocolo | Entrada         | Salida             |
|-----------|------------------|---------------------|
| ARP       | IP conocida      | Devuelve la MAC     |
| RARP      | MAC conocida     | Devuelve la IP      |

---

### 👨‍💻 Relevancia para backend

Aunque **no usarás RARP directamente**, puede ayudarte a:

- Comprender cómo funcionaban los **arranques por red (PXE, BIOS)**.
- Diagnosticar problemas raros en entornos virtualizados o embebidos antiguos.
- Entender cómo evolucionó DHCP para cubrir sus limitaciones.

---

### 🛠️ Comandos / herramientas útiles

> ⚠️ Como RARP está obsoleto, pocos sistemas lo usan, pero puedes capturar solicitudes si aún existen en tu entorno.

| Comando / Herramienta         | Función                                                   |
|-------------------------------|------------------------------------------------------------|
| `tcpdump -n -i <iface> rarp` | Captura solicitudes y respuestas RARP                     |
| `ip link` / `ip a`            | Ver dirección MAC (usada como identificador por RARP)     |

---

### 🧪 Ejemplos prácticos

#### 🔧 `tcpdump -n -i eth0 rarp`

✅ **Qué hace:** Captura tráfico RARP en la red.

```bash
sudo tcpdump -n -i eth0 rarp
```

📤 **Salida esperada:**
```bash
RARP, Request who-am-I 08:00:27:12:34:56 tell 08:00:27:12:34:56
RARP, Reply 192.168.1.45 is-at 08:00:27:12:34:56
```

🧠 **Comentario:**  
El dispositivo con MAC `08:00:27:12:34:56` solicita su IP, y el servidor responde con `192.168.1.45`.

#### 🔧 `ip link`

✅ **Qué hace:**  Muestra las direcciones MAC locales (clave para RARP).

```bash
ip link
```
📤 **Salida esperada:**
```
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    link/ether 08:00:27:12:34:56 brd ff:ff:ff:ff:ff:ff
```
🧠 **Comentario:**  La MAC mostrada sería la utilizada por un cliente RARP para identificarse.


## 📘 Capítulo 6: ICMP – Internet Control Message Protocol

### 🧠 Lo esencial que debes saber
- **ICMP** es un protocolo de soporte del protocolo IP, utilizado para **diagnóstico, control de errores y mensajes informativos** entre dispositivos.
- Aunque **no transporta datos de aplicaciones**, es **crítico para el funcionamiento de la red**.
- Se encapsula dentro de **paquetes IP** y tiene su propio campo de protocolo (número 1).

---

### 🔔 Tipos comunes de mensajes ICMP

| Tipo / Código             | Función                                      |
|---------------------------|----------------------------------------------|
| `Echo Request / Reply`    | Lo usa `ping` para verificar conectividad    |
| `Destination Unreachable` | El host no puede alcanzar el destino         |
| `Time Exceeded`           | El TTL ha llegado a cero (lo usa `traceroute`) |
| `Redirect`                | Sugiere usar otro gateway                    |
| `Fragmentation Needed`    | Usado en Path MTU Discovery                  |

---

### 👨‍💻 Relevancia para backend

- **Ping y traceroute** dependen de ICMP, así que entenderlo es útil para:
  - Diagnosticar problemas de red (conexiones lentas o fallidas)
  - Ver si un host está vivo o no responde
  - Saber si tus servicios son **accesibles desde fuera**
- Algunas **configuraciones de firewall** o redes en la nube **bloquean ICMP**, lo que puede provocar falsos diagnósticos de caída.

---

### 🛠️ Comandos / herramientas útiles

| Comando / Herramienta                | Función                                                  |
|--------------------------------------|-----------------------------------------------------------|
| `ping <IP>`                          | Envia solicitudes ICMP Echo para verificar conectividad  |
| `traceroute <IP>`                    | Usa ICMP (o UDP) para mostrar el camino hacia un host    |
| `sudo tcpdump -n -i <iface> icmp`    | Captura tráfico ICMP                                     |
| `iptables` / `ufw` / `nft`           | Para permitir o bloquear ICMP (Echo, TTL, etc.)          |

---

### 🧪 Ejemplos prácticos

#### 🔧 `ping <IP>`

✅ **Qué hace:**  Envía paquetes ICMP Echo Request y espera Echo Reply, ideal para verificar conectividad.

🧪 **Ejemplo:**
```bash
ping 8.8.8.8
```
📤 **Salida esperada:**
```bash
64 bytes from 8.8.8.8: icmp_seq=1 ttl=118 time=14.2 ms
```
🧠 **Comentario:**  
El host respondió correctamente, el TTL y el tiempo muestran latencia aproximada.

---
### 🔧 `traceroute <IP>`

✅ **Qué hace:**  
Envía paquetes con TTL incrementando para **ver los routers intermedios**.

🧪 **Ejemplo:** `traceroute google.com` 

📤 **Salida esperada:**
```bash
1  192.168.1.1     1.123 ms
2  10.0.0.1        5.456 ms
3  core.isp.net    12.789 ms ...
```
🧠 **Comentario:**  
Muestra cada salto hasta llegar al destino. Si se corta, puede indicar **filtro de ICMP o problemas de ruta**.

---

### 🔧 `sudo tcpdump -n -i eth0 icmp`

✅ **Qué hace:**  
Captura paquetes ICMP en la interfaz de red especificada.

🧪 **Ejemplo:** `sudo tcpdump -n -i eth0 icmp` 

📤 **Salida típica:**

```bash
IP 192.168.1.45 > 8.8.8.8: ICMP echo request, id 1, seq 1, length 64
IP 8.8.8.8 > 192.168.1.45: ICMP echo reply, id 1, seq 1, length 64` 
```
🧠 **Comentario:**  
Puedes ver claramente las solicitudes y respuestas tipo `ping`, además de otros tipos de mensajes ICMP si se producen.

### 🔧 `iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT`

✅ **Qué hace:**  
Permite explícitamente que el sistema reciba `ping`.

🧠 **Comentario:**  
Si tienes bloqueado ICMP, **no podrás hacer ping a ese servidor**, lo que puede confundir herramientas de monitoreo.

## 📘 Capítulo 7: Ping – Diagnóstico básico de red con ICMP

### 🧠 Lo esencial que debes saber

- `ping` es una herramienta que utiliza **ICMP Echo Request y Echo Reply** para comprobar si un host es alcanzable en la red.
- Es uno de los comandos de red más simples pero más útiles para diagnóstico.
- Por defecto, `ping` envía paquetes ICMP de 64 bytes (puede ajustarse con `-s`).
- Mide:
  - **Latencia (tiempo ida y vuelta - RTT)**
  - **Pérdida de paquetes**
  - **Variabilidad en el tiempo de respuesta (jitter)**

---

### 📦 ¿Cómo funciona internamente?

1. Se envía un **ICMP Echo Request** al host destino.
2. Si el host responde, devuelve un **ICMP Echo Reply**.
3. `ping` calcula el tiempo entre el envío y la respuesta.
4. Si no hay respuesta → **Timeout** (puede deberse a red caída, ICMP bloqueado, o firewall).

---

### 👨‍💻 Relevancia para backend

- Ideal para verificar si una **API, microservicio, o base de datos** está alcanzable desde tu servidor.
- Permite diferenciar entre:
  - **Problemas de red (sin respuesta a `ping`)**
  - **Problemas de aplicación (responde a `ping`, pero no al puerto TCP)**

---

### 🛠️ Comandos / opciones útiles de `ping`

| Comando                          | Descripción                                                   |
|----------------------------------|---------------------------------------------------------------|
| `ping <IP o hostname>`           | Verifica conectividad básica                                  |
| `ping -c 4 <host>`               | Solo envía 4 paquetes                                         |
| `ping -s <tam>`                  | Cambia el tamaño del payload ICMP                             |
| `ping -M do -s <tam> <host>`     | Prueba si un paquete de cierto tamaño se puede enviar sin fragmentar |
| `ping -i 0.2 <host>`             | Cambia el intervalo entre pings (útil para estresar la red)   |

---

### 🧪 Ejemplos prácticos

---

#### 🔧 `ping google.com`

✅ **Qué hace:**  
Prueba si puedes alcanzar `google.com` desde tu sistema.

📤 **Salida típica:**
```bash
64 bytes from 142.250.190.14: icmp_seq=1 ttl=118 time=15.2 ms
```

🧠 **Comentario:**  
Respuesta normal. El TTL indica la cantidad de saltos restantes, y el `time` da una idea de la latencia real.

---

#### 🔧 `ping -c 4 8.8.8.8`

✅ **Qué hace:**  
Envía solo 4 paquetes y luego resume las estadísticas.

📤 **Salida:**
```bash
4 packets transmitted, 4 received, 0% packet loss, time 3004ms rtt min/avg/max/mdev = 13.209/14.237/15.064/0.685 ms
```
🧠 **Comentario:**  
Ninguna pérdida de paquetes, latencia estable.

---

#### 🔧 `ping -s 1472 -M do 8.8.8.8`

✅ **Qué hace:**  
Prueba si puedes enviar un paquete de 1472 bytes **sin fragmentar** (1472 + 28 = 1500, típico MTU de Ethernet).

📤 **Error esperado si no cabe:**
```bash
ping: local error: Message too long, mtu=1500
```
🧠 **Comentario:**  
Muy útil para **detectar problemas de MTU** o redes con túneles como VPN.

#### 🔧 `ping -i 0.2 api.ejemplo.com`

✅ **Qué hace:**  Envía un ping cada 0.2 segundos para ver **jitter o pérdida temporal**.

🧠 **Comentario:**  Ideal para simular una carga leve de red y detectar picos de latencia.


## 📘 Capítulo 8: traceroute – Rastreando el camino de los paquetes

### 🧠 Lo esencial que debes saber

- `traceroute` es una herramienta que permite **ver el camino (hops)** que sigue un paquete IP desde tu máquina hasta un destino.
- Utiliza **paquetes IP con TTL (Time To Live) creciente**:
  - El primer paquete tiene TTL=1 → lo descarta el primer router y devuelve un mensaje ICMP “Time Exceeded”.
  - Luego TTL=2 → lo descarta el segundo router, y así sucesivamente.
- Gracias a las respuestas ICMP generadas en cada salto, se puede **mapear la ruta completa** hasta el destino.

---

### 📦 ¿Qué te dice traceroute?

- Qué **routers intermedios** están involucrados entre tú y el destino.
- Dónde se **pierde la conexión** si hay un fallo.
- Qué **latencia introduce cada router**.

> 📌 En Linux se basa en **UDP** por defecto. En Windows (`tracert`) usa **ICMP Echo Request**.

---

### 👨‍💻 Relevancia para backend

- Te ayuda a identificar **problemas de red más allá de tu infraestructura**.
- Muy útil para:
  - Diagnosticar **problemas de conectividad intermitentes**.
  - Ver si un servicio externo está lento por una **ruta de red ineficiente**.
  - Detectar **firewalls que filtran tráfico en ciertos saltos**.

---

### 🛠️ Comandos / opciones útiles

| Comando                             | Descripción                                               |
|-------------------------------------|-----------------------------------------------------------|
| `traceroute <host>`                 | Rastrea ruta estándar (UDP en Linux)                     |
| `traceroute -I <host>`              | Usa ICMP en lugar de UDP (como Windows)                  |
| `traceroute -T -p 443 <host>`       | Usa TCP, útil si los ICMP/UDP están bloqueados           |
| `traceroute -n <host>`              | Muestra solo IPs, sin resolver DNS                       |

---

### 🧪 Ejemplos prácticos

---

#### 🔧 `traceroute google.com`

✅ **Qué hace:**  
Muestra todos los routers por los que pasa el paquete hacia `google.com`.

📤 **Salida típica:**
```bash
1 192.168.1.1 1.123 ms 1.110 ms 1.098 ms 2 10.0.0.1 4.456 ms 4.300 ms 4.312 ms 3 isp-gateway 12.789 ms 12.512 ms 12.398 ms ...
```

🧠 **Comentario:**  Cada línea es un salto (hop). Se muestran tres medidas de tiempo por cada uno (reintentos).

---

#### 🔧 `traceroute -n github.com`

✅ **Qué hace:**  Evita la resolución DNS → más rápido y útil para diagnósticos IP directos.

📤 **Salida:**
``` bash
1 192.168.1.1 1.1 ms 2 10.0.0.1 4.3 ms 3 142.251.45.9 12.3 ms ...
```
🧠 **Comentario:**  Muestra solo IPs, útil si el DNS está lento o si quieres enfocarte en direcciones.

---

#### 🔧 `traceroute -T -p 443 example.com`

✅ **Qué hace:**  Usa paquetes TCP al puerto 443 (HTTPS), ideal si hay firewalls que **bloquean UDP o ICMP**.

📤 **Ejemplo de salida típica:**

```bash
traceroute to example.com (93.184.216.34), 30 hops max, 60 byte packets
 1  192.168.1.1 (192.168.1.1)  1.123 ms  1.105 ms  1.097 ms
 2  10.0.0.1 (10.0.0.1)        4.456 ms  4.378 ms  4.312 ms
 3  100.64.0.1 (100.64.0.1)    8.791 ms  8.768 ms  8.701 ms
 4  93.184.216.34 (93.184.216.34)  13.002 ms  12.998 ms  13.010 ms
```

🧠 **Comentario:**  Algunos entornos bloquean `traceroute` tradicional. Esta opción permite probar **como si fuera una conexión real** a un servicio.

-   Cada línea representa un **salto (hop)** entre routers desde tu equipo hasta `example.com`.
    
-   El último salto muestra la IP real del servidor web (en este caso, `93.184.216.34`).
    
-   El tiempo es el **RTT (round-trip time)** en milisegundos.
    
-   Al usar `-T`, estás simulando una conexión TCP real, útil cuando:
    
    -   ICMP está bloqueado.
        
    -   UDP no está permitido.
        
    -   Quieres saber cómo se comporta el tráfico “real” hacia un **puerto abierto** (como 443 para HTTPS).

🚫 ¿Y si algo está bloqueado?

Podrías ver asteriscos (`*`) como:
```bash
 3  * * *
```
Lo que significa que **el salto no respondió a los paquetes TCP**, ya sea porque lo filtra un firewall o el host no responde a paquetes SYN con TTL bajo.

---

## 📘 Capítulo 9: IP Routing – Enrutamiento de paquetes IP

### 🧠 Lo esencial que debes saber

- El **enrutamiento IP** es el proceso mediante el cual un sistema determina **a dónde enviar un paquete IP**.
- Cada equipo con red tiene una **tabla de rutas (routing table)** que le indica:
  - Qué interfaz usar
  - Qué gateway utilizar si el destino no está en la red local

- Tipos de rutas:
  - **Red local (directa)**: si el destino está en tu red, se envía directamente.
  - **Gateway o ruta por defecto**: si el destino no está en tu red, se envía al **router (gateway)**.

---

### 📦 ¿Qué contiene una tabla de rutas?

| Campo              | Qué representa                                |
|--------------------|------------------------------------------------|
| `Destination`      | La red destino (ej. `192.168.1.0/24`)          |
| `Gateway`          | A dónde reenviar si no está en red local       |
| `Genmask` / Prefix | La máscara de red o prefijo CIDR               |
| `Iface`            | La interfaz de red usada (eth0, wlan0...)      |

---

### 👨‍💻 Relevancia para backend

- Si tu servidor **no tiene una ruta adecuada**, no podrá responder ni enviar peticiones a ciertos destinos.
- Muy útil para:
  - Diagnosticar problemas de red entre servicios
  - Ver si estás saliendo por la IP esperada (red pública/privada)
  - Entender configuraciones de VPN, NAT, contenedores

---

### 🛠️ Comandos / herramientas útiles

| Comando                        | Función                                                  |
|-------------------------------|----------------------------------------------------------|
| `ip route`                    | Muestra la tabla de rutas                                |
| `ip route get <IP>`           | Muestra la ruta que seguiría un paquete a esa IP        |
| `route -n`                    | Muestra la tabla en formato clásico (sin resolución DNS)|
| `traceroute <host>`           | Muestra los saltos que sigue un paquete hasta el destino|
| `ip route add/del`            | Añade o elimina rutas manualmente                       |

---

### 🧪 Ejemplos prácticos

---

#### 🔧 `ip route`

✅ **Qué hace:**  Muestra las rutas conocidas por el sistema.

📤 **Salida típica:**
```bash
default via 192.168.1.1 dev eth0 192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.45
```

🧠 **Comentario:**
- Todo lo que no sea de tu red (`default`) se manda al gateway `192.168.1.1`.
- La red local `192.168.1.0/24` se maneja directamente por `eth0`.

---

#### 🔧 `ip route get 8.8.8.8`

✅ **Qué hace:**  
Calcula qué ruta seguiría un paquete hacia una IP concreta.

📤 **Salida:**
```bash
8.8.8.8 via 192.168.1.1 dev eth0 src 192.168.1.45
```

🧠 **Comentario:**  
Muestra que para alcanzar 8.8.8.8, se usará el gateway 192.168.1.1 por la interfaz eth0, y se usará tu IP local 192.168.1.45 como origen.

---

#### 🔧 `route -n`

✅ **Qué hace:**  Muestra la tabla de rutas en formato clásico, sin resolver nombres.

📤 **Salida típica:**
```bash
Destination Gateway Genmask Iface 0.0.0.0 192.168.1.1 0.0.0.0 eth0 192.168.1.0 0.0.0.0 255.255.255.0 eth0
```


🧠 **Comentario:**  
`0.0.0.0` como destino significa “todo lo que no tenga una ruta más específica”.

---

#### 🔧 `ip route add 10.10.0.0/16 via 192.168.1.10`

✅ **Qué hace:**  Agrega una ruta para la red `10.10.0.0/16` a través del gateway `192.168.1.10`.

🧠 **Comentario:**  
Útil si necesitas acceder a redes privadas que no están en tu tabla por defecto (como una red interna de empresa o una VPN).

---

## 📘 Capítulo 10: Dynamic Routing Protocols – Protocolos de enrutamiento dinámico

### 🧠 Lo esencial que debes saber

- Los **protocolos de enrutamiento dinámico** permiten que los routers y equipos actualicen automáticamente sus tablas de rutas, sin configuración manual.
- A diferencia del enrutamiento estático (con rutas fijas), el enrutamiento dinámico:
  - Aprende nuevas rutas automáticamente
  - Se adapta a cambios en la red (caídas, nuevos nodos, etc.)
  - Utiliza mensajes para intercambiar información de red

---

### 📦 Protocolos más comunes

| Protocolo | Características principales                                          |
|-----------|----------------------------------------------------------------------|
| **RIP**   | Muy simple, basado en el número de saltos. Máximo 15 hops.          |
| **OSPF**  | Usa el algoritmo de Dijkstra. Muy eficiente. Interior a una red.    |
| **BGP**   | Utilizado entre sistemas autónomos (ej. proveedores de Internet).   |

---

### 🔁 Funcionamiento general

- Los routers que usan estos protocolos:
  - **Envían periódicamente anuncios de enrutamiento** a sus vecinos
  - Detectan enlaces caídos
  - **Actualizan rutas automáticamente** en su tabla de enrutamiento
- Esto permite que una red **"se autorrecupere"** ante fallos de enlaces o routers.

---

### 👨‍💻 Relevancia para backend

- Aunque no configures routing como backend developer, entenderlo es clave si trabajas en:
  - **Infraestructura cloud compleja** (AWS, GCP, redes híbridas)
  - **Microservicios distribuidos** en distintas zonas o regiones
  - **Conectividad entre servicios en distintas VPCs o redes definidas por software**
- Puedes encontrarte con fallos que dependen de **rutas que cambian dinámicamente**, por ejemplo si un servidor deja de ser accesible tras una caída de red.

---

### 🛠️ Herramientas / conceptos útiles

| Herramienta / Concepto   | Función                                                                 |
|---------------------------|------------------------------------------------------------------------|
| `ip route`                | Ver tabla de rutas (estáticas y dinámicas)                            |
| `traceroute`              | Ver el camino real que toman los paquetes                             |
| `zebra` / `quagga` / `FRRouting` | Daemon para soportar RIP, OSPF y BGP en Linux (avanzado)      |
| `bird`, `bgpd`, `ospfd`  | Daemons específicos de routing dinámico                               |

---

### 🧪 Ejemplos y conceptos clave

---

#### 🔧 RIP (Routing Information Protocol)

✅ **Qué hace:**  
Envia actualizaciones cada 30 segundos. Usa el **número de saltos** como métrica.

🧠 **Comentario:**  
Es muy simple, pero no escala bien en redes grandes. Máximo 15 saltos → ideal solo para redes pequeñas o aisladas.

---

#### 🔧 OSPF (Open Shortest Path First)

✅ **Qué hace:**  
Calcula rutas más cortas usando **Dijkstra**. Divide la red en áreas y es muy escalable.

🧠 **Comentario:**  
Es el protocolo más usado en redes empresariales internas (intra-AS). Ofrece convergencia rápida y granularidad.

---

#### 🔧 BGP (Border Gateway Protocol)

✅ **Qué hace:**  
Controla el enrutamiento **entre sistemas autónomos (AS)**, como proveedores de internet o redes globales.

🧠 **Comentario:**  
Es el protocolo que **hace funcionar Internet**. Muy robusto, pero también complejo. Define **quién anuncia qué redes** a quién.

---

#### 🔧 `traceroute` y enrutamiento dinámico

✅ **Qué muestra?:**  
Si la ruta cambia con el tiempo (por fallos, balanceo, etc.), `traceroute` lo reflejará.

📤 **Ejemplo:**
```bash
1 192.168.1.1 2 isp-router1 3 isp-core1 ...
```


🧠 **Comentario:**  
Si un salto desaparece o cambia, puede indicar que un protocolo de routing dinámico ha **reconstruido la ruta** por otro camino.

---

## 📘 Capítulo 11: UDP – User Datagram Protocol

### 🧠 Lo esencial que debes saber

- **UDP** es un protocolo de transporte **ligero y no confiable** que se encuentra sobre IP.
- A diferencia de TCP:
  - **No establece conexión**
  - **No garantiza entrega**
  - **No ordena los mensajes**
  - **No retransmite** paquetes perdidos

- Pero es mucho más rápido y eficiente para ciertos usos, ya que:
  - Añade muy poca sobrecarga (solo 8 bytes de cabecera)
  - Es ideal para aplicaciones **en tiempo real o tolerantes a pérdida**

---

### 📦 Estructura del datagrama UDP

| Campo            | Tamaño | Descripción                                 |
|------------------|--------|---------------------------------------------|
| Source Port      | 2 bytes| Puerto origen                               |
| Destination Port | 2 bytes| Puerto destino                              |
| Length           | 2 bytes| Longitud total del datagrama UDP            |
| Checksum         | 2 bytes| Verifica errores en cabecera + datos        |

---

### 👨‍💻 Relevancia para backend

- Muchos protocolos populares de backend usan UDP:
  - **DNS**
  - **NTP**
  - **DHCP**
  - Servicios propios de baja latencia o telemetría
- Algunas APIs internas de microservicios en entornos de alta disponibilidad también usan UDP para **notificaciones, descubrimiento o logs livianos**
- Ideal para situaciones donde **la velocidad importa más que la fiabilidad**

---

### 🛠️ Comandos / herramientas útiles

| Comando / Herramienta             | Función                                                                 |
|----------------------------------|--------------------------------------------------------------------------|
| `ss -u -l`                        | Ver puertos UDP en escucha                                              |
| `tcpdump udp`                    | Captura tráfico UDP                                                     |
| `netstat -u -n`                   | Ver conexiones UDP                                                      |
| `dig`                             | Ejecuta consultas DNS (usa UDP por defecto)                             |
| `nc -u`                           | Cliente UDP manual (netcat)                                             |

---

### 🧪 Ejemplos prácticos

#### 🔧 `ss -u -l`

✅ **Qué hace:**  
Muestra puertos **UDP en escucha** en el sistema.

📤 **Salida típica:**
```bash
Netid State Local Address:Port udp UNCONN 0.0.0.0:12345
```


🧠 **Comentario:**  
Un servicio local está escuchando en el puerto 12345 por UDP. `UNCONN` indica que no hay conexión establecida (UDP es connectionless).

---

#### 🔧 `tcpdump udp`

✅ **Qué hace:**  
Captura y muestra solo paquetes UDP.

📤 **Salida típica:**
```bash
IP 192.168.1.10.5353 > 224.0.0.251.5353: UDP, length 120
```

🧠 **Comentario:**  
Aquí se muestra un datagrama UDP enviado a una dirección multicast (como en mDNS). También puedes capturar DNS, DHCP, etc.

---

#### 🔧 `netstat -u -n`

✅ **Qué hace:**  
Lista conexiones activas y puertos UDP abiertos (sin resolver DNS).

📤 **Salida:**
```bash
udp 0 0 0.0.0.0:123 0.0.0.0:*
```

🧠 **Comentario:**  
El servicio está escuchando en UDP:123 (probablemente NTP). UDP no muestra "estados" como TCP.

---

#### 🔧 `dig google.com`

✅ **Qué hace:**  
Envía una consulta DNS a los servidores públicos (por defecto usa UDP).

📤 **Salida resumida:**
```bash
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345 ;; QUESTION SECTION: ;google.com. IN A

;; ANSWER SECTION: google.com. 300 IN A 142.250.190.78
```


🧠 **Comentario:**  
Consulta DNS estándar. `dig` usa UDP por defecto, aunque cambia a TCP si la respuesta es demasiado grande.

---

### 🔧 `echo "hello" | nc -u 127.0.0.1 12345`

✅ **Qué hace:**  
Envía un mensaje UDP manualmente a `localhost:12345`.

🧠 **Comentario:**  
Muy útil para probar si tu servicio UDP está recibiendo datos correctamente.

---

## 📘 Capítulo 12: Broadcasting and Multicasting

### 🧠 Lo esencial que debes saber

Este capítulo trata sobre **formas especiales de comunicación IP** en las que un paquete se envía **a múltiples receptores**, en lugar de a un único destino:

---

### 📢 Broadcasting

- **Broadcast** significa enviar un paquete a **todos los hosts de una red local**.
- Se usa en protocolos como:
  - **ARP**
  - **DHCP (cuando no se conoce aún la IP del servidor)**
- Existen dos tipos:
  - **Directed Broadcast**: a la dirección final de la red (ej. `192.168.1.255`)
  - **Limited Broadcast**: a `255.255.255.255` (nunca sale de la red local)

🧠 **Importante:** Los routers **no reenvían broadcasts**, por lo que solo funcionan dentro de una red local.

---

### 📡 Multicasting

- **Multicast** permite enviar paquetes a **múltiples destinos específicos**, sin afectar a todos los hosts.
- Usado por aplicaciones como:
  - **Streaming multimedia**
  - **Protocolo de descubrimiento (mDNS, SSDP)**
  - **Protocolos de routing dinámico (OSPF, RIPng, etc.)**
- Utiliza direcciones IP especiales: `224.0.0.0` a `239.255.255.255`
  - Ejemplo: `224.0.0.1` (todos los hosts)

🧠 **Importante:** A diferencia del broadcast, **los routers pueden reenviar multicast** si están configurados correctamente.

---

### 👨‍💻 Relevancia para backend

- Servicios que usan descubrimiento automático o comunicación distribuida (como **microservicios en red local** o **contenedores**) pueden apoyarse en **multicast o broadcast**.
- Algunos sistemas legados o protocolos embebidos aún usan broadcast para configurarse.
- Entender estas técnicas ayuda a:
  - Depurar tráfico inesperado
  - Detectar **anuncios de servicios** (como impresoras, cámaras IP, etc.)
  - Controlar qué se expone en red local

---

### 🛠️ Comandos / herramientas útiles

| Comando / Herramienta              | Función                                                                 |
|------------------------------------|--------------------------------------------------------------------------|
| `tcpdump -i <iface> broadcast`     | Captura tráfico broadcast                                               |
| `tcpdump -i <iface> multicast`     | Captura tráfico multicast                                               |
| `ping 224.0.0.1`                   | Prueba si tu máquina puede enviar/recibir multicast (todos los hosts)   |
| `netstat -g` / `ip maddr`          | Muestra los grupos multicast suscritos                                 |
| `ssdp-discovery` / `avahi-browse`  | Descubre servicios vía multicast en red local                           |

---

### 🧪 Ejemplos prácticos

#### 🔧 `tcpdump -i eth0 broadcast`

✅ **Qué hace:**  
Captura paquetes que usan direcciones broadcast.

```bash
ARP, Request who-has 192.168.1.1 tell 192.168.1.45
```
🧠 **Comentario:**  Aquí tu sistema está pidiendo a toda la red quién tiene una determinada IP.


#### 🔧 `ping 224.0.0.1`

✅ **Qué hace:**  Envía paquetes ICMP multicast a todos los hosts de la red que lo soporten.

```bash
64 bytes from 192.168.1.12: icmp_seq=1 ttl=1 time=1.3 ms
64 bytes from 192.168.1.34: icmp_seq=1 ttl=1 time=1.9 ms
```
🧠 **Comentario:**  
Estás viendo respuestas de otros hosts en tu red que escuchan en ese grupo multicast.


#### 🔧 `netstat -g` o `ip maddr`

✅ **Qué hace:**  
Muestra los **grupos multicast** a los que tu máquina está suscrita.

```bash
224.0.0.1
239.255.255.250 
```

🧠 **Comentario:**  
Tu máquina puede recibir paquetes enviados a esas direcciones multicast (SSDP, mDNS, etc.).

#### 🔧 `tcpdump -i eth0 multicast`

✅ **Qué hace:**  
Captura tráfico multicast en la interfaz especificada.

```bash
IP 192.168.1.45.5353 > 224.0.0.251.5353: UDP, length 100
```

🧠 **Comentario:**  
Tráfico típico de mDNS (Bonjour, Avahi, etc.). Puedes usarlo para descubrir dispositivos y servicios.


## 📘 Capítulo 13: IGMP – Internet Group Management Protocol

### 🧠 Lo esencial que debes saber

- **IGMP** es un protocolo de la capa de red utilizado por los hosts y routers para gestionar la **suscripción a grupos multicast**.
- Solo se utiliza con **IPv4** (en IPv6 se reemplaza por MLD – Multicast Listener Discovery).
- Permite que un host informe a los routers cercanos que **quiere recibir tráfico multicast** de un grupo concreto (por ejemplo, `224.0.0.1`).
- No transporta datos; solo gestiona la **participación en grupos multicast**.

---

### 📦 ¿Cómo funciona IGMP?

1. Un host quiere unirse a un grupo multicast → **envía un mensaje IGMP Membership Report**.
2. El router detecta ese mensaje y **empieza a reenviar tráfico** para ese grupo a la red local.
3. Si el host ya no desea recibir tráfico → **se puede enviar un Leave Group** (en IGMPv2+).
4. El router puede enviar periódicamente **queries IGMP** para verificar qué hosts siguen interesados.

---

### 🔢 Versiones de IGMP

| Versión   | Características clave                                             |
|-----------|--------------------------------------------------------------------|
| IGMPv1    | Básico, sin Leave Group                                            |
| IGMPv2    | Soporta Leave Group y tiempo de espera ajustable                  |
| IGMPv3    | Permite filtrar por fuentes específicas (source-specific multicast)|

---

### 👨‍💻 Relevancia para backend

- Aunque como desarrollador backend **no configures IGMP directamente**, puede afectarte si:
  - Usas servicios que **dependen de multicast** (descubrimiento, streaming, protocolos distribuidos).
  - Trabajas en sistemas embebidos, IoT, o redes locales cerradas.
  - Estás debugueando tráfico multicast que **no llega a tu servicio** (porque tu host no está inscrito en el grupo).

- Muchos **contenedores o máquinas virtuales** no manejan bien IGMP por defecto, lo que puede romper servicios multicast internos.

---

### 🛠️ Comandos / herramientas útiles

| Comando / Herramienta             | Función                                                                 |
|----------------------------------|--------------------------------------------------------------------------|
| `ip maddr`                       | Ver los grupos multicast a los que la interfaz está suscrita            |
| `netstat -g`                     | Ver membresías multicast actuales                                       |
| `tcpdump igmp`                   | Captura mensajes IGMP                                                   |
| `ping 224.0.0.1`                 | Ver si otros hosts responden a una IP multicast estándar                |
| `smcroute`, `igmpproxy`, `avahi-daemon` | Herramientas para gestionar multicast y proxies IGMP                |

---

### 🧪 Ejemplos prácticos

#### 🔧 `ip maddr`

✅ **Qué hace:**  
Muestra los grupos multicast a los que está suscrita cada interfaz de red.

```bash
eth0
    link  01:00:5e:00:00:01
    inet  224.0.0.1
    inet  239.255.255.250
```
🧠 **Comentario:**  
Tu interfaz `eth0` está suscrita a múltiples grupos multicast (como mDNS o SSDP).

#### 🔧 `netstat -g`

✅ **Qué hace:**  
Muestra membresías multicast activas a nivel de sistema.


```bash
IPv4 Multicast Group Memberships
Interface       RefCnt Group
--------------- ------ ---------------------
eth0            1      224.0.0.1
eth0            1      239.255.255.250
```
🧠 **Comentario:**  
Aquí ves qué grupos están activos y en qué interfaz.

---
#### 🔧 `tcpdump igmp`

✅ **Qué hace:**  
Captura mensajes IGMP en tiempo real (Membership Report, Leave, etc.).

```bash
IP 192.168.1.45 > 224.0.0.1: igmp query v2
IP 192.168.1.45 > 224.0.0.251: igmp report v2
```

🧠 **Comentario:**  
Puedes ver cuándo tu sistema se une o deja un grupo multicast, o responde a queries de un router.

---

#### 🔧 `ping 224.0.0.1`

✅ **Qué hace:**  
Envía ICMP multicast a todos los hosts que escuchen ese grupo.

```bash
64 bytes from 192.168.1.34: icmp_seq=1 ttl=1 time=1.9 ms
``` 

🧠 **Comentario:**  
Ves qué otros hosts en tu red responden a solicitudes multicast.

---

## 📘 Capítulo 14: DNS – Domain Name System

### 🧠 Lo esencial que debes saber

- **DNS** (Domain Name System) es el sistema encargado de **resolver nombres de dominio (como google.com) en direcciones IP** (como 142.250.190.14).
- Es fundamental en toda comunicación de red: sin DNS, necesitarías recordar IPs en lugar de nombres.
- DNS utiliza generalmente **UDP puerto 53**, aunque puede usar TCP para respuestas grandes o transferencia de zonas.
- Es una arquitectura distribuida, jerárquica y en forma de árbol.

---

### 🧩 Cómo funciona una consulta DNS

1. El cliente pregunta a su **servidor DNS configurado localmente** (generalmente un router o 8.8.8.8).
2. Si ese servidor no tiene la respuesta en caché, realiza una **consulta recursiva**:
   - Contacta a los **root servers** → `.`
   - Luego a los **servidores TLD** → `.com`
   - Luego al **servidor autoritativo** → `example.com`
3. La IP final se devuelve al cliente, que puede entonces hacer su conexión (ej. HTTP, SMTP...).

---

### 📦 Tipos comunes de registros DNS

| Tipo  | Descripción                                      |
|-------|--------------------------------------------------|
| A     | Dirección IPv4                                   |
| AAAA  | Dirección IPv6                                   |
| CNAME | Alias de otro dominio                            |
| MX    | Servidor de correo                               |
| NS    | Nameserver autorizado                            |
| PTR   | Resolución inversa (IP → nombre)                 |
| TXT   | Información arbitraria (SPF, verificación, etc.) |

---

### 👨‍💻 Relevancia para backend

- Toda comunicación entre servicios **usará DNS**, ya sea dentro o fuera del clúster o red.
- Muchos errores en apps backend se deben a:
  - **Timeouts DNS**
  - **Resolución incorrecta**
  - **Cambios de IP sin actualización de caché**
- DNS mal configurado en contenedores, Kubernetes, o VPNs puede romper microservicios.
- Puedes usar DNS para:
  - Balanceo de carga básico
  - Alta disponibilidad (fallbacks)
  - Discovery dinámico

---

## 🛠️ Comandos / herramientas útiles

| Comando / Herramienta            | Función                                                               |
|----------------------------------|-----------------------------------------------------------------------|
| `dig <dominio>`                  | Consulta DNS detallada (muy completa)                                 |
| `nslookup <dominio>`            | Consulta básica de nombre a IP                                        |
| `host <dominio>`                 | Consulta simple, salida compacta                                      |
| `ping <dominio>`                 | Prueba conectividad y resolución                                      |
| `resolvectl status` / `systemd-resolve` | Ver el DNS configurado actualmente en sistemas modernos         |
| `tcpdump port 53`               | Captura tráfico DNS                                                   |

---

### 🧪 Ejemplos prácticos

---

#### 🔧 `dig openai.com`

✅ **Qué hace:**  
Consulta DNS al servidor configurado y muestra toda la información.

```bash
; <<>> DiG 9.16.1 <<>> openai.com
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345
;; QUESTION SECTION:
;openai.com.            IN    A

;; ANSWER SECTION:
openai.com.     299     IN    A    104.18.12.123
```
🧠 **Comentario:**  
`dig` da detalles útiles: TTL, tipo de registro, autoridad, etc. Ideal para depurar.


#### 🔧 `nslookup google.com`

✅ **Qué hace:**  Consulta rápida y fácil, útil en casi cualquier sistema.

```bash
Server:  192.168.1.1
Address: 192.168.1.1#53 Non-authoritative answer:
Name: google.com
Address: 142.250.190.14
``` 

🧠 **Comentario:**  Menos detallado que `dig`, pero rápido y disponible incluso en Windows.

#### 🔧 `host github.com`

✅ **Qué hace:**  
Consulta DNS con salida concisa.

```bash
github.com has address 140.82.114.4
``` 

🧠 **Comentario:**  
Perfecto para scripts o verificaciones rápidas.

----------

#### 🔧 `ping openai.com`

✅ **Qué hace:**  
Hace una consulta DNS y luego intenta conectar por ICMP.

```bash
PING openai.com (104.18.12.123): 56 data bytes
64 bytes from 104.18.12.123: icmp_seq=0 ttl=57 time=12.3 ms
``` 

🧠 **Comentario:**  
Confirmas que el dominio resuelve y es accesible.

----------

#### 🔧 `resolvectl status`

✅ **Qué hace:**  
Muestra qué servidores DNS está usando tu sistema actualmente (Linux + systemd).

```bash
Current DNS Server: 192.168.1.1
DNS Servers: 192.168.1.1
DNSSEC supported: yes
``` 

🧠 **Comentario:**  
Útil para ver si estás usando el DNS de la red, uno externo como 8.8.8.8 o uno local.


## 📘 Capítulo 15: TFTP – Trivial File Transfer Protocol

### 🧠 Lo esencial que debes saber

- **TFTP** es un protocolo de transferencia de archivos **muy simple**, diseñado para sistemas **ligeros o embebidos**.
- Funciona sobre **UDP (puerto 69)**, lo que lo hace rápido pero sin fiabilidad incorporada como TCP.
- Fue diseñado para:
  - **Cargar firmware o sistemas operativos** (ej. por red en dispositivos sin disco)
  - **Transferencias sencillas sin autenticación**
- Es un protocolo **sin estado** y muy limitado.

---

### 📦 Características clave de TFTP

| Característica      | Descripción                                               |
|---------------------|-----------------------------------------------------------|
| Protocolo base      | UDP (puerto 69)                                           |
| Seguridad           | No tiene autenticación ni cifrado                         |
| Fiabilidad          | Requiere ACKs y reintentos manuales                       |
| Uso principal       | Boot por red (PXE), dispositivos embebidos, routers       |
| Comandos soportados | RRQ (read), WRQ (write), DATA, ACK, ERROR                 |

🧠 **Importante:** Debido a su simplicidad y falta de seguridad, **TFTP solo se recomienda en redes internas controladas.**

---

### 👨‍💻 Relevancia para backend

- No se usa directamente en backend moderno, pero **puede estar presente en entornos industriales, IoT, routers o BIOS PXE boot**.
- Si trabajas cerca del hardware, firmware, arranque de red o sistemas embebidos, **te cruzarás con TFTP**.
- Es útil para:
  - **Cargar configuraciones o firmware**
  - Depurar cargas PXE que fallan

---

### 🛠️ Comandos / herramientas útiles

| Herramienta / Comando       | Función                                                        |
|-----------------------------|-----------------------------------------------------------------|
| `tftp <host>`               | Cliente TFTP interactivo                                       |
| `tftp -g -r <archivo> <host>` | Descarga (`get`) un archivo desde un servidor TFTP            |
| `tftp -p -l <archivo> <host>` | Sube (`put`) un archivo a un servidor TFTP                    |
| `tcpdump port 69`           | Captura tráfico TFTP                                           |
| `atftpd`, `tftpd-hpa`       | Servidores TFTP en Linux                                       |

---

### 🧪 Ejemplos prácticos

---

#### 🔧 `tftp 192.168.1.100`

✅ **Qué hace:**  Inicia una sesión interactiva TFTP con el host.

```bash
tftp> get firmware.bin
Received 245760 bytes in 2.0 seconds
tftp> quit
```
🧠 **Comentario:**  
Descarga de archivo desde un servidor TFTP local, sin autenticación ni cifrado.

#### 🔧 `tftp -g -r config.txt 192.168.1.100`

✅ **Qué hace:**  
Descarga el archivo `config.txt` del servidor `192.168.1.100`.

`config.txt received successfully` 

🧠 **Comentario:**  
Opción muy usada en scripts o procesos automáticos de configuración.


#### 🔧 `tftp -p -l init.cfg 192.168.1.100`

✅ **Qué hace:**  Sube el archivo `init.cfg` al servidor TFTP.

`Sent 3 blocks, 512 bytes per block` 

🧠 **Comentario:**  
No hay control de acceso, así que es importante **no usarlo en redes abiertas**.

----------

#### 🔧 `tcpdump port 69`

✅ **Qué hace:**  
Captura el tráfico TFTP (UDP puerto 69).

`192.168.1.45.43256 > 192.168.1.100.69:  25 RRQ "firmware.bin" octet
192.168.1.100.69 > 192.168.1.45.43256: DATA block 1 (512 bytes)` 

🧠 **Comentario:**  
Muy útil para verificar si la transferencia se inicia correctamente.


## 📘 Capítulo 16: BOOTP – Bootstrap Protocol

### 🧠 Lo esencial que debes saber

- **BOOTP (Bootstrap Protocol)** permite que un dispositivo sin disco (o sin configuración IP) obtenga automáticamente:
  - Su dirección IP
  - La dirección de su servidor de arranque
  - La ubicación de un archivo de arranque (ej. para cargar vía TFTP)

- BOOTP fue diseñado para equipos que arrancan por red y **no tienen almacenamiento persistente**.

- Usa **UDP**:
  - Cliente → Servidor: puerto 67
  - Servidor → Cliente: puerto 68

---

### 📦 Características principales

| Característica      | Valor                                 |
|---------------------|----------------------------------------|
| Protocolo base      | UDP (67/68)                            |
| Método de asignación| Manual (basado en la MAC del cliente)  |
| Función clave       | Proveer IP y parámetros de arranque    |
| Respuesta esperada  | IP, gateway, servidor TFTP, ruta del archivo de arranque |

🧠 **Importante:** BOOTP fue el precursor de **DHCP**, que lo reemplazó al añadir asignación dinámica y más opciones.

---

### 👨‍💻 Relevancia para backend

- Aunque **ya casi no se usa en entornos modernos**, BOOTP puede estar presente en:
  - Entornos industriales / IoT antiguos
  - Arranque de red (PXE boot)
  - Laboratorios de virtualización o BIOS legacy

- Si trabajas en:
  - Automatización de sistemas base
  - Dispositivos embebidos
  - Provisionamiento de hardware desde cero

  ...entender BOOTP te ayudará a **interpretar arranques por red y logs tempranos**.

---

### 🛠️ Comandos / herramientas útiles

| Herramienta / Comando       | Función                                                       |
|-----------------------------|----------------------------------------------------------------|
| `tcpdump port 67 or port 68`| Captura tráfico BOOTP/DHCP                                     |
| `dnsmasq` / `isc-dhcp-server`| Pueden actuar como servidores BOOTP (con opción TFTP)         |
| `pxelinux.0` / `bootfile`   | Archivo de arranque que se entrega junto con BOOTP            |
| `tftp`                      | BOOTP suele usarse junto con TFTP para transferir archivos     |

---

### 🧪 Ejemplos prácticos

#### 🔧 `tcpdump port 67 or port 68`

✅ **Qué hace:**  Captura mensajes BOOTP en la red.

```bash
IP 0.0.0.0.68 > 255.255.255.255.67: BOOTP/DHCP, Request from 08:00:27:12:34:56
IP 192.168.1.1.67 > 192.168.1.10.68: BOOTP/DHCP, Reply, IP 192.168.1.10
```
🧠 **Comentario:**  
El cliente no tiene IP, así que envía desde `0.0.0.0` a broadcast. El servidor le asigna una IP válida.

#### 🔧 Configuración de `dnsmasq` para BOOTP

✅ **Qué hace:**  Actúa como servidor BOOTP + TFTP.

```bash
dhcp-boot=pxelinux.0
enable-tftp
tftp-root=/srv/tftp
``` 

🧠 **Comentario:**  
Con esta configuración, `dnsmasq` responde a solicitudes BOOTP y ofrece el archivo de arranque `pxelinux.0` por TFTP.


#### 🔧 Respuesta BOOTP típica

```bash
Your IP: 192.168.1.50
Server IP: 192.168.1.1
Bootfile: pxelinux.0
Next server: 192.168.1.1
``` 

🧠 **Comentario:**  
El cliente ahora puede descargar el archivo de arranque desde el servidor especificado.

#### 🔧 Archivo de arranque por TFTP (`pxelinux.0`)

✅ **Qué hace:**  BOOTP solo dice dónde está el archivo, pero **TFTP lo transfiere**.

```bash
192.168.1.50.12345 > 192.168.1.1.69: 25 RRQ "pxelinux.0" octet
``` 

🧠 **Comentario:**  
Esta es la siguiente etapa tras recibir la IP y el archivo de arranque. BOOTP + TFTP = PXE boot funcional.

## 📘 Capítulo 17: TCP – Transmission Control Protocol

### 🧠 Lo esencial que debes saber
- **TCP** es un protocolo de transporte confiable, orientado a conexión.
- Garantiza:
  - Entrega **sin errores**
  - Entrega **en orden**
  - **Evita duplicados**
- Se usa para la mayoría de aplicaciones backend: **HTTP(S), SMTP, FTP, SSH, SQL, etc.**
- Opera sobre IP, pero añade:
  - Control de flujo
  - Retransmisiones
  - Confirmaciones (ACK)
  - Control de congestión

---

### 📦 Cabecera TCP (campos importantes)

| Campo             | Descripción                                      |
|------------------|--------------------------------------------------|
| Source Port      | Puerto de origen                                 |
| Destination Port | Puerto de destino                                |
| Sequence Number  | Número de secuencia del primer byte              |
| Acknowledgment # | Confirma recepción de bytes anteriores           |
| Flags            | Control de la conexión: SYN, ACK, FIN, RST...    |
| Window Size      | Control de flujo: cuántos bytes puede recibir    |
| Checksum         | Verificación de errores                          |

---

### 🔁 Cómo funciona una conexión TCP

1. **Three-way handshake**:
   - Cliente envía `SYN`
   - Servidor responde `SYN-ACK`
   - Cliente responde `ACK`
2. Luego los datos se intercambian en segmentos.
3. La conexión se cierra con `FIN` / `ACK`.

🧠 TCP **mantiene estado** en ambos extremos de la conexión.

---

### 👨‍💻 Relevancia para backend

- Casi todo backend moderno se basa en TCP:
  - APIs REST, servicios gRPC, bases de datos, microservicios
- Conocer TCP ayuda a:
  - **Diagnosticar timeouts y caídas de conexión**
  - Saber si tu servicio está saturado (ventana TCP llena)
  - Entender el efecto de la **latencia y pérdida de paquetes**
  - Optimizar **sockets** y conexiones en apps de alto rendimiento

---

### 🛠️ Comandos / herramientas útiles

| Herramienta / Comando         | Función                                                                 |
|-------------------------------|-------------------------------------------------------------------------|
| `ss -t -a`                    | Ver conexiones TCP activas                                             |
| `netstat -tn`                 | Ver conexiones TCP sin resolución DNS                                 |
| `tcpdump tcp`                 | Capturar tráfico TCP                                                   |
| `telnet <host> <puerto>`      | Probar conexión TCP simple                                             |
| `curl -v` / `nc`              | Ver detalles de conexión (handshake, headers, etc.)                   |

---

### 🧪 Ejemplos prácticos

#### 🔧 `ss -t -a`

✅ **Qué hace:**  Muestra todas las conexiones TCP abiertas o en escucha.

```bash
State      Recv-Q Send-Q Local Address:Port   Peer Address:Port
LISTEN     0      128    0.0.0.0:80           0.0.0.0:*
ESTAB      0      0      192.168.1.50:22      192.168.1.30:53200
```
🧠 **Comentario:**  Puedes ver servicios escuchando (ej. HTTP, SSH) y sesiones establecidas.


#### 🔧 `tcpdump tcp port 80`

✅ **Qué hace:**  Captura tráfico HTTP (TCP puerto 80).

`IP 192.168.1.50.53200 > 93.184.216.34.80: Flags [S], seq 0, win 64240` 

🧠 **Comentario:**  Aquí empieza una conexión TCP con `SYN`. Puedes seguir el handshake completo si capturas más tráfico.

----------

#### 🔧 `telnet example.com 80`

✅ **Qué hace:**  Inicia una conexión TCP a un puerto (como HTTP).

```bash
Trying 93.184.216.34...
Connected to example.com.
``` 

🧠 **Comentario:**  Útil para comprobar si un puerto TCP está accesible (aunque el protocolo no sea Telnet).

----------

#### 🔧 `curl -v http://example.com`

✅ **Qué hace:**  Muestra el proceso de conexión TCP + petición HTTP.

```bash
*   Trying 93.184.216.34:80...
* Connected to example.com
> GET / HTTP/1.1
> Host: example.com
``` 

🧠 **Comentario:**  
Combina visibilidad de TCP + HTTP. Muy útil para backend.

----------

#### 🔧 `netstat -tn`

✅ **Qué hace:**  Muestra conexiones TCP activas sin resolver DNS.

`tcp        0      0 192.168.1.50:54321   93.184.216.34:443   ESTABLISHED` 

🧠 **Comentario:**  Ideal para ver conexiones reales en producción o contenedores sin overhead de resolución.


## 📘 Capítulo 18: TCP Connection Establishment – Three-Way Handshake

### 🧠 Lo esencial que debes saber

- El establecimiento de una conexión TCP se realiza mediante el **three-way handshake** ("apretón de manos en tres pasos").
- Este mecanismo permite:
  - Confirmar que ambos extremos están vivos
  - Sincronizar números de secuencia
  - Preparar el canal confiable para intercambiar datos

---

### 🔁 Proceso del three-way handshake

| Paso | Cliente                | Servidor                     |
|------|------------------------|------------------------------|
| 1    | Envía `SYN`            |                              |
| 2    |                        | Recibe `SYN`, responde `SYN-ACK` |
| 3    | Recibe `SYN-ACK`, responde `ACK` | Servidor recibe `ACK` |

🧠 **Resultado:**  
Ambos extremos conocen los números de secuencia y están listos para enviar datos.

---

### 📦 Campos relevantes en la cabecera TCP

| Campo            | Función                                         |
|------------------|--------------------------------------------------|
| `SYN`            | Solicita conexión e inicia secuencia            |
| `ACK`            | Confirma recepción de datos o solicitud         |
| `Sequence Number`| Número inicial elegido aleatoriamente           |
| `Window`         | Tamaño de ventana (control de flujo)            |

---

### 🔄 Ejemplo de secuencia (simplificada)

```bash
Cliente → Servidor: SYN, Seq=100
Servidor → Cliente: SYN-ACK, Seq=200, Ack=101
Cliente → Servidor: ACK, Seq=101, Ack=201
```

### 👨‍💻 Relevancia para backend

-   Entender el handshake es clave para:
    
    -   Diagnosticar **latencia en el establecimiento de conexión**
        
    -   Detectar **conexiones a medio abrir (SYN flood)**
        
    -   Depurar problemas de servicios que **no responden a conexiones entrantes**
        
-   Las herramientas de observabilidad y firewalls **pueden filtrar conexiones SYN** maliciosas.

### 🛠️ Comandos / herramientas útiles

| Comando / Herramienta                                | Función                                                                 |
|------------------------------------------------------|-------------------------------------------------------------------------|
| `tcpdump 'tcp[tcpflags] & tcp-syn != 0'`             | Captura paquetes TCP con flag SYN (inicio de conexión)                 |
| `ss -t state syn-recv`                               | Muestra conexiones en estado `SYN-RECV` (esperando último ACK)         |
| `netstat -nat`                                       | Lista conexiones TCP con sus estados (LISTEN, SYN_SENT, etc.)          |
| `iptables -A INPUT -p tcp --syn -j ACCEPT`           | Permite explícitamente paquetes SYN entrantes                          |
| `ufw allow proto tcp from any to any port 80`        | Permite conexiones TCP entrantes al puerto 80 (usando UFW)             |



### 🧪 Ejemplos prácticos

----------

#### 🔧 `tcpdump 'tcp[tcpflags] & (tcp-syn) != 0'`

✅ **Qué hace:**  
Muestra todos los paquetes que contienen el flag `SYN`.

bash

Copiar

`IP 192.168.1.100.54321 > 93.184.216.34.443: Flags [S], seq 0, win 64240` 

🧠 **Comentario:**  
Captura el primer paso del handshake TCP. Ideal para comprobar si un cliente intenta conectarse.

----------

#### 🔧 `ss -t state syn-recv`

✅ **Qué hace:**  
Muestra conexiones TCP que están **esperando el ACK final del cliente**.

```bash
Recv-Q Send-Q Local Address:Port Peer Address:Port
0      0      192.168.1.80:443     192.168.1.50:56234
``` 

🧠 **Comentario:**  Un ataque SYN flood dejaría muchas conexiones aquí sin completarse.

----------

#### 🔧 `netstat -nat`

✅ **Qué hace:**  Muestra todas las conexiones TCP con su estado.


```bash
tcp  0  0 0.0.0.0:443  0.0.0.0:*  LISTEN
tcp  0  0 192.168.1.80:443  192.168.1.50:56234  ESTABLISHED
``` 

🧠 **Comentario:**  
Puedes ver conexiones establecidas o en proceso de establecimiento.




## 📘 Capítulo 11: tcpdump – Herramienta de captura de paquetes

### 🧠 Lo esencial que debes saber

- `tcpdump` es una herramienta de línea de comandos para **capturar y analizar paquetes** de red en tiempo real.
- Te permite observar el tráfico **desde y hacia tu máquina** en diferentes capas: IP, TCP, UDP, ICMP, ARP, etc.
- Es extremadamente útil para:
  - Depurar problemas de red
  - Ver qué paquetes están saliendo o entrando en tu app
  - Analizar protocolos (DNS, HTTP, TLS…)

---

### 🔍 ¿Qué puede mostrarte tcpdump?

- Direcciones IP de origen y destino
- Puertos de aplicación (ej. 443, 80)
- Flags TCP (SYN, ACK, FIN…)
- Protocolos usados (ICMP, DNS, TLS, etc.)
- Tramas ARP o solicitudes DHCP
- Payload (contenido del paquete) si se desea

---

### 👨‍💻 Relevancia para backend

- Ideal para ver si tu **servicio está recibiendo peticiones** o si hay **errores de red (timeouts, pérdidas)**.
- Puedes observar si una app realmente está haciendo requests (p. ej., microservicios, llamadas HTTP).
- Es crucial en debugging de **conectividad, DNS, SSL/TLS**, o incluso ataques de red.

---

### 🛠️ Comandos / opciones útiles

| Comando                                | Descripción                                                           |
|----------------------------------------|-----------------------------------------------------------------------|
| `sudo tcpdump -i <iface>`              | Captura todo el tráfico de la interfaz                               |
| `sudo tcpdump -n`                      | No resuelve nombres DNS ni de puertos (más rápido)                   |
| `sudo tcpdump port 80`                 | Solo tráfico HTTP (puerto 80)                                        |
| `sudo tcpdump tcp`                     | Solo tráfico TCP                                                     |
| `sudo tcpdump -X port 80`              | Muestra también el contenido (payload) de cada paquete HTTP          |
| `sudo tcpdump -i lo`                   | Captura tráfico entre procesos locales (loopback)                    |

---

### 🧪 Ejemplos prácticos

#### 🔧 `sudo tcpdump -i eth0`

✅ **Qué hace:**  Muestra todo el tráfico de la interfaz de red principal (`eth0`).

📤 **Salida típica:**
```bash
IP 192.168.1.45.54321 > 93.184.216.34.443: Flags [S], seq 0, win 29200, length 0
```

🧠 **Comentario:**  
Un paquete TCP saliendo hacia el puerto 443 (HTTPS). Puedes ver flags como `S` (SYN), `P` (Push), `F` (FIN), etc.

---

### 🔧 `sudo tcpdump port 53`

✅ **Qué hace:**  Filtra solo el tráfico DNS (puerto 53).

📤 **Salida típica:**
```bash
IP 192.168.1.45.53536 > 8.8.8.8.53: 12345+ A? google.com. (28)
```

🧠 **Comentario:**  
Muestra una solicitud DNS preguntando por la IP de `google.com`.

---

### 🔧 `sudo tcpdump -X port 80`

✅ **Qué hace:**  Muestra tráfico HTTP con el contenido del paquete en formato hexadecimal + ASCII.

📤 **Salida típica:**
```bash
GET / HTTP/1.1 Host: example.com User-Agent: curl/7.68.0
```

🧠 **Comentario:**  
Perfecto para ver qué datos envía tu app al servidor (headers, cuerpo de petición, etc.).

---

### 🔧 `sudo tcpdump -n -i lo`

✅ **Qué hace:**  Muestra tráfico en la interfaz loopback (`localhost`), sin resolver nombres de dominio o puertos.

📤 **Salida típica:**
```bash
IP 127.0.0.1.5000 > 127.0.0.1.8080: Flags [P.], length 64
```

🧠 **Comentario:**  
Útil cuando estás debugueando microservicios que se comunican entre sí en tu propio sistema.

---

### 🔧 `sudo tcpdump -i eth0 icmp`

✅ **Qué hace:**  Filtra tráfico ICMP (como ping o traceroute).

📤 **Salida típica:**
```bash
IP 192.168.1.45 > 8.8.8.8: ICMP echo request, id 12345, seq 1 IP 8.8.8.8 > 192.168.1.45: ICMP echo reply, id 12345, seq 1
```

🧠 **Comentario:**  Muy útil para depurar conectividad básica y respuestas a `ping`.

---

## 📘 Capítulo 20: TCP – Bulk Data Flow

### 🧠 Lo esencial que debes saber

- Este capítulo analiza cómo TCP gestiona **transferencias de datos grandes** (bulk transfers), como:
  - Descarga de archivos grandes
  - Transferencia de bases de datos
  - Streams multimedia de gran tamaño
- A diferencia de flujos interactivos, aquí lo importante es **eficiencia y rendimiento**, más que latencia inmediata.

---

### ⚙️ Mecanismos clave en flujo de datos grandes

| Mecanismo             | Descripción                                                                 |
|------------------------|-----------------------------------------------------------------------------|
| **Ventana de recepción (rwnd)** | Cuántos bytes puede recibir el host destino sin desbordar su buffer  |
| **Ventana de congestión (cwnd)**| TCP limita la cantidad de datos enviados para evitar congestión      |
| **Slow Start**         | TCP comienza con una ventana pequeña y la incrementa exponencialmente      |
| **Retransmisión rápida**| Reenvía paquetes perdidos sin esperar el timeout completo (si recibe 3 ACKs duplicados) |
| **TCP Flow Control**   | Controla el ritmo de envío según capacidad del receptor                    |
| **TCP Congestion Control** | Controla el ritmo según el estado de la red                            |

---

### 🔁 Flujo típico de una transferencia grande

1. Se establece conexión (3-way handshake)
2. TCP empieza con **slow start**
3. A medida que no hay pérdidas, aumenta la ventana (más rendimiento)
4. Si detecta congestión → reduce velocidad y se recupera

🧠 TCP **se adapta dinámicamente** a las condiciones de la red y del receptor.

---

### 👨‍💻 Relevancia para backend

- Afecta directamente a:
  - APIs que **descargan o suben archivos grandes**
  - **Backups y restauraciones** por red
  - **Bases de datos distribuidas**
  - Comunicación entre microservicios que comparten datos masivos

- Problemas típicos:
  - **Pérdidas de paquetes** → bajada drástica de cwnd
  - Mala configuración de buffers → **rendimiento limitado**
  - **Firewalls o balanceadores** con timeout bajo → cierre de conexiones largas

---

### 🛠️ Comandos / herramientas útiles

| Comando / Herramienta                    | Función                                                            |
|------------------------------------------|---------------------------------------------------------------------|
| `ss -t -i`                                | Ver parámetros como cwnd, rtt, retransmisiones                     |
| `iperf3 -c <host>`                        | Medir rendimiento de TCP en bulk transfers                         |
| `tcpdump`                                 | Ver tamaño de segmentos, retransmisiones, ACKs                     |
| `netstat -s`                              | Ver estadísticas globales TCP, retransmisiones, congestión         |
| `sysctl -a | grep tcp_window_scaling`     | Ver si la escala de ventanas está activada (clave para alto rendimiento) |

---

### 🧪 Ejemplos prácticos

#### 🔧 `ss -t -i`

✅ **Qué hace:**  
Muestra detalles técnicos de conexiones TCP activas.

```bash
cwnd: 23, rtt: 34.5 ms, retrans: 1
```
🧠 **Comentario:**  
El tamaño de la ventana de congestión (`cwnd`) es clave en transferencias masivas. Cuanto más alto, más rendimiento.

#### 🔧 `iperf3 -c <servidor>`

✅ **Qué hace:**  Testea el rendimiento de una conexión TCP con envío sostenido.


```bash
[ ID] Interval           Transfer     Bandwidth
[  5]   0.00-10.00 sec  1.10 GBytes  944 Mbits/sec
``` 

🧠 **Comentario:**  
Excelente para medir throughput real en bulk transfers (¡útil en tuning de red!).

----------

#### 🔧 `tcpdump -i eth0 tcp`

✅ **Qué hace:**  
Analiza si hay pérdidas o retransmisiones durante una descarga masiva.

```bash
IP ... Flags [P.], length 1448
IP ... Retransmission
``` 

🧠 **Comentario:**  Puedes ver si hay paquetes perdidos, lo cual limita la velocidad por caída de cwnd.

----------

#### 🔧 `netstat -s`

✅ **Qué hace:**  
Muestra estadísticas del stack TCP.

```bash
4560 segments retransmitted
120 fast retransmits
``` 

🧠 **Comentario:**  
Si hay muchas retransmisiones, hay pérdida de rendimiento. Puede que la red esté saturada o inestable.

----------

#### 🔧 `sysctl net.ipv4.tcp_window_scaling`

✅ **Qué hace:**  
Indica si tu sistema soporta ventanas grandes (para redes de alto rendimiento).

```bash
net.ipv4.tcp_window_scaling = 1
``` 

🧠 **Comentario:**  
En redes modernas con alta latencia (como cloud + S3), sin esto activado **se limita el rendimiento** TCP.


## 📘 Capítulo 21: TCP Timeout and Retransmission

### 🧠 Lo esencial que debes saber

- TCP garantiza la entrega de datos mediante un sistema de **retransmisión con temporizadores (timeouts)**.
- Si un paquete no es **confirmado (ACK)** dentro de cierto tiempo → se **retransmite**.
- El temporizador **se ajusta dinámicamente** según la latencia real (RTT).
- TCP también aplica técnicas para **detectar pérdidas más rápidamente** que un simple timeout.

---

### 🔁 Proceso de retransmisión TCP

1. Se envía un segmento.
2. Si no se recibe ACK antes del **RTO (Retransmission Timeout)** → se retransmite.
3. TCP **duplica el RTO** en cada fallo (exponencial backoff).
4. Si se reciben **ACKs duplicados** → se activa **Fast Retransmit** (antes del timeout).

---

### ⚙️ Mecanismos involucrados

| Mecanismo             | Descripción                                                                 |
|------------------------|-----------------------------------------------------------------------------|
| **RTO (Retransmission Timeout)** | Tiempo máximo esperado para el ACK de un paquete                   |
| **RTT (Round-Trip Time)**        | Tiempo real de ida y vuelta, medido dinámicamente                 |
| **Fast Retransmit**              | Si se reciben 3 ACKs duplicados, se considera pérdida inmediata    |
| **Exponential Backoff**          | Cada retransmisión duplica el RTO → evita saturar la red          |
| **SACK (Selective Acknowledgment)** | Permite al receptor informar de qué bloques recibió               |

---

### 👨‍💻 Relevancia para backend

- Ayuda a entender:
  - Por qué algunas peticiones **parecen congelarse** → retransmisiones ocultas
  - Por qué una conexión **no se rompe inmediatamente** ante fallo → espera de timeout
  - Por qué **microservicios pueden experimentar retrasos esporádicos** en redes inestables
- Algunas **librerías o proxies** pueden aplicar timeouts más agresivos que TCP → diferencias entre comportamiento de red y app

---

### 🛠️ Comandos / herramientas útiles

| Comando / Herramienta            | Función                                                             |
|----------------------------------|----------------------------------------------------------------------|
| `ss -ti`                         | Ver información de conexiones, incluido RTO y retransmisiones       |
| `netstat -s`                     | Ver estadísticas de retransmisiones y timeouts                      |
| `tcpdump tcp`                    | Ver retransmisiones reales y ACKs duplicados                        |
| `iperf3 --retrans`               | Ver tasa de retransmisión bajo carga                                |
| `sysctl net.ipv4.tcp_retries2`   | Cambiar cuánto espera TCP antes de cerrar una conexión rota         |

---

### 🧪 Ejemplos prácticos

#### 🔧 `ss -ti`

✅ **Qué hace:**  
Muestra detalles técnicos de las conexiones TCP, incluyendo retransmisiones.

```bash
cwnd: 10, rtt: 45.6 ms, rto: 200ms, retrans: 1
```

🧠 **Comentario:**  
RTO indica cuánto espera TCP antes de retransmitir. Si hay retransmisiones frecuentes, podría haber congestión o pérdida.

---

### 🔧 `netstat -s`

✅ **Qué hace:**  Muestra estadísticas acumuladas de TCP.

`450 segments retransmitted
120 connections reset due to timeout` 

🧠 **Comentario:**  
Te da una visión general del comportamiento de TCP en el sistema. Buena herramienta de diagnóstico global.

----------

#### 🔧 `tcpdump 'tcp[13] & 0x10 != 0'`

✅ **Qué hace:**  Captura segmentos con el flag ACK, útiles para analizar duplicados.

```bash
IP ... ack 3001 win 512
IP ... ack 3001 win 512
IP ... ack 3001 win 512  ← ACK duplicados
``` 

🧠 **Comentario:**  Si ves múltiples ACKs iguales → podría activarse **Fast Retransmit**.

----------

#### 🔧 `iperf3 --retrans` (modo servidor)

✅ **Qué hace:**  
Mide retransmisiones durante un test de rendimiento.

```bash
[ ID] Interval  Transfer   Bandwidth   Retr
[  4] 0.0-10.0s  1.0 GBytes  850 Mbits/s  32
``` 

🧠 **Comentario:**  
Si hay muchos `Retr`, tu red o el stack TCP están teniendo problemas. Útil para tuning.

----------

#### 🔧 `sysctl net.ipv4.tcp_retries2`

✅ **Qué hace:**  
Controla cuántos reintentos hace TCP antes de **cerrar** la conexión (por defecto: 15 → ~13 minutos).

`net.ipv4.tcp_retries2 = 15` 

🧠 **Comentario:**  
Si tienes servicios que tardan en caer o colgar conexiones, puedes reducir esto para cerrar más rápido.



## 📘 Capítulo 22: TCP Persist Timer

### 🧠 Lo esencial que debes saber

- El **persist timer** de TCP se activa cuando el receptor **anuncia una ventana de recepción de 0 bytes (rwnd = 0)**.
- Esto significa que **el receptor no puede aceptar más datos**, así que el emisor **debe detener el envío**.

🧠 Pero… si el receptor **olvida avisar** cuando vuelve a tener espacio → la conexión quedaría congelada indefinidamente.

➡️ Para evitar esto, TCP usa el **persist timer**, que:
- Fuerza al emisor a enviar pequeños paquetes ("probes") de vez en cuando.
- Así el receptor puede notificar si **ya tiene espacio disponible** en su buffer.

---

### 🔁 Flujo de uso del persist timer

1. El receptor envía un ACK con **ventana cero (rwnd = 0)**.
2. El emisor **detiene el envío de datos**.
3. Se activa el **persist timer**.
4. Cuando el timer expira, el emisor envía un **probe** (un byte no válido).
5. El receptor responde con su nueva **ventana de recepción**.
6. Si rwnd > 0, el envío se reanuda.

---

### 🛑 ¿En qué se diferencia de otros timers?

| Timer             | Función                                                                 |
|-------------------|-------------------------------------------------------------------------|
| **RTO (Retransmission Timeout)** | Retransmitir si no hay ACK                                 |
| **Keepalive**      | Detectar si la conexión aún está viva (inactiva)                        |
| **Persist Timer**  | Detectar si la **ventana cero sigue siendo cero**                      |

🧠 El persist timer **mantiene viva la conexión y previene deadlocks** en presencia de ventanas 0.

---

### 👨‍💻 Relevancia para backend

- Ayuda a evitar **bloqueos silenciosos** cuando un cliente no lee datos del socket.
- Es útil para detectar:
  - Servicios que se “cuelan” pero no cierran la conexión
  - Clientes que no procesan datos pero mantienen la sesión abierta
- Especialmente relevante en:
  - **Bases de datos**
  - **WebSockets**
  - **Sistemas de streaming**

---

## 🛠️ Comandos / herramientas útiles

| Comando / Herramienta           | Función                                                                 |
|---------------------------------|--------------------------------------------------------------------------|
| `ss -i`                         | Ver detalles como la ventana de recepción (`rcv_wnd`)                   |
| `tcpdump`                       | Captura paquetes ACK con rwnd = 0 y probes TCP                          |
| `netstat -s`                    | Estadísticas de ventanas cero                                           |
| `strace` / `lsof`               | Ver si una app está bloqueada esperando escribir en un socket lleno     |
| `sysctl net.ipv4.tcp_keepalive_time` | No controla el persist, pero puede ayudar a forzar detección de conexiones muertas |

---

### 🧪 Ejemplos prácticos

---

#### 🔧 `ss -i`

✅ **Qué hace:**  
Muestra el estado de las conexiones TCP, incluidas las ventanas.

```bash
rcv_wnd: 0, snd_wnd: 20480
```
🧠 **Comentario:**  
Si `rcv_wnd` está a cero, se ha activado el persist timer. El emisor no puede enviar más hasta que se reciba un update.


#### 🔧 `tcpdump 'tcp[13] & 0x10 != 0' and tcp[14:2] = 0'`

✅ **Qué hace:**  Captura ACKs con ventana cero.

`IP 192.168.1.10.443 > 192.168.1.50.51234: Flags [ACK], win 0` 

🧠 **Comentario:**  Indica que el receptor **no puede aceptar más datos**. Si esto persiste, puede congelar el flujo.

---

#### 🔧 `netstat -s | grep 'zero window'`

✅ **Qué hace:**  Muestra cuántas veces se ha detectado una ventana cero.

`38 connections with persist probes
15 zero window probes sent` 

🧠 **Comentario:**  
Ideal para saber si tus servicios están usando el persist timer frecuentemente (puede ser síntoma de cuello de botella).

---

#### 🔧 `strace -p <PID>` o `lsof -p <PID>`

✅ **Qué hace:**  Verifica si un proceso está bloqueado escribiendo en un socket cuyo receptor no lee.

`sendto(...) = EAGAIN (Resource temporarily unavailable)` 

🧠 **Comentario:**  
Si tu app intenta escribir pero el receptor no lee, se bloquea → el persist timer actúa.


## 📘 Capítulo 23: TCP Keepalive Timer

### 🧠 Lo esencial que debes saber

- El **keepalive timer** permite a TCP **detectar si la otra parte de la conexión ha desaparecido** sin cerrarla correctamente.
- Está **desactivado por defecto** en muchas implementaciones, pero puede habilitarse a nivel de socket o sistema.
- Si una conexión está **inactiva** por un largo tiempo, TCP puede enviar paquetes **"keepalive"** (sin datos) para verificar si el otro extremo sigue presente.

---

### 🔁 ¿Cómo funciona el TCP Keepalive?

1. La conexión TCP permanece **inactiva durante un tiempo prolongado**.
2. Si el **keepalive está activado**, tras cierto tiempo (`tcp_keepalive_time`) se envía un paquete vacío (ACK).
3. Si no hay respuesta, se envían más intentos (`tcp_keepalive_probes`) con cierto intervalo (`tcp_keepalive_intvl`).
4. Si tras varios intentos no hay respuesta, **la conexión se cierra**.

---

### 🧪 Parámetros importantes

| Parámetro                      | Descripción                                                  |
|-------------------------------|--------------------------------------------------------------|
| `tcp_keepalive_time`          | Tiempo de inactividad antes de enviar el primer keepalive    |
| `tcp_keepalive_intvl`         | Intervalo entre cada intento                                 |
| `tcp_keepalive_probes`        | Número de intentos antes de cerrar la conexión               |

✅ Se configuran vía `sysctl` o en el código de la app con `setsockopt()`.

---

### 👨‍💻 Relevancia para backend

- Útil para:
  - **Detectar clientes que se desconectaron sin cerrar conexión**
  - **Evitar que sockets queden colgados** eternamente (especialmente en conexiones largas)
  - Trabajos con:
    - WebSockets
    - Proxies persistentes
    - Conexiones base de datos

🧠 Ayuda a liberar recursos cuando el otro extremo **ya no existe pero no se notificó**.

---

### 🛠️ Comandos / herramientas útiles

| Herramienta / Comando                          | Función                                                               |
|-----------------------------------------------|------------------------------------------------------------------------|
| `sysctl net.ipv4.tcp_keepalive_time`          | Ver/modificar tiempo de inicio de keepalive (en segundos)             |
| `ss -ti`                                       | Ver si una conexión tiene keepalive activo (algunos sistemas)         |
| `tcpdump`                                      | Ver paquetes ACK sin datos (keepalive packets)                        |
| `setsockopt()`                                 | Habilitar keepalive en sockets en apps propias                        |
| `netstat -s | grep keepalive`                 | Ver estadísticas de keepalive                                         |

---

### 🧪 Ejemplos prácticos

#### 🔧 Ver configuración del sistema

```bash
sysctl net.ipv4.tcp_keepalive_time
sysctl net.ipv4.tcp_keepalive_intvl
sysctl net.ipv4.tcp_keepalive_probes
```
🧠 **Comentario:**  
Te dice cuánto tarda en enviarse el primer keepalive, con qué frecuencia se repite y cuántos intentos se hacen antes de cerrar.

----------

#### 🔧 Activar keepalive en un socket (ej. Python)

```python
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
``` 

🧠 **Comentario:**  
Ideal en servidores que gestionan muchas conexiones persistentes (como un backend con sockets largos o idle).

----------

### 🔧 Ver paquetes keepalive con tcpdump

`tcpdump 'tcp[13] & 0x10 != 0 and len <= 0'` 

🧠 **Comentario:**  
Filtra ACKs sin datos (posibles keepalive TCP). No verás payload, solo confirmación de que el host sigue vivo.

----------

### 🔧 Estadísticas de keepalive

`netstat -s | grep keepalive` 

📤 **Salida posible:**

`20 keepalive probes sent 5 keepalive timeouts` 

🧠 **Comentario:**  
Útil para monitorear comportamiento en sistemas de producción que usan conexiones largas.


## 📘 Capítulo 24: TCP Futures and Performance

### 🧠 Lo esencial que debes saber

Este capítulo explora **mejoras modernas y futuras del protocolo TCP**, especialmente aquellas orientadas a:

- Mejorar el **rendimiento**
- Reducir la **latencia**
- Soportar redes más rápidas y complejas

Estas mejoras se han incorporado al stack TCP para **mantener su relevancia** frente a nuevos protocolos como **QUIC** y necesidades de alta velocidad (cloud, fibra, 5G…).

---

### 🚀 Extensiones modernas de TCP

| Mecanismo                  | Propósito                                                            |
|---------------------------|----------------------------------------------------------------------|
| **TCP Window Scaling**     | Permite usar ventanas de recepción > 64 KB                          |
| **TCP Timestamps (RFC 1323)** | Mejora cálculo de RTT y ayuda a evitar errores de secuencia     |
| **Selective Acknowledgments (SACK)** | Acelera recuperación de pérdidas sin reenviar todo             |
| **ECN (Explicit Congestion Notification)** | Detecta congestión sin pérdida de paquetes                 |
| **Fast Open (TFO)**        | Envía datos durante el handshake (menos latencia)                   |

🧠 Estas extensiones requieren **compatibilidad en ambos extremos**.

---

### 📊 Métricas de rendimiento en TCP

TCP mide y adapta su comportamiento usando:

- **RTT (Round-Trip Time)**: tiempo de ida y vuelta
- **RTO (Retransmission Timeout)**: cuánto esperar antes de retransmitir
- **CWND (Congestion Window)**: cuánto puede enviar sin congestionar la red
- **RWND (Receive Window)**: cuánto puede recibir el otro extremo

El rendimiento está limitado por:

```text
Throughput ≈ min(cwnd, rwnd) / RTT
```

### 👨‍💻 Relevancia para backend

Estas mejoras son clave si trabajas en:

-   Transferencia de archivos pesados (ej. S3, video, backups)
    
-   Alta concurrencia (muchas conexiones TCP simultáneas)
    
-   Latencia ultra baja (trading, gaming, IoT en tiempo real)
    
-   Microservicios distribuidos en redes inestables
    

📌 Un mal uso de TCP (o su configuración) puede:

-   Causar **cuellos de botella**
    
-   Provocar **pérdidas de rendimiento invisibles**
    
-   Afectar el **comportamiento de tus aplicaciones bajo carga**


## 🛠️ Comandos / herramientas útiles

| Comando / Herramienta                    | Descripción                                                                 |
|------------------------------------------|-----------------------------------------------------------------------------|
| `ss -i`                                  | Muestra información detallada de conexiones TCP (RTT, cwnd, retrans, etc.) |
| `sysctl net.ipv4.tcp_window_scaling`     | Verifica si la ampliación de ventana TCP está activada                     |
| `sysctl net.ipv4.tcp_sack`               | Comprueba si está activado el soporte de Selective Acknowledgment (SACK)   |
| `iperf3 --bidir`                         | Test de rendimiento TCP bidireccional entre dos nodos                      |
| `netstat -s`                             | Muestra estadísticas acumuladas del stack TCP                              |
| `ethtool -k <interfaz>`                  | Muestra si la interfaz de red soporta offloading para mejorar rendimiento  |

----------

### 🧪 Ejemplos prácticos

#### 🔧 Ver uso de SACK y window scaling
```bash
sysctl net.ipv4.tcp_sack
sysctl net.ipv4.tcp_window_scaling
``` 

📤 **Salida:**
```bash
net.ipv4.tcp_sack = 1
net.ipv4.tcp_window_scaling = 1
``` 

🧠 **Comentario:**  
Ambos activados → TCP más eficiente en redes modernas con latencia y pérdida.

----------

#### 🔧 `ss -i`

✅ **Qué hace:**  
Verifica parámetros de rendimiento TCP por conexión.

`cwnd: 21, rtt: 30ms, rto: 200ms, retrans: 0` 

🧠 **Comentario:**  
Te ayuda a ver el rendimiento real y detectar cuellos de congestión.

----------

#### 🔧 `iperf3 --bidir`

✅ **Qué hace:**  
Prueba el rendimiento **de subida y bajada simultáneamente** entre dos nodos.

`[SUM] 0.00-10.00 sec  2.0 GBytes  1.7 Gbits/sec  sender
[SUM] 0.00-10.00 sec  1.9 GBytes  1.6 Gbits/sec  receiver` 

🧠 **Comentario:**  
Ideal para probar rendimiento real en producción o redes virtualizadas.

----------

#### 🔧 `ethtool -k eth0`

✅ **Qué hace:**  
Verifica si están activadas funciones de offload (como TCP checksum, TSO).

```bash
tcp-segmentation-offload: on
generic-receive-offload: on
``` 

🧠 **Comentario:**  
Estas funciones alivian la CPU y mejoran rendimiento para tráfico TCP pesado.

----------

### 📦 ¿Y el futuro?

TCP sigue evolucionando, pero:

-   Protocolos como **QUIC (basado en UDP)** están ganando terreno, especialmente en web moderna.
    
-   Aun así, **TCP sigue siendo el pilar de backend, bases de datos, APIs y microservicios**.


## 📘 Capítulo 25: SNMP – Simple Network Management Protocol


### 🧠 Lo esencial que debes saber

- **SNMP** es un protocolo de capa de aplicación diseñado para **monitorizar y administrar dispositivos de red**: routers, switches, servidores, impresoras, etc.
- Usa **UDP (puerto 161)** para las consultas y **puerto 162** para recibir alertas (traps).
- Opera mediante una estructura de **pregunta/respuesta (GET, SET)** sobre una base de datos jerárquica llamada **MIB (Management Information Base)**.

---

### 🧩 Estructura de SNMP

| Componente      | Función                                                                  |
|------------------|-------------------------------------------------------------------------|
| **Agent**         | Software que corre en el dispositivo gestionado                         |
| **Manager**       | Software que envía comandos SNMP y recibe respuestas o traps            |
| **MIB**           | Base de datos jerárquica de variables gestionables (CPU, RAM, red...)   |
| **OID**           | Identificador único de cada variable dentro de la MIB                   |

Ejemplo de OID:  
```text
1.3.6.1.2.1.1.5.0 → nombre del host
```

--- 

### 🔁 Operaciones básicas
| Operación SNMP | Descripción                                               |
|----------------|-----------------------------------------------------------|
| GET            | Solicita el valor de una variable (OID)                   |
| SET            | Modifica el valor de una variable (si está permitido)     |
| GET-NEXT       | Navega al siguiente OID dentro de la MIB                  |
| TRAP           | Alerta enviada automáticamente por el agente al manager   |

---

### 🔒 Versiones de SNMP

| Versión  | Características                                                 |
|----------|-----------------------------------------------------------------|
| SNMPv1   | Simple, pero sin cifrado ni autenticación                       |
| SNMPv2c  | Más eficiente, aún sin seguridad real                           |
| SNMPv3   | Añade autenticación, privacidad (cifrado) y control de acceso   |
🧠 Hoy se recomienda usar **SNMPv3** por razones de seguridad.

---

### 👨‍💻 Relevancia para backend

-   Aunque no lo uses directamente en tus APIs, **SNMP puede afectar o ayudar a monitorizar servicios backend**, como:
    
    -   Uso de CPU/RAM/puertos
        
    -   Estado de red en instancias backend
        
    -   Alerta temprana ante fallos de hardware o saturación
        
-   También puedes integrar SNMP con herramientas como:
    
    -   **Nagios**, **Zabbix**, **Prometheus (con exporters)**

---

### 🛠️ Comandos / herramientas útiles
| Comando / Herramienta                            | Función                                                              |
|--------------------------------------------------|----------------------------------------------------------------------|
| `snmpget -v 2c -c public <host> <OID>`           | Obtiene valor de una variable SNMP                                  |
| `snmpwalk -v 2c -c public <host>`                | Lista múltiples OIDs de forma recursiva                             |
| `snmpset -v 2c -c private <host> <OID> type val` | Modifica el valor de una variable SNMP                              |
| `snmptrap`                                       | Envía un trap manualmente                                           |
| `snmpd` / `snmptrapd`                            | Agente SNMP o receptor de traps                                     |
| `tcpdump port 161 or port 162`                   | Captura tráfico SNMP o traps SNMP                                   |

---

### 🧪 Ejemplos prácticos

---

#### 🔧 `snmpget -v 2c -c public 192.168.1.1 1.3.6.1.2.1.1.1.0`

✅ **Qué hace:**  
Consulta el valor de un OID (en este caso, descripción del sistema).

`SNMPv2-MIB::sysDescr.0 = STRING: Linux server01 5.10.0-22-amd64 #1 SMP ...` 

🧠 **Comentario:**  
Responde con la información básica del sistema remoto. Ideal para validaciones simples.

----------

#### 🔧 `snmpwalk -v 2c -c public 192.168.1.1`

✅ **Qué hace:**  
Explora la MIB desde un punto inicial (por defecto: `1.3.6.1`).

```bash
SNMPv2-MIB::sysName.0 = STRING: server01
SNMPv2-MIB::sysLocation.0 = STRING: Datacenter A
...
``` 

🧠 **Comentario:**  
Útil para inspeccionar qué variables están disponibles en un dispositivo.

----------

#### 🔧 `snmpset -v 2c -c private 192.168.1.1 1.3.6.1.2.1.1.6.0 s "Nueva ubicación"`

✅ **Qué hace:**  Modifica un valor de la MIB (ej. ubicación del host).

`SNMPv2-MIB::sysLocation.0 = STRING: Nueva ubicación` 

🧠 **Comentario:**  Necesita permisos y el string de comunidad de escritura (`private`).

----------

#### 🔧 `tcpdump udp port 161 or port 162`

✅ **Qué hace:**  Captura tráfico SNMP (consultas) o traps SNMP (notificaciones).

`IP 192.168.1.1.161 > 192.168.1.100.1033: SNMP trap` 

🧠 **Comentario:**  Muy útil para saber si se están enviando alertas o si hay actividad SNMP sospechosa.


## 📘 Capítulo 26: Telnet and Rlogin

### 🧠 Lo esencial que debes saber

- **Telnet** y **Rlogin** son protocolos de acceso remoto a través de **TCP/IP**, usados principalmente para controlar sistemas Unix/Linux desde otro host.
- Ambos permiten **conexión a línea de comandos remota**, pero **no son seguros**, ya que transmiten credenciales en texto plano.
- Usan TCP:
  - **Telnet**: puerto 23
  - **Rlogin**: puerto 513

Hoy en día están **obsoletos en favor de SSH**, pero se estudian por su valor histórico y arquitectura de protocolo.

---

### 🧩 Diferencias entre Telnet y Rlogin

```markdown
| Característica     | Telnet                        | Rlogin                          |
|--------------------|-------------------------------|---------------------------------|
| Autenticación      | Manual (usuario + password)   | Automática si `.rhosts` está configurado |
| Configuración local| Nula                          | Usa la identidad del usuario local       |
| Compatibilidad     | Cualquier sistema TCP/IP      | Solo Unix/Linux                 |
| Seguridad          | Ninguna                       | Ninguna                         |
```

---

### 🧠 ¿Cómo funciona Telnet?

-   Telnet usa TCP para abrir una sesión de terminal remota.
    
-   Se basa en una **negociación inicial de opciones** (modo eco, tipo de terminal, etc.) con comandos especiales (`IAC`, `WILL`, `DO`, `DONT`, `WONT`).
    
-   Todo lo que escribes se envía como entrada estándar al host remoto.

---

### 👨‍💻 Relevancia para backend (hoy en día)

-   Aunque ya **no se usa en producción**, **Telnet sigue siendo útil para pruebas rápidas** de puertos TCP abiertos.
    
    -   Ejemplo: `telnet <host> <puerto>` → para probar conectividad a un servicio HTTP, SMTP, etc.
        
-   También es útil para:
    
    -   Ver si una aplicación escucha correctamente
        
    -   Depurar firewalls y reglas de red
        
-   **Rlogin** prácticamente ha desaparecido.

### 🛠️ Comandos / herramientas útiles

| Comando / Herramienta       | Función                                                                 |
|-----------------------------|-------------------------------------------------------------------------|
| `telnet <host> <puerto>`    | Prueba conexión TCP manual (cualquier puerto)                          |
| `telnet`                    | Inicia cliente Telnet interactivo                                      |
| `rlogin <host>`             | Inicia sesión remota si está permitido por `.rhosts`                  |
| `tcpdump port 23 or port 513` | Captura sesiones Telnet o Rlogin                                    |
| `ss -t -a` / `netstat -tn`  | Verifica si hay conexiones abiertas en esos puertos                   |

### 🧪 Ejemplos prácticos

----------

#### 🔧 Conexión básica con Telnet

`telnet example.com 80` 

📤 Salida esperada:

```bash
Trying 93.184.216.34...
Connected to example.com. Escape  character  is  '^]'.
``` 

🧠 **Comentario:**  
Ideal para comprobar si un servicio escucha y responde por TCP (como HTTP, SMTP, Redis…).

----------

#### 🔧 Simular petición HTTP con Telnet
`GET / HTTP/1.1 Host: example.com` 

📤 Respuesta esperada:

```bash
HTTP/1.1 200 OK
Content-Type: text/html ...
``` 

🧠 **Comentario:**  
Puedes simular peticiones HTTP sin navegador ni curl. Muy útil para depuración básica.

----------

#### 🔧 Capturar tráfico con tcpdump

`sudo tcpdump -n port 23` 

📤 Salida:

`IP  192.168.1.50.53920 > 192.168.1.1.23: Flags [P.], length 28` 

🧠 **Comentario:**  
Muestra sesión Telnet activa. Puedes ver comandos y respuestas sin cifrar (¡no usar en producción!).

----------

### 🔒 Nota de seguridad

**No uses Telnet ni Rlogin en entornos productivos o públicos**:

-   Transmiten usuario y contraseña en texto plano.
    
-   Son vulnerables a sniffing y ataques MITM.
    
-   Siempre usa **SSH** como alternativa moderna y segura.


## 📘 Capítulo 27: FTP – File Transfer Protocol

### 🧠 Lo esencial que debes saber

- **FTP** (File Transfer Protocol) es uno de los protocolos más antiguos de la capa de aplicación, diseñado para **transferencia de archivos** entre cliente y servidor.
- Opera sobre **TCP**, usando dos conexiones separadas:
  - **Puerto 21**: conexión de control (comandos, respuestas)
  - **Puerto 20** o dinámico: conexión de datos (para los archivos)

- FTP puede operar en dos modos:
  - **Activo**: el servidor abre la conexión de datos al cliente.
  - **Pasivo**: el cliente abre ambas conexiones (más común detrás de NAT/firewalls).

---

### 🔁 Flujo de conexión FTP

1. Cliente abre conexión TCP al puerto 21 (control).
2. Envía usuario/contraseña.
3. Solicita operación (`RETR`, `STOR`, `LIST`, etc.).
4. Se abre **una segunda conexión TCP** para los datos.
5. Se transfiere el archivo.
6. Se cierra la conexión de datos; la de control puede quedar abierta.

---

### 🔒 Seguridad

| Variante | Descripción                                  |
|----------|----------------------------------------------|
| FTP      | Sin cifrado, todo en texto plano             |
| FTPS     | FTP sobre TLS (SSL)                          |
| SFTP     | Protocolo diferente, basado en SSH           |

🧠 **SFTP** es el estándar seguro moderno, **no confundirlo con FTP sobre TLS (FTPS)**.

---

### 👨‍💻 Relevancia para backend

- FTP todavía se usa en:
  - Integraciones con sistemas legados
  - Transferencia de grandes volúmenes de archivos batch
  - Automatizaciones con scripts
- Problemas comunes:
  - Firewalls bloqueando el canal de datos
  - Configuraciones NAT que impiden el modo activo
  - Exposición de credenciales (por ser texto plano)

---

### 🛠️ Comandos / herramientas útiles

```markdown
| Comando / Herramienta             | Función                                                                 |
|----------------------------------|--------------------------------------------------------------------------|
| `ftp <host>`                     | Inicia una sesión FTP interactiva                                       |
| `ncftp`, `lftp`                  | Clientes FTP mejorados                                                  |
| `curl ftp://host/file`           | Descargar archivo por FTP usando curl                                   |
| `tcpdump port 21 or port 20`     | Captura conexiones de control y datos FTP                               |
| `ss -t state established`        | Verifica conexiones TCP abiertas                                        |
| `vsftpd`, `proftpd`              | Servidores FTP comunes en Linux                                         |
```

### 🧪 Ejemplos prácticos

----------

#### 🔧 Conexión FTP simple
`ftp ftp.gnu.org` 

📤 Salida:

```bash
Connected to ftp.gnu.org. 220 GNU FTP server ready.
Name (ftp.gnu.org:you): anonymous 331 Please specify the password. Password:  230 Login successful.
``` 

🧠 **Comentario:**  Muchos servidores FTP públicos aceptan `anonymous` como usuario.

----------

### 🔧 Descargar archivo con curl
`curl -O ftp://ftp.gnu.org/gnu/bash/bash-5.1.tar.gz` 

🧠 **Comentario:**  Descarga directa vía FTP sin abrir una sesión interactiva.

----------

### 🔧 FTP pasivo con lftp

`lftp -u user,pass -e "set ftp:passive-mode on; get data.csv; bye" ftp.example.com` 

🧠 **Comentario:**  Ideal en scripts o detrás de NAT/firewall. LFTP soporta autenticación y scripts complejos.

----------

### 🔧 Captura de tráfico FTP

`tcpdump -n port 21 or port 20` 

📤 Salida típica:
`IP  192.168.1.100.21 > 192.168.1.50.51234: Flags [P.], FTP: 220 Welcome` 

🧠 **Comentario:**  Puedes ver login, comandos y respuestas. ¡Ojo! Todo en texto plano.

----------

### 🔐 Recomendación actual

Usar **SFTP o HTTPS para transferencias de archivos seguras**. FTP debe restringirse a redes internas o entornos controlados.



## 📘 Capítulo 28: SMTP – Simple Mail Transfer Protocol

### 🧠 Lo esencial que debes saber

- **SMTP** es el protocolo estándar de la capa de aplicación para **envío de correo electrónico** entre servidores.
- Utiliza **TCP puerto 25** por defecto (aunque también se usa 587 para envío autenticado y 465 para SMTP seguro).
- Funciona mediante comandos de texto plano que definen la comunicación entre cliente y servidor de correo.

---

### 🧩 Flujo básico de envío de correo con SMTP

1. Cliente abre conexión TCP al servidor SMTP (puerto 25/587).
2. Se intercambian comandos como:
   - `HELO` o `EHLO` → saludo
   - `MAIL FROM` → indica remitente
   - `RCPT TO` → indica destinatario
   - `DATA` → cuerpo del mensaje
   - `QUIT` → cierra la sesión

3. Si el servidor acepta, el mensaje se entrega o enruta.

---

### 📦 Comandos SMTP comunes

```markdown
| Comando     | Descripción                                |
|-------------|--------------------------------------------|
| HELO/EHLO   | Saludo inicial, identifica al cliente      |
| MAIL FROM   | Define el remitente del correo             |
| RCPT TO     | Define el destinatario                     |
| DATA        | Inicia el cuerpo del mensaje               |
| RSET        | Resetea la sesión                          |
| QUIT        | Cierra la conexión                         |
```

### 🔒 Seguridad y autenticación

```bash
| Puerto | Uso                                           |
|--------|-----------------------------------------------|
| 25     | Envío entre servidores (sin autenticación)     |
| 587    | Envío autenticado (STARTTLS obligatorio)       |
| 465    | Envío autenticado con TLS directo (legacy)     |
```
    

----------

### 👨‍💻 Relevancia para backend

-   Si tu app envía correos (registro, notificaciones, alertas):
    
    -   Necesitas configurar SMTP correctamente
        
    -   Debes manejar fallos como timeouts, respuestas 5xx, etc.
        
-   Integraciones típicas:
    
    -   **Correo transaccional (SendGrid, Mailgun, SES)**
        
    -   **Servidores internos (Postfix, Exim)**
        
-   Es común usar librerías (como `nodemailer`, `smtplib`, etc.), pero entender el protocolo ayuda a depurar errores.

### 🛠️ Comandos / herramientas útiles
| Herramienta / Comando               | Función                                                             |
|-------------------------------------|----------------------------------------------------------------------|
| `telnet <host> 25`                  | Probar conexión SMTP y enviar comandos manualmente                  |
| `openssl s_client -starttls smtp -connect <host>:587` | Inicia sesión segura STARTTLS                                     |
| `swaks`                             | Herramienta avanzada para probar SMTP                               |
| `postfix`, `exim`, `sendmail`       | Servidores SMTP comunes                                             |
| `tcpdump port 25 or port 587`       | Captura tráfico SMTP para debugging                                 |


### 🧪 Ejemplos prácticos

#### 🔧 Enviar correo manual con Telnet (no seguro)


`telnet smtp.example.com 25` 

```bash
EHLO myserver.local
MAIL FROM:<user@example.com>
RCPT TO:<dest@example.com>
DATA
Subject: Prueba SMTP

Hola, esto es un test.
.
QUIT
``` 

🧠 **Comentario:**  Ideal para entender cómo funciona SMTP por dentro y ver errores como 550 (user unknown).


#### 🔧 Prueba de conexión segura con OpenSSL

`openssl s_client -starttls smtp -connect smtp.gmail.com:587` 

📤 Salida: TLS handshake + sesión SMTP

🧠 **Comentario:**  
Útil para validar certificados, autenticación y cifrado con proveedores reales.

----------

#### 🔧 Envío completo con `swaks`
```bash
swaks --to test@ejemplo.com --from user@tudominio.com --server smtp.tudominio.com --auth LOGIN --auth-user user --auth-password secret
``` 

🧠 **Comentario:**  
`swaks` permite probar de forma avanzada sin escribir comandos manualmente.

----------

### 📌 Códigos de respuesta SMTP (algunos comunes)
| Código | Significado                              |
|--------|-------------------------------------------|
| 220    | Servicio listo                            |
| 250    | Acción completada correctamente           |
| 354    | Esperando cuerpo del mensaje (después de DATA) |
| 421    | Servicio no disponible                    |
| 450/550| Problemas con la entrega (ej. no existe el destinatario) |
| 530    | Requiere autenticación                    |

---

## 📘 Capítulo 29: NFS – Network File System

### 🧠 Lo esencial que debes saber

- **NFS** (Network File System) permite acceder a **archivos remotos como si fueran locales**, a través de la red.
- Es un protocolo de **sistema de archivos distribuido**, desarrollado por Sun Microsystems.
- Se basa en **RPC (Remote Procedure Call)**, y usa **TCP o UDP** como transporte.
- Muy usado en entornos Linux/Unix para:
  - Montar volúmenes compartidos
  - Compartir datos entre nodos
  - Centralizar almacenamiento en servidores

---

### 🧩 Arquitectura de NFS

```markdown
| Componente         | Función                                                           |
|--------------------|-------------------------------------------------------------------|
| Cliente NFS        | Sistema que accede a archivos remotos                             |
| Servidor NFS       | Provee los archivos compartidos                                    |
| Mount Daemon (`rpc.mountd`) | Maneja solicitudes de montaje desde clientes           |
| NFS Daemon (`nfsd`) | Procesa solicitudes de lectura/escritura                         |
| Portmapper (`rpcbind`) | Asigna puertos dinámicos a servicios RPC                      |
```
---

### 🔁 Funcionamiento general

1.  El cliente se comunica con el `portmapper` del servidor para obtener puertos.
    
2.  Solicita montar un recurso compartido con `rpc.mountd`.
    
3.  Las operaciones de archivo (open, read, write, etc.) se gestionan con `nfsd` a través de RPC.

---

### 📦 Versiones de NFS
| Versión | Características principales                                              |
|---------|-------------------------------------------------------------------------|
| v2      | Muy simple, usa UDP, tamaño limitado                                    |
| v3      | Soporta TCP/UDP, mayor rendimiento, errores más detallados             |
| v4      | Soporta autenticación, ACLs, multiplexación en un solo puerto TCP 2049 |
🧠 Hoy en día, **NFSv4** es la versión recomendada.

---

### 🔒 Seguridad

-   NFS tradicional depende de **UID/GID** del sistema operativo cliente.
    
-   Para mejorar la seguridad:
    
    -   Usa **NFSv4** con autenticación Kerberos (`sec=krb5`)
        
    -   Monta recursos de solo lectura si no necesitas escritura
        
    -   Aísla redes NFS detrás de firewalls
        

----------

### 👨‍💻 Relevancia para backend

-   NFS se usa para:
    
    -   Compartir archivos entre contenedores o nodos
        
    -   Montar recursos en entornos CI/CD
        
    -   Mantener datos consistentes entre servicios distribuidos
        
-   En Kubernetes, puede ser backend de volúmenes persistentes (PV/PVC)
    
-   Problemas comunes:
    
    -   Latencia → afecta rendimiento
        
    -   Desincronización de permisos UID/GID
        
    -   Fallos de red → bloqueos en operaciones de archivo
        

----------

### 🛠️ Comandos / herramientas útiles
| Comando / Herramienta               | Función                                                        |
|------------------------------------|-----------------------------------------------------------------|
| `showmount -e <host>`              | Ver recursos exportados por el servidor NFS                    |
| `mount -t nfs <host>:/ruta /mnt`   | Montar recurso NFS manualmente                                 |
| `df -h` / `mount`                  | Ver si el recurso está montado correctamente                   |
| `rpcinfo -p <host>`                | Ver servicios RPC activos (incluidos NFS)                      |
| `tcpdump port 2049`                | Captura tráfico NFS                                            |
| `exportfs -v`                      | Ver recursos exportados (servidor NFS)                         |

----------

### 🧪 Ejemplos prácticos

#### 🔧 Ver recursos compartidos con `showmount`

`showmount -e nfs-server.local` 

📤 Salida:

```bash
Export list for nfs-server.local:
/home/projects   192.168.1.0/24
``` 

🧠 **Comentario:**  Muestra qué directorios están disponibles para montar.

----------

#### 🔧 Montar un recurso NFS
`sudo mount -t nfs nfs-server.local:/home/projects /mnt/nfs` 

🧠 **Comentario:**  Monta el recurso NFS en `/mnt/nfs`. Puede automatizarse en `/etc/fstab`.

----------

#### 🔧 Ver si el recurso está activo

`df -h | grep nfs` 

📤 Salida: `nfs-server.local:/home/projects   100G   55G   45G  55% /mnt/nfs` 

🧠 **Comentario:**  Confirma que el sistema de archivos remoto está montado correctamente.

----------

#### 🔧 Ver puertos RPC/NFS activos

`rpcinfo -p nfs-server.local` 

📤 Salida: `100003 3 tcp 2049 nfs 100005 1 udp 631 mountd` 

🧠 **Comentario:**  Útil si NFS no está funcionando: puedes confirmar si los servicios están corriendo.

### 🚫 Nota sobre rendimiento
-   NFS es más rápido con TCP y buffers grandes (`rsize`, `wsize`)
-   Puedes usar opciones de montaje como:

```bash
mount -t nfs -o rw,noatime,nolock,nfsvers=4,rsize=1048576,wsize=1048576 ...

```
---

## 📘 Capítulo 30: Otras Aplicaciones TCP/IP

### 🧠 Lo esencial que debes saber

Este capítulo presenta una **variedad de aplicaciones que usan TCP/IP**, además de las ya tratadas en capítulos anteriores. Aunque algunas son menos conocidas hoy, ofrecen una visión general de cómo **la pila TCP/IP soporta distintos tipos de servicios**.

El objetivo es mostrar la **diversidad de usos** que puede tener TCP/IP, desde login remoto hasta reloj en red.

---

### 📦 Aplicaciones destacadas

```markdown
| Aplicación    | Protocolo(s) | Puerto(s) | Descripción breve                                     |
|---------------|--------------|-----------|--------------------------------------------------------|
| Daytime       | TCP/UDP      | 13        | Devuelve la fecha y hora como texto                   |
| Time          | TCP/UDP      | 37        | Devuelve la hora como entero de 32 bits               |
| Echo          | TCP/UDP      | 7         | Devuelve todo lo que recibe (testing/debug)          |
| Discard       | TCP/UDP      | 9         | Descarta todo lo recibido (medición de rendimiento)  |
| Chargen       | TCP/UDP      | 19        | Devuelve cadenas repetidas (carga artificial)        |
| Whois         | TCP          | 43        | Consultas de nombres de dominio o usuarios           |
```
🧠 Muchas de estas aplicaciones son **más útiles en pruebas de red que en producción real** hoy en día.

### 🔒 Consideraciones de seguridad
-   Estas aplicaciones suelen estar **deshabilitadas por defecto** por razones de seguridad.
-   Algunas pueden ser usadas maliciosamente (DoS, amplificación).
-   Solo deberían activarse en redes de prueba o cerradas.

### 👨‍💻 Relevancia para backend
Aunque estas aplicaciones no se usan directamente en desarrollo backend, son **muy útiles para**:

-   **Probar latencia**, conectividad y rendimiento básico
-   Simular tráfico o carga en entornos controlados
-   Aprender cómo se comportan los servicios TCP/UDP simples
-   Desarrollar herramientas personalizadas de red o diagnóstico


#### 🛠️ Comandos / herramientas útiles
| Comando / Herramienta              | Función                                                             |
|-----------------------------------|----------------------------------------------------------------------|
| `telnet <host> 13`                | Consultar servicio Daytime                                          |
| `nc <host> 19`                    | Conectarse a Chargen (genera carga)                                 |
| `tcpdump port 7 or port 9`        | Capturar tráfico Echo o Discard                                     |
| `nmap --script time`              | Consultar puertos 13/37 si están abiertos (servicios de tiempo)     |
| `xinetd` / `inetd`                | Servicios de red que pueden lanzar estas apps de red (legacy)       |

### 🧪 Ejemplos prácticos

----------

#### 🔧 Probar Daytime con Telnet
`telnet time.nist.gov 13` 

📤 Salida esperada: `58256  24-04-17  12:34:56  00  0  0  465.1  UTC(NIST)` 

🧠 **Comentario:**  Devuelve la hora exacta. Aún hay servidores públicos disponibles.

----------

#### 🔧 Usar `nc` con Echo o Chargen

`nc localhost 7` 

✍️ Escribe algo y verás que se te devuelve (echo).

`nc localhost 19` 

📤 Salida: `!"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[...\n` 

🧠 **Comentario:**  
Chargen genera cadenas repetitivas: útil para pruebas de carga o throughput.

----------

#### 🔧 Captura de tráfico simple
`sudo tcpdump port 13 or port 37` 

🧠 **Comentario:**  Puedes observar cómo fluyen los paquetes de las apps de tiempo en texto o binario.

----------

### 📦 Conclusión del libro

-   TCP/IP soporta una **amplísima variedad de aplicaciones**, desde HTTP y SMTP hasta herramientas de depuración y administración.
    
-   Aunque algunas de estas aplicaciones están obsoletas, son valiosas para:
    
    -   Comprender cómo opera TCP/IP
        
    -   Probar configuraciones de red
        
    -   Analizar tráfico y depurar conectividad
        
-   Las herramientas simples basadas en TCP y UDP **siguen siendo esenciales para pruebas, aprendizaje y observabilidad**.

## 📘 Apéndice A – El programa `tcpdump`

El apéndice A describe cómo funciona internamente `tcpdump`, una herramienta esencial para **capturar, filtrar y analizar tráfico de red**. También cubre cómo accede a los datos de red en distintos sistemas operativos y sus implicaciones de seguridad.

---

### 🔍 ¿Qué es `tcpdump`?

- Es una herramienta de línea de comandos que permite observar paquetes a nivel IP y superiores.
- Usa **`libpcap`** (Packet Capture Library) para acceder a los paquetes directamente desde la interfaz de red.
- Puede funcionar con filtros para mostrar solo el tráfico relevante (ej. `tcp port 80`).

---

### A.1 BSD Packet Filter (BPF)

- Sistema **eficiente y seguro** para capturar paquetes en sistemas tipo BSD.
- BPF opera en **espacio de kernel**, aplicando filtros antes de pasar datos al usuario → evita overhead.
- Ventajas:
  - Bajo impacto en el rendimiento.
  - Evita copiar todos los paquetes innecesarios al espacio de usuario.
- Estructura:
  - BPF es como una **máquina virtual pequeña** que ejecuta filtros (compilados desde expresiones `tcpdump`).
  - Ejemplo: `tcpdump tcp port 80` se convierte en instrucciones de BPF.

🧠 **Hoy es el estándar en sistemas como FreeBSD, macOS, y Linux (vía libpcap).**

---

### A.2 SunOS Network Interface Tap (`/dev/nit`)

- Método propietario de captura usado en sistemas **SunOS 4.x**.
- El dispositivo especial `/dev/nit` permite leer paquetes crudos desde interfaces.
- Problemas:
  - Menos eficiente que BPF.
  - Necesita acceso root.
  - Depende de comportamiento del driver de red.
- Ha sido reemplazado por BPF o DLPI en versiones modernas.

---

### A.3 SVR4 Data Link Provider Interface (DLPI)

- Interfaz estándar en **System V Release 4 y Solaris** para acceso a capa de enlace.
- Más generalista que BPF, pero también más compleja de programar.
- Requiere saber el tipo de enlace y negociar la conexión (estilo conexión orientada).
- A menudo se usa con herramientas como `snoop` o implementaciones personalizadas de `tcpdump`.

---

### A.4 Salida de `tcpdump`

- Muestra información de cabeceras IP/TCP/UDP/ICMP de manera legible.
- Ejemplo:

```bash
IP 192.168.1.10.50514 > 93.184.216.34.80: Flags [S], seq 100, win 8192
```

-   Puedes observar:
    
    -   Dirección origen/destino y puerto
        
    -   Flags TCP (`SYN`, `ACK`, `FIN`)
        
    -   Números de secuencia, longitud de ventana, TTL
        

🛠 Muy útil para detectar:

-   Problemas de handshake
    
-   Retransmisiones
    
-   Latencia, pérdida de paquetes

### A.5 Consideraciones de seguridad

-   `tcpdump` requiere privilegios elevados (root o capacidades especiales) porque accede a interfaces de red crudas.
    
-   Riesgos:
    
    -   Puede **leer todo el tráfico no cifrado** (contraseñas, cookies, tokens).
        
    -   Podría usarse para espionaje si se ejecuta en secreto.
        
-   Recomendaciones:
    
    -   Limitar acceso al binario (`chmod`, `sudoers`)
        
    -   Usar filtros precisos (para capturar solo lo necesario)
        
    -   Registrar quién accede al sistema cuando se usa

### A.6 Opción de depuración de socket (`SO_DEBUG`)

-   Permite activar el modo debug en un socket a través de la opción `SO_DEBUG`.
    
-   Útil para ver internamente cómo evoluciona una conexión TCP:
    
    -   Estados (`SYN_SENT`, `ESTABLISHED`, `TIME_WAIT`)
        
    -   Número de retransmisiones
        
    -   Cambios en ventana de congestión
        

🧠 No todos los sistemas exponen esta funcionalidad, y requiere acceso a estructuras internas del kernel.

----------

### ✅ En resumen:

-   `tcpdump` es una herramienta **imprescindible para depurar redes**.
    
-   Su funcionamiento varía según el sistema operativo:
    
    -   **BPF** en BSD/macOS/Linux modernos.
        
    -   **DLPI** en Solaris/SVR4.
        
    -   **/dev/nit** en SunOS antiguos.
        
-   Su uso debe ser **cauteloso y controlado**, especialmente en entornos productivos.
    
-   Con `tcpdump` y un buen filtro, puedes inspeccionar casi cualquier cosa en la red.


## 📘 Apéndice B – Relojes de los ordenadores (Computer Clocks)

### 🧠 Lo esencial que debes saber

Los protocolos TCP/IP, especialmente aquellos como **TCP, ICMP y NTP**, dependen fuertemente de **mediciones de tiempo precisas**. Este apéndice explica cómo funcionan los relojes del sistema y por qué **la sincronización es crucial** en redes.

---

### 🕓 Tipos de relojes en un sistema

| Tipo de reloj           | Uso principal                                      |
|-------------------------|----------------------------------------------------|
| Reloj de hardware (RTC) | Mantiene la hora incluso apagado el sistema       |
| Reloj del sistema       | Se actualiza con cada "tick" del sistema operativo |
| Reloj de red (NTP)      | Corrige y sincroniza la hora con servidores externos |

---

### ⏱️ Medición de tiempo en protocolos

- **TCP** mide el **RTT (Round-Trip Time)** para calcular los timeouts.
- **ICMP (ping)** también mide RTT entre hosts.
- **NTP (Network Time Protocol)** ajusta el reloj del sistema en base a una fuente externa confiable.

🧠 Si los relojes están desincronizados entre sistemas, puede haber problemas en:
- Logs (eventos en orden incorrecto)
- Autenticación (tokens expiran demasiado pronto o tarde)
- Protocolos sensibles a la latencia (ej. retransmisiones TCP)

---

### ⚠️ Problemas comunes con relojes

| Problema             | Efecto                                                |
|----------------------|--------------------------------------------------------|
| **Drift (deriva)**   | El reloj del sistema se adelanta o atrasa lentamente |
| **Skew (desfase)**   | Diferencia fija entre dos relojes                     |
| **Jitter (variación)**| Cambios pequeños en los tiempos medidos              |

Ejemplo: Un reloj que gana 1 segundo por hora tendrá un **drift de ~24 segundos por día**.

---

### 🔧 Solución: NTP

- El protocolo **NTP** permite mantener relojes sincronizados con precisión de milisegundos.
- Sincroniza con servidores jerárquicos:
  - **Stratum 0**: relojes atómicos o GPS
  - **Stratum 1**: servidores conectados directamente a stratum 0
  - **Stratum 2+**: clientes sincronizados en cascada

✅ Recomendado configurar **servicios NTP como `chronyd` o `ntpd`** en cualquier servidor o sistema distribuido.

---

### 👨‍💻 Relevancia para backend y redes

- Si trabajas con **sistemas distribuidos, microservicios, autenticación o logs**, la hora **debe estar bien sincronizada**.
- Desincronización puede causar:
  - Incompatibilidad con JWT, OAuth
  - Inconsistencias en bases de datos
  - Fallos en debugging (logs fuera de orden)
- **Buenas prácticas**:
  - Usar NTP o Chrony
  - Verificar con `timedatectl status` o `ntpq -p`
  - Sincronizar todos los nodos con el mismo servidor o pool

---

### ✅ En resumen

- Los relojes son **críticos para el correcto funcionamiento de redes y aplicaciones**.
- Todos los sistemas deben tener **NTP activado** y funcionando.
- El conocimiento de cómo el tiempo afecta a TCP/IP ayuda a entender **timeouts, retransmisiones, errores de autenticación, y orden de eventos**.

---
