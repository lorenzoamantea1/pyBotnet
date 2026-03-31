# pyBotnet

## 📌 Panoramica

`pyBotnet` è un progetto Python organizzato in tre componenti principali:

- `controller/`: console di controllo per gestire nodi e inviare comandi.
- `node/`: server che autentica il controller, gestisce client e inoltra istruzioni.
- `client/`: agente che si collega al nodo, riceve comandi crittografati ed esegue azioni di rete.

> Questo repository è destinato all'analisi del codice. L'esecuzione in ambienti non autorizzati può violare leggi o policy.

## 🧩 Struttura del progetto

- `client/`
  - `main.py` - avvia il client.
  - `core/connect.py` - gestisce la connessione sicura al nodo.
  - `core/crypto.py` - funzioni di crittografia per client.
  - `core/layers.py` - metodi di generazione traffico (L7/L4/L3).
  - `core/utilities.py` - parsing URL, utilità di rete e decoding Base64.

- `controller/`
  - `main.py` - carica i nodi e avvia la shell interattiva.
  - `core/connect.py` - connessioni ai nodi, scambio chiavi e messaggi.
  - `core/crypto.py` - RSA/AES per la console.
  - `core/logger.py` - logger standardizzato.
  - `core/errors.py` - gestione delle eccezioni globali.
  - `core/shell.py` - shell testuale e comandi disponibili.
  - `data/nodes.json` - elenco di nodi configurati.

- `node/`
  - `main.py` - legge configurazione e avvia il nodo.
  - `core/server.py` - implementazione del server nodo.
  - `core/crypto.py` - crittografia e chiavi del nodo.
  - `core/logger.py` - logger per il nodo.
  - `core/errors.py` - eccezioni del nodo.
  - `data/config.json` - configurazione runtime del nodo.
  - `data/nodes.network` - elenco nodi sincronizzati.

- `requirements.txt` - dipendenze Python.

## 🔗 Architettura e flusso dati

1. Il `controller` legge la lista dei nodi da `controller/data/nodes.json`.
2. Si connette a ogni nodo e scambia chiavi RSA.
3. Il `nodo` autentica il controller tramite firma RSA.
4. Il controller invia comandi JSON firmati ai nodi.
5. Il nodo esegue comandi di controllo o inoltra istruzioni ai client con AES.
6. Il `client` riceve comandi cifrati e li esegue.

## ⚙️ Configurazione

### Controller

`controller/data/nodes.json`

```json
[
  ["127.0.0.1", 547]
]
```

### Nodo

`node/data/config.json`

- `address.host` - indirizzo di bind del nodo.
- `address.port` - porta TCP del nodo.
- `clients.max_clients` - massimo client collegabili.
- `clients.client_overflow_sleep_s` - tempo di attesa per overflow.
- `debug` - attiva logging dettagliato.

Esempio:

```json
{
  "address": {
    "host": "0.0.0.0",
    "port": 547
  },
  "clients": {
    "max_clients": 25,
    "client_overflow_sleep_s": 3600
  },
  "debug": false
}
```

## 🛠️ Installazione

```bash
python3 -m pip install -r requirements.txt
```

Dipendenze principali:

- `cryptography`
- `colorama`
- `scapy`

## 🔐 Chiavi e autenticazione

### Controller

Il controller genera automaticamente le chiavi RSA in `controller/data/keys/` se non esistono:

- `pub.key`
- `priv.key`

### Nodo

Il nodo richiede la chiave pubblica del controller in `node/data/keys/pub.key`.
Copia la chiave pubblica generata dal controller nel nodo:

```bash
mkdir -p node/data/keys
cp controller/data/keys/pub.key node/data/keys/pub.key
```

Senza questa chiave, il nodo non potrà autenticare il controller.

## ▶️ Esecuzione

### Avviare un nodo

```bash
cd /workspaces/pyBotnet/node
python3 main.py
```

### Avviare il controller

```bash
cd /workspaces/pyBotnet/controller
python3 main.py
```

### Avviare un client

```bash
cd /workspaces/pyBotnet/client
python3 main.py
```

Il client predefinito si connette a `127.0.0.1:547`.

## 🧠 Controller: comandi disponibili

- `help [command]` — mostra i comandi disponibili.
- `quit` / `exit` — esce dalla shell.
- `ping` — ping a tutti i nodi connessi.
- `nodes list` — visualizza i nodi connessi.
- `nodes status` — verifica lo stato dei nodi.
- `nodes sync` — sincronizza la lista dei nodi sui nodi remoti.
- `nodes disconnect <node_id>` — disconnette un nodo.
- `clients list` — elenca i client registrati sui nodi.
- `clients disconnect <node_id> <client_id>` — disconnette un client.
- `flood <url> [duration] [method] [threads]` — invia un comando flood.
- `methods` — lista dei metodi supportati.
- `! <command>` — esegue comando shell (solo admin).

## 🌐 Metodi supportati per flood

- Layer 7: `GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `DNS`
- Layer 4: `ACK`, `SYN`, `FIN`, `RST`, `TCP`, `UDP`
- Layer 3: `ICMP`

## 🔧 Dettagli del nodo

Il nodo:

- scambia la propria chiave pubblica con ogni connessione.
- verifica la firma del controller.
- gestisce comandi di controllo (`status`, `sync_nodes`, `get_clients`, `disconnect_client`).
- inoltra altri messaggi ai client con AES.
- se supera `max_clients`, invia un comando `wait` o `redirect` ai client in overflow.

`node/data/nodes.network` conserva nodi sincronizzati ricevuti dal controller.

## 🚀 Dettagli del client

Il client:

- si connette al nodo specificato.
- riceve la chiave pubblica del nodo.
- invia la propria chiave pubblica.
- invia un messaggio iniziale di identificazione come client.
- riceve comandi cifrati e li decifra.
- gestisce i comandi:
  - `flood` — esegue attacchi di rete.
  - `redirect` — si riconnette a un altro nodo.
  - `wait` — attende e si riconnette.

## 🧪 Protocollo di comunicazione

- I messaggi usano un prefisso di 2 byte per la lunghezza.
- Il nodo invia pubbliche chiavi in formato PEM.
- Le sessioni AES sono cifrate con RSA.
- I comandi principali sono JSON.

## ⚠️ Note importanti

- Per il funzionamento completo, la chiave pubblica del controller deve essere disponibile al nodo.
- `scapy` può richiedere privilegi di root per pacchetti raw.
- `client` usa URL e ip non riservati per evitare loop su reti interne.

## 📄 Licenza

Nessuna licenza è specificata in questo repository.
