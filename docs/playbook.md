# jinrai — playbook dei test case

Un test case per riga della lista use case, con il comando pronto da copiare e la
spiegazione di **ogni singolo switch passato**, così chi lancia il test sa
esattamente cosa finisce sul filo e come si legge il risultato.

Versione di riferimento: **0.41.0**.

---

## Indice

- [Prima di tutto: setup](#prima-di-tutto-setup)
- [I flag obbligatori, spiegati una volta sola](#i-flag-obbligatori-spiegati-una-volta-sola)
- [Test case L3/L4](#test-case-l3l4) — 1–19
- [Test case L7](#test-case-l7) — 20–36
- [Test case di capacità](#test-case-di-capacità) — 37–40
- [Fuori scope, e perché](#fuori-scope-e-perché)
- [Come si legge il summary](#come-si-legge-il-summary)
- [Verifica dell'audit log](#verifica-dellaudit-log)

---

## Prima di tutto: setup

```sh
export REQ='--ack-lab --audit-log /home/c2/runs.jsonl'
export T=192.168.178.41                  # il target del lab
export A='--allow 192.168.178.41'        # la regola di autorizzazione
export URL=http://192.168.178.41/        # il datum L7
export JINRAI_OPERATOR="$(whoami)"       # finisce in ogni record di audit
```

**Aggiungi `--dry-run` a qualsiasi comando** per far girare tutto il percorso
rifiutabile (allowlist, gate di autorizzazione, preflight dei privilegi) e
stampare il piano **senza mandare un byte**. È il modo giusto di provare una riga
nuova: se il dry-run passa, il run vero parte.

I comandi marcati `[sudo]` aprono raw socket: servono `CAP_NET_RAW` o root. In
alternativa a `sudo`, una volta sola:

```sh
sudo setcap cap_net_raw+ep /home/c2/jinrai/target/release/jinrai
```

---

## I flag obbligatori, spiegati una volta sola

Compaiono in **tutti** i comandi del playbook. Qui la spiegazione completa; nelle
tabelle dei singoli test case li trovi con una riga di richiamo.

| Switch | Cosa fa |
|---|---|
| `--allow <IP\|CIDR\|nome>` | **La lista di autorizzazione. Ripetibile, senza default: vuota non autorizza niente.** È il cardine di sicurezza: jinrai rifiuta di mandare traffico a qualsiasi cosa non coperta. La validazione è sul **dato così com'è scritto**: un IP viene confrontato con le regole IP/CIDR, un nome DNS con le regole DNS. Un nome che risolve su un IP autorizzato ma non corrisponde a nessuna regola DNS **viene rifiutato**. |
| `--target <IP>` | Destinazione per L3/L4. **Ripetibile**: più target in un run è la forma "carpet bombing", il carico viene distribuito su tutti. Ogni target deve corrispondere a una regola `--allow`. |
| `--url <URL>` | Il datum per L7 (al posto di `--target`). L'host viene autorizzato, risolto **una volta sola** e l'IP viene pinnato nel client HTTP: il DNS non può cambiare destinazione a run avviato, e i redirect non vengono seguiti (uscirebbero dal pin). |
| `--ack-lab` | Presa d'atto che il bersaglio è un sistema di lab autorizzato e isolato. **Obbligatorio per ogni layer**, non solo L3/L4 — un run L7 non richiede privilegi ed è il più facile da lanciare per sbaglio. Non serve con `--dry-run`. |
| `--audit-log <PATH>` | Registro append-only con catena di hash SHA-256: un record prima del traffico (`RunAuthorized`), uno a fine run (`RunCompleted`), uno per ogni rifiuto (`RunRefused`). Se il file non si apre, il run **non parte**. In alternativa esiste `--no-audit`, che dice a voce alta quello che omettere `--audit-log` diceva in silenzio. |
| `--rate <N>` | **Tetto di sicurezza in unità/secondo, non un obiettivo.** Nessun profilo di carico può superarlo. Cosa sia una "unità" dipende dal modulo — è indicato in ogni test case. Max 10 000 000. |
| `--duration <SECS>` | Durata a orologio del run, in secondi. Max 86400. Limita il **traffico**, non solo il dispatch: le richieste ancora in volo vengono cancellate dopo `--drain-timeout-ms`. |
| `--dry-run` | Valida, autorizza, fa il preflight, stampa il piano, **non manda niente**. Esente da `--ack-lab` e dall'obbligo di audit. |
| `--color <auto\|always\|never>` | Colora il summary. `auto` (default) colora solo se stdout è un terminale e `NO_COLOR` non è settata, quindi un report rediretto su file resta in chiaro. Usa `always` se passi l'output in `tee` e vuoi comunque i colori. |
| `--output <human\|line>` | `human` (default) è il blocco leggibile; `line` è la singola riga stabile per script e log scraping. |

**Ctrl-C ferma sempre tutto** (SIGINT e SIGTERM sono agganciati al kill switch),
il drain viene eseguito e il record di audit viene scritto lo stesso.

---

## Test case L3/L4

### 1 — UDP Flood

Il flood volumetrico di base: datagrammi verso una porta, il target deve
processarli e, se non c'è nessuno in ascolto, generare una ICMP port-unreachable
per ognuno.

```sh
jinrai $A --target $T --port 53 --layer l4 --l4-mode udp \
  --payload-size 512 --rate 50000 --duration 60 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `$A` = `--allow 192.168.178.41` | Autorizza il target. Senza, il run è rifiutato. |
| `--target $T` | Destinazione dei datagrammi. |
| `--port 53` | Porta di destinazione. Qui una sola. |
| `--layer l4` | Seleziona il modulo L3/L4 (`l3` e `l4` selezionano lo stesso modulo; cambia solo come si riporta il layer). |
| `--l4-mode udp` | La primitiva: UDP flood. **Non richiede privilegi**, usa la socket UDP del kernel. |
| `--payload-size 512` | Byte di payload per datagramma (default 64). È la leva sulla banda: 50000/s × 512 B ≈ 205 Mbit/s. |
| `--rate 50000` | Tetto: 50 000 datagrammi/secondo. |
| `--duration 60` | 60 secondi. |
| `$REQ` | `--ack-lab` + `--audit-log` (vedi sopra). |

**Sul filo:** un pacchetto per unità, IP sorgente reale (mai spoofato).
**Da leggere:** se `attempts` sta sotto il tetto con `failed 0`, la riga
`bound by` (gialla) dice se il limite era questa macchina e non il target.

---

### 2 — UDP Flood RandomPorts

Stessa cosa, ma la porta di destinazione cambia a ogni pacchetto: una regola di
firewall agganciata a una porta vede un rivolo invece del run.

```sh
jinrai $A --target $T --port 1-65535 --port-order random --layer l4 --l4-mode udp \
  --rate 50000 --duration 60 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `--port 1-65535` | **Spec di porte, non un numero.** Accetta un valore (`443`), una lista (`80,443,8080`), un range inclusivo (`1000-2000`) o un misto (`80,8000-8100`). Tenuto come range, quindi `1-65535` costa due interi. La porta 0 è sempre rifiutata. |
| `--port-order random` | Estrae una porta per pacchetto: pacchetti consecutivi non sono correlati. Il default `sequential` percorre il set nell'ordine scritto avanzando a ogni passata sui target (così un run multi-target enumera l'intero prodotto target × porte). |

Gli altri switch: come al test 1.

> **Garanzia che non cambia:** varia **solo la porta di destinazione**. L'IP
> sorgente non è mai spoofato e la porta sorgente resta deterministica —
> randomizzare quella renderebbe i flussi non attribuibili, ed è assente per la
> stessa ragione per cui è assente lo spoofing.

---

### 3 — UDP CarpetBombing

Più indirizzi di destinazione × un range di porte: nessun singolo IP porta tutto
il run, quindi una soglia per-destinazione non scatta.

```sh
jinrai $A --allow 192.168.178.42 --target $T --target 192.168.178.42 \
  --port 1-65535 --port-order random --layer l4 --l4-mode udp \
  --rate 50000 --duration 60 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `--allow 192.168.178.42` | **Seconda regola di allowlist.** Ogni target va autorizzato: aggiungere `--target` senza `--allow` fa rifiutare il run. |
| `--target` × 2 | I due bersagli. Il carico viene diviso tra loro, non moltiplicato. |
| `--port 1-65535 --port-order random` | Come al test 2. |

**Sul filo:** `--rate 50000` resta il totale del run, ~25 000/s per target.

---

### 4 — UDP Fragmentation `[sudo]`

Il datagramma viene tagliato **dentro l'header di trasporto**: il frammento 0
contiene gli 8 byte di header UDP, il frammento 1 il payload. La porta di
destinazione non è leggibile finché non arrivano entrambi, quindi il target deve
tenere lo stato di riassemblaggio prima di poter decidere qualsiasi cosa.

```sh
sudo -E jinrai $A --target $T --port 53 --layer l3 --l4-mode udp-frag \
  --payload-size 1400 --rate 20000 --duration 60 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `sudo -E` | Serve `CAP_NET_RAW`: jinrai costruisce l'header IPv4 da sé. `-E` conserva l'ambiente (`JINRAI_OPERATOR`). **Solo IPv4.** |
| `--layer l3` | Questi modi riportano **L3**: quello che stressano è il layer IP (la tabella di riassemblaggio), non la porta. |
| `--l4-mode udp-frag` | 2 frammenti per unità, tagliati su confine di 8 byte. Ogni unità ha il **proprio IP identification**, così le entry di riassemblaggio si accumulano invece di sovrascriversi. |
| `--payload-size 1400` | Payload del datagramma **prima** della frammentazione. Minimo forzato a 8 byte: sotto non ci sarebbe niente da tagliare oltre l'header UDP e il run manderebbe datagrammi interi spacciandoli per un frag flood. |
| `--rate 20000` | ⚠️ **`--rate` conta i datagrammi, non i pacchetti.** 20 000 unità/s = **40 000 pacchetti/s** sul filo. Il summary lo dichiara nella riga `of which`. |

---

### 5 — UDP Fragmentation RandomPorts `[sudo]`

Frammentazione e porte casuali insieme: la porta è nel frammento 0 e cambia a
ogni unità.

```sh
sudo -E jinrai $A --target $T --port 1-65535 --port-order random --layer l3 \
  --l4-mode udp-frag --payload-size 1400 --rate 20000 --duration 60 $REQ
```

Switch: unione dei test 2 e 4, stessi significati.

---

### 6 — TCP SYN Flood `[sudo]`

Il classico: SYN a raffica, ogni SYN costa al target una entry nella coda di
half-open.

```sh
sudo -E jinrai $A --target $T --port 445 --layer l4 --l4-mode syn \
  --rate 50000 --duration 60 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `--l4-mode syn` | SYN raw. L'IP sorgente è **l'indirizzo reale scelto dal routing** (`source_ipv4_for`), mai uno arbitrario: significa che le SYN-ACK tornano indietro davvero e il test è attribuibile. |
| `--port 445` | Porta di destinazione. Sceglila su un servizio che esiste, altrimenti misuri il path del RST. |

**Nota lab:** questo modo **passa** il firewall Proxmox (apre stato conntrack
legittimo). I modi out-of-state al test 12–13 no.

---

### 7 — TCP SYN RandomPorts `[sudo]`

```sh
sudo -E jinrai $A --target $T --port 1-65535 --port-order random --layer l4 \
  --l4-mode syn --rate 50000 --duration 60 $REQ
```

Switch: test 6 + `--port`/`--port-order` del test 2.

---

### 8 — TCP CarpetBombing `[sudo]`

```sh
sudo -E jinrai $A --allow 192.168.178.42 --target $T --target 192.168.178.42 \
  --port 1-65535 --port-order random --layer l4 --l4-mode syn \
  --rate 50000 --duration 60 $REQ
```

Switch: test 3 con `--l4-mode syn` al posto di `udp`.

---

### 9 — TCP Fragmentation RandomPorts `[sudo]`

Una SYN frammentata in 3: l'header TCP di 20 byte viene tagliato 8 + 8 + 4, così
**le porte finiscono nel frammento 0 e i flag di controllo nel frammento 1**.
Niente sul percorso può dire che è una SYN senza prima riassemblare.

```sh
sudo -E jinrai $A --target $T --port 1-65535 --port-order random --layer l3 \
  --l4-mode tcp-frag --rate 20000 --duration 60 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `--l4-mode tcp-frag` | 3 frammenti per unità. ⚠️ **`--rate 20000` = 60 000 pacchetti/s** sul filo. |
| `--layer l3` | Come al test 4: è il layer IP a essere sotto test. |

---

### 10 — TCP Connect / handshake flood

Handshake veri, tenuti aperti contro il backlog di accept. Nessun privilegio:
usa lo stack del kernel, e funziona anche su IPv6.

```sh
jinrai $A --target $T --port 445 --layer l4 --l4-mode tcp \
  --concurrency 512 --connect-timeout-ms 500 --rate 10000 --duration 60 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `--l4-mode tcp` | Connect flood: apre connessioni complete e le tiene. |
| `--concurrency 512` | **Socket aperte contemporaneamente** (default 256, cap a 4096 thread). È l'impronta locale del run *ed* è il parallelismo degli handshake. Quando si arriva a N, ammettere un nuovo tentativo chiude la connessione più vecchia. |
| `--connect-timeout-ms 500` | Quanto un tentativo può restare irrisolto prima di essere abbandonato e contato nel bucket errno `timeout` (default 500). **Questa è la leva vera:** un tentativo che va in timeout occupa il suo slot per tutto il timeout, quindi appena una quota significativa fallisce, abbassare questo valore alza il rate raggiungibile molto più che alzare `--concurrency`. |
| `--rate 10000` | Tetto sui tentativi/s. Il rate realmente raggiungibile è circa `--concurrency` ÷ durata media del tentativo. |

**Da leggere:** se `attempts` è molto sotto il tetto, la riga gialla `bound by`
dice **quale delle due manopole** toccare, con l'aritmetica in chiaro.

---

### 11 — TCP PSH-ACK / data flood

Connessioni reali riempite di dati applicativi: il target non deve solo
accettare, deve leggere e consegnare i byte allo strato sopra.

```sh
jinrai $A --target $T --port 445 --layer l4 --l4-mode data \
  --payload-size 1400 --concurrency 256 --rate 5000 --duration 60 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `--l4-mode data` | Flood di segmenti PSH-ACK su connessioni stabilite. Nessun privilegio, IPv4 + IPv6. |
| `--payload-size 1400` | Byte per write. Qui è la dimensione della scrittura applicativa, non del datagramma. |
| `--concurrency 256` | Connessioni tenute aperte contemporaneamente. |

---

### 12 — TCP ACK / RST / FIN flood `[sudo]`

Flag singoli su connessioni che non esistono: mette alla prova il tracciamento
di stato di firewall e stack.

```sh
sudo -E jinrai $A --target $T --port 445 --layer l4 --l4-mode ack \
  --rate 50000 --duration 60 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `--l4-mode ack` | Un flag per modo. Sostituibile con `rst`, `fin`, `urg`, `cwr`, `ece` — `urg`/`cwr`/`ece` mandano un segmento altrimenti vuoto che porta solo quel bit (raramente isolato nel traffico reale). |

> ⚠️ **Lab:** questi sono modi *out-of-state*. Il firewall del datacenter Proxmox
> li scarta tutti prima di consegnarli (vedi [in fondo](#i-modi-out-of-state-e-il-firewall-proxmox)).

---

### 13 — TCP flag anomali (Xmas / NULL) `[sudo]`

Combinazioni di flag illegali o contraddittorie: probe sulla gestione dei campi
di controllo malformati da parte di firewall, IDS e stack TCP.

```sh
sudo -E jinrai $A --target $T --port 445 --layer l4 --l4-mode xmas \
  --rate 50000 --duration 60 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `--l4-mode xmas` | FIN+PSH+URG accesi insieme. Sostituibile con: `null` (nessun flag), `syn-fin` e `syn-rst` (combinazioni contraddittorie), `syn-ack` (una *risposta* legale a una SYN che il target non ha mai mandato — flag legali, **stato** illegale). |

> ⚠️ Anche questi sono out-of-state: stesso avviso del test 12.

---

### 14 — TCP options bomb `[sudo]`

Una SYN con il blocco opzioni riempito al massimo consentito (40 byte): il costo
è nel parsing delle opzioni, non nel volume.

```sh
sudo -E jinrai $A --target $T --port 445 --layer l4 --l4-mode tcp-options \
  --rate 50000 --duration 60 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `--l4-mode tcp-options` | SYN con blocco opzioni massimale. Apre stato legittimo, quindi **passa** il firewall del lab. |

---

### 15 — ICMP Flood `[sudo]`

```sh
sudo -E jinrai $A --target $T --layer l3 --l4-mode icmp \
  --payload-size 1400 --rate 50000 --duration 60 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `--l4-mode icmp` | Echo request flood. Sostituibile con `icmp-timestamp` (tipo 13) e `icmp-address-mask` (tipo 17): ognuno costringe il target a **rispondere direttamente**. |
| *(nessun `--port`)* | I modi ICMP non hanno porte. Passare `--port` qui non serve. |
| `--layer l3` | Vero L3. |
| `--payload-size 1400` | Byte di payload nell'echo. |

---

### 16 — GRE-Attack `[sudo]`

Un header IPv4 esterno con protocollo 47, l'header GRE versione 0 di 4 byte
(RFC 2784), e dentro un datagramma IPv4/UDP completo. Un target che accetta il
protocollo 47 deve riconoscerlo, togliere l'header esterno e **rientrare nel
proprio stack IP** con il pacchetto interno: circa il doppio del lavoro per un
pacchetto di banda.

```sh
sudo -E jinrai $A --target $T --port 53 --layer l3 --l4-mode gre \
  --rate 20000 --duration 60 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `--l4-mode gre` | Il flood incapsulato. |
| `--port 53` | ⚠️ È la porta di destinazione **del datagramma interno**, non dell'esterno (GRE non ha porte). |

> **Nessuno spoofing nemmeno dentro il tunnel:** il datagramma incapsulato è
> indirizzato dallo stesso indirizzo sorgente reale del pacchetto esterno, e il
> costruttore non ha alcun argomento con cui esprimere altro.

---

### 17 — MultiVector UDP + TCP `[sudo]`

```sh
sudo -E jinrai $A --target $T --port 445 --layer l4 \
  --l4-mode udp --l4-mode syn --rate 60000 --duration 60 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `--l4-mode` ripetuto | **Ogni occorrenza aggiunge un vettore.** Girano in parallelo, un thread ciascuno, contro gli stessi target, con una sola `--duration`, un solo kill switch, un solo record di audit e un solo summary. |
| `--rate 60000` | ⚠️ **Il tetto è condiviso, non per vettore.** Due vettori a 60 000 emettono **30 000/s ciascuno**. Un tetto che si moltiplica alle spalle dell'operatore non sarebbe un tetto. Un rate troppo piccolo per essere diviso viene rifiutato invece di azzerare un vettore. |

**Da leggere:** la riga `of which` dà il **breakdown per vettore** — un totale
solo non distingue "sono partiti entrambi" da "uno ha fatto tutto il lavoro".

---

### 18 — MultiVector UDP / TCP / ICMP `[sudo]`

```sh
sudo -E jinrai $A --target $T --port 445 --layer l4 \
  --l4-mode udp --l4-mode syn --l4-mode icmp --rate 60000 --duration 60 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `--l4-mode icmp` nel mix | Consentito. `--port` resta obbligatorio **per i vettori che ne indirizzano una**; ICMP lo ignora. |
| `--layer l4` | Un run tutto-ICMP riporta L3, un run misto riporta **L4**: chiamare L3 un run che floodda una porta la sottovaluterebbe. |
| `--rate 60000` | 3 vettori → 20 000/s ciascuno. |

---

### 19 — MultiVector frammentazione + flood `[sudo]`

```sh
sudo -E jinrai $A --target $T --port 1-65535 --port-order random --layer l4 \
  --l4-mode udp-frag --l4-mode tcp-frag --l4-mode udp --rate 60000 --duration 60 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| tre `--l4-mode` | 20 000 unità/s ciascuno. ⚠️ In pacchetti: udp-frag ×2 + tcp-frag ×3 + udp ×1 = **120 000 pacchetti/s**. Il preflight controlla **ogni** vettore, quindi un `CAP_NET_RAW` mancante ferma il run prima di qualsiasi traffico. |
| `--port-order random` | Vale per tutti i vettori che indirizzano una porta. |

---

## Test case L7

Nessuno di questi richiede privilegi. Tutti usano `--url` invece di `--target`.

### 20 — GET Flood, con verdetto

```sh
jinrai $A --url $URL --l7-method get --rate 2000 --duration 60 \
  --slo-max-5xx-rate 0.01 --slo-max-p99-ms 500 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `--url $URL` | Il datum autorizzato. L'host viene risolto una volta e pinnato. |
| `--l7-method get` | Flood di richieste veloci (default). Sostituibile con `post` e `head`. |
| `--rate 2000` | Richieste/secondo. |
| `--slo-max-5xx-rate 0.01` | **FAIL del run se più dell'1% delle risposte è 5xx.** Un SLO non rispettato fa uscire con codice ≠ 0: è così che una pipeline distingue "il target ha retto" da "il target ha ceduto". |
| `--slo-max-p99-ms 500` | FAIL se la latenza p99 di fine run supera 500 ms. |

Altri SLO disponibili: `--slo-max-error-rate <0.0-1.0>` (errori di trasporto),
`--slo-max-4xx-rate <F>` (spento di default).

---

### 21 — GET-Random-Flood

Ogni richiesta chiede un URI che **non esiste**: niente è cacheabile, l'origine
risponde (e di solito logga) tutto.

```sh
jinrai $A --url $URL --l7-method get --random-path --rate 2000 --duration 60 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `--random-path` | Aggiunge un segmento casuale fresco al path a ogni richiesta. Tocca **solo** il path: l'host non viene mai alterato, quindi l'autorizzazione e il pin DNS reggono per ogni richiesta del run. |

**Da leggere:** un 100% di 4xx qui è il test che funziona, non il target rotto —
il summary lo dichiara con `varying: random path`.

---

### 22 — GET /VALID_RANDOM

Come sopra, ma i path sono presi da endpoint che **esistono davvero**: il carico
finisce sugli handler reali invece che sul path del 404.

```sh
jinrai $A --url $URL --l7-method get --path-file /home/c2/endpoints.txt \
  --rate 2000 --duration 60 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `--path-file <PATH>` | Un path per riga, righe vuote e commenti `#` saltati, **ogni voce deve iniziare con un singolo `/`**. Una voce che sposterebbe il run su un'altra origine **fa rifiutare il run** — non viene saltata in silenzio, perché saltarla vorrebbe dire che la lista ha girato diversamente da come si legge. Un file illeggibile fa fallire il parsing degli argomenti, prima ancora dell'ack di lab. |

Esempio di `endpoints.txt`:

```
# endpoint reali del target
/api/v1/health
/api/v1/users?page=2
/static/app.css
```

---

### 23 — POST Flood

```sh
jinrai $A --url $URL --l7-method post --body '{"q":"load"}' --cache-bust \
  --rate 1000 --duration 60 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `--l7-method post` | Percorso di scrittura. |
| `--body '<STRING>'` | Il corpo mandato con ogni POST. |
| `--cache-bust` | Aggiunge una query `_cb=<n>` unica, così una CDN o una cache non può rispondere al posto dell'origine. |

---

### 24 — SearchField-Flood

La query che nessuna cache può servire: un termine nuovo a ogni richiesta.

```sh
jinrai $A --url ${URL}search --l7-method get --search-param q \
  --rate 2000 --duration 60 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `--search-param q` | Manda `q=<termine casuale>` a ogni richiesta: in query string per `get`/`head`, in corpo form-encoded per `post` (dove **sostituisce** `--body`). Il termine è una parola pronunciabile, non un blob esadecimale: un blob è ugualmente non cacheabile, ma un termine che sembra un termine raggiunge lo stesso percorso di codice di una ricerca vera. |

---

### 25 — THOR / Session-Exhaustion

Sessione nuova **e** query nuova a ogni richiesta: né la cache né lo store delle
sessioni possono assorbire niente.

```sh
jinrai $A --url $URL --l7-method get --session-cookie JSESSIONID --search-param q \
  --rate 2000 --duration 60 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `--session-cookie JSESSIONID` | Manda un cookie `JSESSIONID=<valore>` distinto e sconosciuto a ogni richiesta, così il target alloca o cerca stato di sessione per ognuna invece di riusarne una per tutto il run. Usa il nome giusto per lo stack sotto test: `JSESSIONID`, `PHPSESSID`, `connect.sid`, `ASP.NET_SessionId`. |
| `--search-param q` | Come al test 24, si combina. |

---

### 26 — Keep-alive connection exhaustion

La forma controllata di GoldenEye/XerXes: il carico viene fissato a un numero
massimo di connessioni tenute occupate.

```sh
jinrai $A --url $URL --l7-method get --max-connections 50 --rate 5000 --duration 60 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `--max-connections 50` | Tetto sulle richieste in volo ≈ connessioni keep-alive concorrenti (default 1024). Serve a sondare il limite di slot/worker del server. **`--rate` da solo non limita le connessioni**: contro un target lento, rate × latenza *è* il numero di socket, ed è questo flag a impedire che il run diventi un test dei descriptor della tua macchina. `0` = illimitato, scelta esplicita, mai il default. |

---

### 27 — Slowloris

Connessioni mezze aperte, una riga di header ogni tanto per tenerle vive.

```sh
jinrai $A --url $URL --l7-method slowloris --slow-connections 500 --drip-ms 10000 \
  --rate 50 --duration 300 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `--l7-method slowloris` | Header parziali lenti. Funziona anche su `https://` (handshake TLS vero, poi si sgocciola dentro il tunnel). |
| `--slow-connections 500` | **Tetto di connessioni concorrenti** per i modi lenti e per websocket/sse (default 100). È il numero che stai davvero testando. |
| `--drip-ms 10000` | Intervallo tra un tick e l'altro (default 10000): qui, ogni quanto si scrive un pezzo di header. Va tenuto **sotto** il read timeout del target, altrimenti è il target a chiudere e non hai misurato niente. |
| `--rate 50` | ⚠️ Per i modi lenti il tetto è **connessioni aperte al secondo**, non richieste. Con 500 connessioni e 50/s ci vogliono 10 s per arrivare a regime. |
| `--duration 300` | Questi test hanno senso lunghi. |

**Da leggere:** dichiarare il tetto di connessioni **silenzia** le note di
scostamento (`bound by`): il run smette di aprire perché ha raggiunto il tetto
che hai chiesto tu, non perché la macchina non ce la faceva.

---

### 28 — RUDY (slow POST body)

```sh
jinrai $A --url $URL --l7-method slowbody --slow-connections 500 --drip-ms 10000 \
  --rate 50 --duration 300 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `--l7-method slowbody` | Richiesta completa con `Content-Length` dichiarato, corpo sgocciolato. |
| `--drip-ms 10000` | Intervallo tra un pezzo di corpo e il successivo. |

Gli altri: come al test 27.

---

### 29 — Slow-read

Lo specchio in lettura di slowbody: richiesta completa e corretta, poi la
risposta viene drenata un pezzetto per tick con la finestra di ricezione
ristretta, così il server non riesce a svuotare il suo buffer.

```sh
jinrai $A --url $URL --l7-method slow-read --slow-connections 500 --drip-ms 10000 \
  --rate 50 --duration 300 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `--l7-method slow-read` | Come sopra. Punta a un URL che restituisce una risposta **grande**, altrimenti non c'è niente da trattenere. |
| `--drip-ms 10000` | Qui è l'intervallo di **lettura** di un chunk. |

---

### 30 — WebSocket session exhaustion

Il test che nessun read timeout ritira: niente è lento e niente è malformato,
sono sessioni corrette che restano aperte.

```sh
jinrai $A --url ${URL}ws --l7-method websocket --slow-connections 500 \
  --drip-ms 15000 --rate 100 --duration 300 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `--l7-method websocket` | Upgrade RFC 6455 fatto per bene, chiave `Sec-WebSocket-Key` di 16 byte fresca per connessione. |
| `--url ${URL}ws` | ⚠️ **`http://` e `https://`, non `ws://`/`wss://`** — l'upgrade *è* una richiesta HTTP/1.1. Per wss usa `https://`. |
| `--slow-connections 500` | Sessioni concorrenti tenute: è il ceiling che stai misurando. |
| `--drip-ms 15000` | Intervallo del Ping vuoto mascherato che tiene viva la sessione. |
| `--rate 100` | Connessioni aperte al secondo. |

**Da leggere:** la riga `of which` separa un server che **rifiuta** il trasporto
(path sbagliato, upgrade non supportato) da una connessione che non ha mai avuto
risposta. Sono cose diverse e un solo contatore non le distingue.

---

### 31 — SSE session exhaustion

Stessa idea con un event-stream, che non ha nemmeno bisogno di keep-alive: è il
server a tenerlo aperto per disegno.

```sh
jinrai $A --url ${URL}events --l7-method sse --slow-connections 500 \
  --rate 100 --duration 300 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `--l7-method sse` | GET normale con `Accept: text/event-stream`, tenuta aperta e drenata. |

---

### 32 — TLS Handshake Flood (THC-SSL-DoS)

Handshake completo, connessione buttata, ripetere: l'asimmetria è tutta nel costo
crittografico lato server.

```sh
jinrai $A --url https://$T/ --l7-method tls-handshake --max-connections 200 \
  --rate 500 --duration 60 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `--l7-method tls-handshake` | **Solo `https://`.** Il tetto conta handshake/secondo. |
| `--url https://...` | Obbligatoriamente TLS. Il certificato del server **non viene verificato** ed è deliberato: il confine di sicurezza è l'host autorizzato e pinnato, non l'identità TLS del peer; il run non manda segreti e non legge risposte. |
| `--max-connections 200` | Vale anche per i metodi TLS una-connessione-per-unità. |

---

### 33 — TLS ClientHello parser stress

Nessun handshake completato: si spende tutta la connessione nel far analizzare al
target un ClientHello enorme ma **legale**.

```sh
jinrai $A --url https://$T/ --l7-method tls-big-hello --rate 500 --duration 60 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `--l7-method tls-big-hello` | Un hello ben formato gonfiato fino al tetto di 16 KiB del record: 2048 cipher suite che il server deve intersecare + padding RFC 7685. Sostituibile con `tls-sni-bomb`, che isola l'SNI: ~12 KiB di `server_name` fatto di label DNS legali da ≤63 byte, così sopravvive ai controlli di sintassi e **arriva alla lookup del vhost** invece di essere scartato come malformato. |
| `--rate 500` | Hello al secondo. |

**Da leggere:** ⚠️ **non guardare il conteggio dei completati, guarda la riga
`of which`.** `parsed` significa che il target ha fatto il lavoro;
`refused with an alert` è il risultato **sano** — il parser ha rifiutato.

---

### 34 — HTTP/2 Rapid Reset (CVE-2023-44487)

Apri uno stream, mandi subito RST_STREAM: il client non paga quasi niente, il
server sì, e il limite di stream concorrenti non lo ferma perché lo slot si
libera all'istante.

```sh
jinrai $A --url https://$T/ --l7-method h2-rapid-reset --rate 5000 --duration 60 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `--l7-method h2-rapid-reset` | Il tetto conta **reset al secondo**. Su `https` usa ALPN `h2`; su `http` usa h2c a conoscenza pregressa. |

---

### 35 — Gli altri flood HTTP/2

Stessa identica forma del test 34, cambia solo `--l7-method`:

| Metodo | Cosa fa fare al server |
|---|---|
| `h2-made-you-reset` | CVE-2025-8671: richiesta completa poi WINDOW_UPDATE a incremento 0, così è **il server** a resettare lo stream (aggira le mitigazioni per rapid-reset). |
| `h2-continuation` | CVE-2024-27316: HEADERS senza END_HEADERS + CONTINUATION all'infinito. |
| `h2-settings` | CVE-2019-9515: SETTINGS vuoti che il server deve ACKare. |
| `h2-ping` | CVE-2019-9512: PING che il server deve PONGare. |
| `h2-window-update` | CVE-2019-9514: update di flow control a livello connessione sullo stream 0. |
| `h2-priority` | CVE-2019-9513 (Resource Loop): frame che rimescolano l'albero delle priorità. |
| `h2-empty-data` | CVE-2019-9518: DATA di lunghezza 0 senza END_STREAM. |
| `h2-bomb` | CVE-2026-49975: amplificazione header HPACK con riferimenti da 1 byte + finestra iniziale a zero, così la memoria amplificata resta bloccata. |

Per tutti, `--rate` conta **frame al secondo**.

---

### 36 — Header-profile test

```sh
jinrai $A --url $URL --l7-method get \
  --header 'User-Agent: LoadTest/1.0' --header 'Referer: https://intranet/' \
  --rate 2000 --duration 60 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `--header '<K: V>'` | Header extra, **ripetibile**. È il gancio per i test basati sul profilo di richiesta (User-Agent, Referer, Cookie…). |

> Nota: la rotazione di User-Agent/Referer in stile HULK è **fuori scope per
> scelta** — è evasione, non carico. Questo flag serve a mandare un profilo
> dichiarato, non a nasconderlo.

---

## Test case di capacità

### 37 — Breaking point (knee)

Sale a gradini fino al tetto e **si ferma al primo gradino che rompe lo SLO**,
riportando il ginocchio della curva di capacità.

```sh
jinrai $A --url $URL --rate 5000 --duration 300 --discover-knee \
  --slo-max-5xx-rate 0.02 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `--discover-knee` | Attiva la scoperta del punto di rottura. **Richiede almeno un `--slo-max-*-rate`**, altrimenti il run è rifiutato: senza soglia non c'è modo di sapere cos'è "rotto". Trovare il ginocchio è un **successo** (exit 0). Il watchdog viene sospeso durante la scoperta. |
| `--slo-max-5xx-rate 0.02` | La soglia che definisce "rotto": 2% di 5xx. |
| `--rate 5000` | Il tetto della rampa. |
| `--duration 300` | Finestra totale, divisa tra i gradini. |

**Da leggere:** la riga `knee` dice *ha retto X/s dentro SLO, ha ceduto a Y/s*.

---

### 38 — Burst / autoscaling

Tiene una baseline, salta al tetto, ricade: la forma che mette alla prova la
reattività dell'autoscaling.

```sh
jinrai $A --url $URL --profile spike --spike-base 200 --spike-secs 30 \
  --rate 5000 --duration 300 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `--profile spike` | La forma del carico. Altri: `constant` (default), `soak`, `ramp`. |
| `--spike-base 200` | Rate della baseline (default: tetto ÷ 5). |
| `--spike-secs 30` | Durata del picco. ⚠️ **Ritagliata da `--duration`, mai aggiunta**: la baseline riempie il resto della finestra. |
| `--rate 5000` | Il picco *è* il tetto. Un profilo modella il traffico **solo fino a** `--rate`, mai oltre. |

---

### 39 — Endurance / soak, con watchdog

```sh
jinrai $A --url $URL --profile soak --rate 500 --duration 3600 \
  --watchdog --slo-max-5xx-rate 0.05 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `--profile soak` | Tenuta piatta lunga: fa emergere leak e degradi lenti. |
| `--duration 3600` | Un'ora. |
| `--watchdog` | **Interrompe il run** quando uno SLO di rate è violato per più finestre consecutive. Può solo **fermare** il traffico, mai aumentarlo. Inerte senza almeno un `--slo-max-*-rate` da guardare (viene segnalato). |
| `--slo-max-5xx-rate 0.05` | Ciò che il watchdog guarda. |

Regolabili: `--watchdog-window <SECS>` (finestra di campionamento, default 5) e
`--watchdog-breaches <K>` (finestre consecutive prima di abortire, default 3).

**Da leggere:** un abort da watchdog stampa `outcome` in **rosso** ed esce con
codice ≠ 0.

---

### 40 — Ramp

```sh
jinrai $A --url $URL --profile ramp --ramp-start 100 --ramp-steps 10 \
  --rate 5000 --duration 300 $REQ
```

| Switch | Cosa fa qui |
|---|---|
| `--profile ramp` | Sale a gradini da `--ramp-start` fino al tetto. |
| `--ramp-start 100` | Rate iniziale (default 0). |
| `--ramp-steps 10` | Numero di gradini di uguale durata (default 10). |

---

## Fuori scope, e perché

| Use case | Perché non c'è |
|---|---|
| **UDP DNS / NTP Reflection** | Richiede lo spoofing dell'IP sorgente. jinrai non ha alcun percorso di spoofing **per progetto**: l'indirizzo sorgente viene sempre dal routing reale, in ogni modo, incapsulamento GRE incluso. È la garanzia su cui poggia il fatto che questo strumento sia usabile in casa. |
| Smurf / Fraggle / amplificazione | Stessa ragione: sono attacchi per riflessione. |
| Ping of Death / teardrop / Boink | Crash di stack storici, non test di resilienza. |
| Rotazione UA/Referer in stile HULK | Evasione di firme vendor, non carico. |
| Renegoziazione TLS | Sostanzialmente superata da TLS 1.3. |

---

## Come si legge il summary

Ogni run finisce con questo blocco. Su terminale è colorato
(`--color auto|always|never`).

```
==== run summary =========================================================
 target     http://192.168.178.41/
 module     L7 / l7-http-get  (HTTP/1.1 forced)
 window     60.0s elapsed of 60.0s planned, rate cap 2000/s
 started    2026-08-03T09:14:02Z
 finished   2026-08-03T09:15:02Z
 attempts   120000 total, 1994.2/s achieved (100% of the 2000/s cap)
 completed  119940 (99.9%)
   status   2xx 118000 (98.4%)  3xx 0 (0.0%)  4xx 800 (0.7%)  5xx 1140 (0.9%)
   protocol HTTP/1.1 119940
 failed     60 (0.1%), of which 60 timed out
            60 x timeout — our own attempt timeout expired first
 latency    p50 12.4ms   p90 45.1ms   p99 210.0ms   max 1.20s
 outcome    ran to completion
 SLO        FAIL (5xx-rate 0.9% > 0.5%)
==========================================================================
```

| Colore | Significato |
|---|---|
| 🟢 **verde** | il run ha fatto il suo lavoro: `completed`, `failed 0`, `2xx`, `SLO: PASS`, `ran to completion` |
| 🟡 **giallo** | un caveat sul **nostro** lato: `bound by`, `not offered`, errno locali (EMFILE, EADDRNOTAVAIL…), abort dell'operatore, `4xx` |
| 🔴 **rosso** | fallimento e gli errori del target: `failed`, `5xx`, errno remoti, `SLO: FAIL`, abort del watchdog, il `WARNING` di run vuoto |

Le righe da non ignorare mai:

- **`attempts … achieved (…% del tetto)`** — dice se il carico chiesto è stato
  davvero prodotto. Senza questa riga un risultato si legge come "il target ha
  retto" anche quando il generatore non è mai arrivato al rate.
- **`bound by`** (gialla) — compare quando il run non ha raggiunto il tetto e
  **nomina il vincolo**. Una percentuale bassa con **zero fallimenti** è la riga
  più fraintendibile che questo strumento possa stampare: sembra identica a un
  target che assorbe la differenza. Se dice `the generator, not the target` o
  `concurrency, not the target`, quel divario **non è carico assorbito**.
- **`of which`** — il breakdown dove "completato" copre esiti che significano
  cose opposte: per vettore nei run multi-vector, parsed/rifiutato nei test TLS
  hello, declinato/senza risposta per websocket e sse.
- **`failed` + i bucket errno** — dicono **di chi** è la colpa. `ECONNREFUSED`,
  `ETIMEDOUT`, `ECONNRESET` sono comportamento del target (il risultato che
  cercavi); `EMFILE`, `ENFILE`, `ENOBUFS`, `EADDRNOTAVAIL` sono un tetto della
  **tua** macchina e non dicono niente sul target.
- **`WARNING`** — 0 completati con soli fallimenti: non è stato testato niente,
  e il processo esce con codice ≠ 0. Un `completed 0` è **rosso**, non verde, e
  in quel caso anche `outcome` diventa giallo: "ran to completion" verde sopra un
  WARNING rosso sarebbe esattamente il falso-verde da evitare.

---

## Verifica dell'audit log

```sh
jinrai --verify-audit /home/c2/runs.jsonl
```

Ricalcola l'intera catena di hash e stampa ogni record in forma leggibile.
Esce 0 se è intatta, ≠ 0 nominando il primo punto di rottura. La catena
**continua tra un processo e l'altro**: è questo che rende rilevabile un run
cancellato in mezzo.

Onestà sui limiti: è **evidenza di manomissione, non non-ripudio**. Chi riscrive
l'intero file può ricalcolare una catena pulita; chiudere quel buco richiede HMAC
o un'ancora esterna, ed è fuori scope.

---

## I modi out-of-state e il firewall Proxmox

Il firewall del datacenter Proxmox scarta **ogni** flood L4 fuori stato — `ack`,
`fin`, `rst`, `urg`, `cwr`, `ece`, `syn-ack`, `syn-fin`, `syn-rst`, `xmas`,
`null` — con una regola generata da PVE in cima alla catena:

```
-A PVEFW-FORWARD -m conntrack --ctstate INVALID -j DROP
```

`sendto()` riesce comunque dentro la VM, quindi **jinrai riporta
`5000 completed (100%), failed 0` mentre al target non arriva niente**. Non c'è
segnale nel summary che il run era vuoto: la sonda va fatta fuori.

Diagnosi, sull'host `pve`:

```sh
iptables -Z                                  # azzera i contatori
# ...lancia il run...
iptables -L PVEFW-FORWARD -nvx | head        # ~N pkt sulla regola INVALID = firma
```

Per farli passare: `enable: 0` in `/etc/pve/firewall/cluster.fw`, verifica che
`iptables -L -n | grep -c PVEFW` arrivi a 0, **e rimetti tutto dopo** — riguarda
ogni VM dell'host, non solo quella sotto test.

Passano invece senza toccare niente: `syn`, `tcp-options`, `udp`, `tcp`, `data`,
i tre modi ICMP e tutto L7, perché aprono stato conntrack legittimo.

Non diagnosticare mai da Wireshark su una terza macchina: cattura alla sorgente.

```sh
tcpdump -ni any 'host 192.168.178.41 and tcp port 445'
```
