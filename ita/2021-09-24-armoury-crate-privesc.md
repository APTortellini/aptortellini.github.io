---
layout: post
title: [ITA] Stealing weapons from the Armoury	
subtitle: Analisi della privilege escalation in ASUS ROG Armoury Crate Lite Service v4.2.8 (CVE-2021-40981)
image: /img/armourytortellino.jpg
published: true
author:
- last
---
[![armoury pwnd]({{site.baseurl}}/img/armourytortellino.jpg)]({{site.baseurl}}/img/armourytortellino.jpg)
### TL;DR
Il software [ASUS ROG Armoury Crate](https://rog.asus.com/us/armoury-crate/) installa un servizio chiamato Armoury Crate Lite Service, vulnerabile a phantom DLL hijacking. Cio' permette a un utente non privilegiato di eseguire codice nel contesto di altri utenti, amministratori inclusi. Per sfruttare la vulnerabilita', un amministratore deve autenticarsi sulla macchina compromessa dopo che un attaccante ha posizionato una DLL malevola nel path `C:\ProgramData\ASUS\GamingCenterLib\.DLL`. ASUS ha fixato la vulnerabilita' rilasciando la versione v4.2.10 di Armoury Crate Lite Service.

### Introduzione
Salve compagni di viaggio, e' [last](https://twitter.com/last0x00) che vi scrive! Recentemente mi sono messo alla ricerca di qualche vulnerabilita' qua e la' (devo lavorare sull'impiego del mio tempo libero, lo so). Piu' precisamente mi sono concentrato sulla caccia di un particolare tipo di vulnerabilita' chiamato phantom DLL hijacking ("statece", lo lascio in inglese che tradotto faceva un po' ~~schifarcazzo~~ pieta') che su Windows puo' portare, nel migliore dei casi, a backdoor negli applicativi o, nel peggiore dei casi, a bypass di UAC e/o privilege escalation.  

I phantom DLL hijacking sono una sottocategoria dei DLL hijacking, un tipo di vulnerabilita' in cui un attaccante forza un processo vittima a caricare una DLL arbitraria, sostituendola a quella legittima. Si dicono phantom quando la DLL in questione e' proprio assente nel filesystem, mentre quelli classici vanno a sostituire una DLL che invece e' presente.  

Ricordiamo cos'e' una DLL per chi si fosse perso: una Dynamic-Link Library (DLL) e' un tipo di Portable Executable (PE) su Windows, come i famigerati .exe, con la differenza che essa non e' eseguibile con un normale doppio-click, ma deve essere importata da un processo in esecuzione. Una volta importata, il processo esegue il contenuto della funzione `DllMain` presente all'interno della DLL e puo' usufruire delle funzioni esportate dalla stessa. Per gli amanti del software libero, le DLL sono essenzialmente lo stesso concetto dei file .so su Linux (come la libc). Come accennato, il codice della `DllMain` viene eseguito nel contesto del processo che importa la DLL stessa, significando che, se la DLL dovesse essere caricata da un processo con un token privilegiato, il codice della DLL eseguirebbe in un contesto privilegiato.  

Tornando a noi, giocando con [Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) sono riuscito a trovare un phantom DLL hijacking in [ASUS ROG Armoury Crate](https://rog.asus.com/us/armoury-crate/), un software che e' molto facile trovare in PC e laptop da gaming con una scheda madre TUF/ROG per gestire LED e ventole di raffreddamento.

[![such gaming much 0days gif]({{site.baseurl}}/img/armourycratememe.gif)]({{site.baseurl}}/img/armourycratememe.gif)

L'anno scorso ho assemblato un PC con una scheda madre ASUS TUF (i cugini sfigati di Roma Nord di ASUS ROG) e mi sono ritrovato questa meraviglia di software installato. Tendenzialmente questo tipo di software non e' pensato per essere sicuro - non me la sto prendendo con ASUS, vale lo stesso per le altre case produttrici (ehm ehm... Acer... ehm ehm). E' questo il motivo per cui ho deciso di concentrare i miei sforzi su questo genere di software, la pigrizia vera.

Al momento del login il servizio di Armoury Crate, fantasiosamente chiamato Armoury Crate Lite Service, crea una serie di processi, fra i quali troviamo `ArmouryCrate.Service.exe` e il processo figlio `ArmouryCrate.UserSessionHelper.exe`. Come potete vedere dal prossimo screenshot, il primo esegue con un token SYSTEM, mentre il figlio esegue, nel caso di utenti amministratori, ad alta integrita' - per saperne di piu' riguardo al concetto di integrita' clicca [qui](https://docs.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control). Nel caso in cui l'utente autenticato non sia amministratore, `ArmouryCrate.UserSessionHelper.exe` esegue a integrita' media. Tenetelo a mente, ci tornera' utile piu' avanti.

[![armourycrate arch]({{site.baseurl}}/img/armouryservice0.png)]({{site.baseurl}}/img/armouryservice0.png)

### Si va a caccia
Ora che abbiamo una vaga idea di quale sia il nostro target, passiamo ad analizzare l'approccio che useremo per cercare la vulnerabilita':
1. Isolare tutte le chiamate che portano a una `CreateFile` tramite Process Monitor e che hanno come risultato "NO SUCH FILE" o "PATH NOT FOUND";
2. Ispezioniamo il call stack (la sequenza di funzioni chiamate all'interno del codice) per accertarci che la `CreateFile` avvenga a seguito di una chiamata a una funzione appartenente alla famiglia delle funzioni `LoadLibrary` (come `LoadLibraryA`, `LoadLibraryW`, `LoadLibraryExW` o le loro corrispondenti native dentro ntdll). N.B. `CreateFile` su Windows e' un mezzo false friend, non serve solo a "creare file", ma anche ad aprirne di gia' esistenti;
3. Prendiamo nota del percorso sul filesystem da cui viene caricata la DLL e assicuriamoci che un utente non privilegiato abbia permessi di scrittura sul percorso stesso;
4. Profit!

Andare a caccia di questo genere di vulnerabilita' e' abbastanza semplice in realta' e la metodologia segue quella che ho gia' spiegato in [questo thread su Twitter](https://twitter.com/last0x00/status/1435160730035183616): bisogna avviare Process Monitor con privilegi amministrativi, impostare alcuni filtri e ispezionare i risultati. Dal momento che siamo interessati solo ed esclusivamente a phantom DLL hijacking in grado di portare a privilege escalation (backdoor e UAC bypass li lasciamo agli skid) imposteremo il nostro filtro per mostrarci solo i processi __privilegiati__ (ossia con integrita' >= ad alta) con operazioni di caricamento DLL che falliscono con `PATH NOT FOUND` o `NO SUCH FILE`. Per aprire la mascherina del filtro su Process Monitor cliccate su `Filter -> Filter...`. Vediamo quali filtri impostare per filtrare tutte le operazioni che non rispondono ai canoni riportati:
- Operation - is - CreateFile - Include
- Result - contains - not found - Include
- Result - contains - no such - Include
- Path - ends with - .dll - Include
- Integrity - is - System - Include
- Integrity - is - High - Include

[![procmon filters]({{site.baseurl}}/img/procmonfilter0.png)]({{site.baseurl}}/img/procmonfilter0.png)

Impostati i filtri corretti tornate sulla barra del menu e salvate il filtro cliccando `Filter -> Save Filter...` cosi' che possiamo riutilizzarlo dopo. Visto che molti processi e servizi ad alta integrita' vengono eseguiti all'atto dell'autenticazione dell'utente o all'avvio, dobbiamo instrumentare Process Monitor affinche' tenga traccia del processo di boot e di login. Per fare cio' tornate sulla barra del menu e cliccate `Options -> Enable Boot Logging`, lasciate il resto ai valori di default, chiudete Process Monitor e riavviate il dispositivo. Dopo esservi riautenticati, riaprite Process Monitor e salvate il file `Bootlog.pml` contenente tutto il tracing dell'avvio fatto da Process Monitor. Una volta salvato, Process Monitor procedera' automaticamente a parsarlo e a mostrarvi i risultati. Tornate sulla barra dei menu, premete `Filter -> Load Filter`, caricate il  filtro salvato precedentemente e dovreste trovare qualche riga di operazioni, se siete fortunati e non avete sbagliato nulla. Tutto cio' che vedete __potrebbe__ portare a phantom DLL hijacking.

[![armoury missing DLL]({{site.baseurl}}/img/armourymissingdll.png)]({{site.baseurl}}/img/armourymissingdll.png)

E' ora di investigare i risultati! Nel caso di Armoury Crate, potete vedere che cerca di caricare un file chiamato `.DLL` posizionato nel path `C:\ProgramData\ASUS\GamingCenterLib\.DLL`. Tale path e' molto interessante, in quanto, diversamente dalle sottocartelle di `C:\Program Files\`, le sottocartelle di `C:\ProgramData\` non hanno ACL sicure di default e quindi e' estremamente probabile che un utente non privilegiato sia in grado di scrivere in una di esse.

Per assicurarci che le operazioni `CreateFile` relative agli eventi che stiamo osservando siano effettivamente conseguenza di una chiamata a una funzione della famiglia `LoadLibrary`, possiamo aprire l'evento (doppio click sullo stesso), aprire la tab `Stack` e dare un'occhiata alla pila di funzioni chiamate. Come potete vedere dallo screenshot, nel caso di Armoury Crate la `CreateFile` avviene a seguito di una chiamata a `LoadLibraryExW`:

[![armoury crate loadlibrary]({{site.baseurl}}/img/loadlibrary.png)]({{site.baseurl}}/img/loadlibrary.png)

Per assicurarci che le ACL della directory `C:\ProgramData\ASUS\GamingCenterLib\` siano lasche possiamo usare il convenientissimo cmdlet Powershell `Get-Acl` cosi':
```
Get-Acl 'C:\ProgramData\ASUS\GamingCenterLib' | Select-Object *
```

Questo comando ci restituisce una stringa contenente le ACL in formato SDDL (Security Descriptor Definition Language), che puo' essere interpretata in maniera comprensibile da un umano tramite il cmdlet `ConvertFrom-SddlString`. Tramite tale comando possiamo notare che il gruppo `BUILTIN\Users` ha accesso con privilegi di scrittura sul path in questione:

[![armoury acls]({{site.baseurl}}/img/acl0.png)]({{site.baseurl}}/img/acl0.png)

Un modo molto piu' becero ma ugualmente funzionale di verificare le ACL di un oggetto su Windows e' tramite la tab `View effective access`, nascosta nelle proprieta' dell'oggetto stesso (che nel nostro caso e' la cartella `C:\ProgramData\ASUS\GamingCenterLib\`). Per visualizzare "l'accesso effettivo" che un utente o un gruppo di utenti ha tramite questa funzionalita' basta aprire le proprieta' della cartella, cliccare sulla tab `Security`, poi `Advanced`, selezionare un utente o un gruppo di utenti (nel mio caso ho usato un utente di test non amministratore) e premere su `View effective access`. Il risultato di questa operazione e' una mascherina che mostra quali privilegi ha il singolo utente sulla cartella, mettendolo a sistema con i gruppi di cui fa parte.

[![armoury acls gui]({{site.baseurl}}/img/acl.png)]({{site.baseurl}}/img/acl.png)

Ora che sappiamo che chiunque ha privilegi di scrittura su `C:\ProgramData\ASUS\GamingCenterLib\` dobbiamo solo compilare una DLL contenente il codice che vogliamo eseguire e "dropparla" su disco a quel path con il nome `.DLL`. Come PoC useremo una semplice DLL che aggiungera' un nuovo utente chiamato `aptortellini` con password `aptortellini` e gli dara' privilegi amministrativi aggiungendolo al gruppo degli amministratori locali.

```c++
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    system("C:\\Windows\\System32\\cmd.exe /c \"net user aptortellini aptortellini /add\"");
    system("C:\\Windows\\System32\\cmd.exe /c \"net localgroup administrators aptortellini /add\"");
    return TRUE;
}
```

Ora che abbiamo tutto pronto dobbiamo solo aspettare che un utente amministratore si autentichi sulla macchina. Questo e' necessario poiche' la DLL in questione viene caricata dal processo `ArmouryCrate.UserSessionHelper.exe` che, come abbiamo detto all'inizio dell'articolo, esegue con i privilegi massimi consentiti all'utente autenticato. Nonappena un amministratore si autentica ci ritroveremo con un nuovo utente amministratore, confermando la privilege escalation.

### Root cause analysis

Vediamo adesso brevemente cosa ha causato la vulnerabilita' in questione. Come si evince dal call stack mostrato in uno degli screenshot precedenti, la chiamata a `LoadLibraryExW` avviene   all'offset `0x167d` nella funzione `QueryLibrary`, all'interno della DLL `GameBoxPlugin.dll` caricata dal processo `ArmouryCrate.UserSessionHelper.exe`. Reversando la DLL tramite IDA Pro si puo' inoltre osservare che la maggior parte delle funzioni in questa DLL hanno una sorta di forma di logging che contiene il nome originale della funzione chiamante. Da cio' si puo' evincere che la funzione responsabile della chiamata a `LoadLibraryExW` e' la funzione `DllLoadLibraryImplement`:

[![ida call]({{site.baseurl}}/img/idaloadlibrary.png)]({{site.baseurl}}/img/idaloadlibrary.png)

In questo caso abbiamo due "colpevoli":
1. Una DLL e' caricata senza nessuna forma di check. ASUS ha fixato questa problematica implementando un check crittografico nelle nuove versioni di Armoury Crate Lite Service per assicurarsi che le DLL caricate siano firmate da ASUS;
2. Le ACL della directory `C:\ProgramData\ASUS\GamingCenterLib\` non sono impostate nella maniera corretta. Questa cosa __non e' stata fixata__ da ASUS, significando che se in futuro una problematica del genere dovesse riverificarsi, ci sarebbero i presupposti per una nuova vulnerabilita'. Il processo `ArmouryCrate.UserSessionHelper.exe` tra l'altro cerca nella stessa directory delle DLL con un nome rispondente alla wildcard `??????.DLL`, cosa che potrebbe essere exploitabile. Consiglio di fixare "a mano" le ACL della cartella in questione e rimuovere i privilegi di scrittura a tutti gli utenti non membri del gruppo degli amministratori locali.

### Responsible disclosure timeline (YYYY/MM/DD)
- 2021/09/06: vulnerabilita' riportata ad ASUS tramite il loro portale di disclosure;
- 2021/09/10: ASUS conferma di aver ricevuto il report e lo inoltra al suo team di sviluppo;
- 2021/09/13: Il team di sviluppo conferma la presenza della vulnerabilita' e afferma che sara' fixata nella successiva release, prevista per la 39esima settimana dell'anno in corso(27/09 - 01/10);
- 2021/09/24: ASUS conferma che la vulnerabilita' e' stata fixata nella versione 4.2.10 del servizio;
- 2021/09/27: il MITRE assegna il CVE con codice [CVE-2021-40981](https://nvd.nist.gov/vuln/detail/CVE-2021-40981) a questa vulnerabilita';

Kudos ad ASUS per la celerita' e professionalita' nella gestione della vulnerabilita'. E' tutto per oggi e alla prossima!

last, out.
