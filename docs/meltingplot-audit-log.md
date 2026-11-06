# Anforderungen: Audit-Log für Duet-Pi und HMI

Stand 2026-11-04, Entwurf zur Abstimmung mit Tim. Nach der Abstimmung wird das Log in beiden Images umgesetzt (`duet-pi5.yaml`, `hmi-pi5.yaml`).

Dieses Dokument lag bis 2026-11-05 in [Meltingplot/rpi-image-gen](https://github.com/Meltingplot/rpi-image-gen). Pfade, Layer und Hooks darin, etwa `docs/meltingplot-layout.md` oder `mp-base.yaml`, liegen weiterhin dort.

## Anlass

Am 2026-11-04 hat am Labor-HMI die USB-Freigaberegel (`mp-hmi-usb-guard`, noch Side-Load der DSF-Session) eine Cherry-Tastatur abgewiesen. Der Eingriff steht nur im Journal. Dort rotiert er mit allen anderen Meldungen heraus, sobald die 512 MB voll sind (`SystemMaxUse=512M`, `preimage10-slots`). Tim, 2026-11-04: Solche Eingriffe sollen dauerhaft in einem persistenten Log stehen, als eine Art Audit-Log, auf dem HMI und auf dem Duet-Pi.

## Festlegungen (Tim, 2026-11-04)

1. Jedes System führt ein eigenes Audit-Log: das HMI und der Duet-Pi (SBC). Beide lassen sich zum Maschinen-Log zusammenführen (AL-25 bis AL-32).
2. Das Log liegt auf einer eigenen Partition im neuen Layout. Sie ist nur im Namespace des Log-Dienstes eingehängt; eine Datei auf der Persistenzpartition ist ausgeschlossen (AL-04, AL-33 bis AL-38).
3. Der Schutz gegen Fluten und gestellte Uhren muss durch die Konstruktion gelten, nicht durch Mustererkennung. Sonst lohnt der Aufwand nicht (AL-39 bis AL-49).
4. Verschleiß des Datenträgers wird über eine begrenzte Schreiblast berücksichtigt, nicht über eine größere Partition (AL-50 bis AL-54).
5. Statt WORM, das die Hardware nicht hergibt, wird vorwärtssicher signiert, in Schichten nach Betriebszeit. Jede Schicht hat ihr eigenes Schlüsselpaar, der private Schlüssel wird nach Gebrauch vernichtet. Prüfbar ist das ohne Geheimnis, nur mit dem öffentlichen, außerhalb verankerten Starthash (AL-55 bis AL-61).
6. journald mit Forward-Secure Sealing ist nicht das Audit-Log, weil seine Siegel an der Systemuhr hängen und es alte Einträge verdrängt. journald liefert die Filter für fremde Ereignisse und versiegelt zusätzlich das normale Journal (AL-62, AL-63).
7. Bestandsgeräte werden mit der Installerkarte auf das neue Layout überführt, so wie beim Wechsel auf die 4G-Slots (offene Frage 10). Sie können noch das Layout gen1 oder gen2 haben (AL-33). Ein Audit-Log haben sie noch nicht, zu übernehmen ist also nichts. Die Karte muss nur das Layout überführen (AL-18, AL-36).
8. Der Starthash jedes Systems entsteht bei der Inbetriebnahme auf dem Gerät und wird dort ausgelesen. Festgehalten wird er in der Betriebsanleitung, im ERP und auf dem Typenschild des Geräts (offene Frage 12, AL-58).
9. Beim Tausch eines Pis übernimmt das neue Gerät das Log aus der Kopie beim anderen System und schreibt es weiter. Der Starthash und damit das Typenschild bleiben gültig (AL-19, AL-64).
10. Kein Opt-out. Alle Ereignisse gelten als Nachweis nach der Maschinenverordnung und lassen sich nicht abschalten (Frage 1, AL-09).
11. Fünf Jahre Aufbewahrung für alle Ereignisse (Frage 2, AL-05).
12. Betreiber ohne Shell sehen das Log auf einer Seite am Panel und exportieren es dort auf einen USB-Stick. Der Duet-Pi nimmt nur einen USB-Stick an, und nur zum Export: Er exportiert automatisch beim Einstecken (Fragen 3 und 8, AL-21, AL-68).
13. Sicherheitsrelevante G-Codes aus der DWC-Konsole werden später als eigenes Paket erfasst (Frage 4).
14. Beide Pis bekommen künftig eine RTC-Batterie. Bei Geräten ohne Batterie reicht die Markierung „Uhr nicht synchron“ (Frage 5, AL-27).
15. Rechtsgrundlage nach DSGVO ist die rechtliche Pflicht (Art. 6 Abs. 1 lit. c). Die Betriebsanleitung legt offen, was das Log festhält (Frage 6, AL-24).
16. Gegenseitige Verankerung und Kopie des Partner-Logs sind beide Pflicht (Frage 7, AL-28, AL-29).
17. Die USB-Kamera ist nicht sicherheitsrelevant. Das HMI hält fest, wenn sich Gerät oder Softwareversion der Kamera ändern (Frage 9, E23).
18. Ist das Log gestört, bleiben SSH- und Connect-Anmeldungen möglich (Frage 11, AL-48).
19. Gerätebindung über den OTP-Schlüssel kommt mit der Secure-Boot-Provisionierung, nicht vorher. Die Prüfung an den Laborgeräten hat ergeben: Der Schlüssel ist dort nicht erzeugt, und ohne Secure Boot könnte root die Lesesperre umgehen (Frage 13, AL-60). Bis dahin trägt der Starthash auf Typenschild, in der Betriebsanleitung und im ERP die Verankerung allein.
20. Ohne Audit-Partition gibt es keine Ausnahme. Ein Gerät mit gen1 oder gen2 gilt wie eines, dessen Log nicht schreibbar ist, und verweigert ab Phase 2b Updates und die übrigen Eingriffe nach AL-48. Alle Bestandsgeräte werden vorher mit der Installerkarte auf gen4 überführt (vorher gen3, `docs/meltingplot-layout.md`). Sonst ließe sich das Log abschalten, indem man die Partition aus der Partitionstabelle entfernt: Das Gerät sähe dann aus wie gen2 (Tim, 2026-11-04; AL-36, AL-48).
21. Einträge der Klasse Änderung werden sofort dauerhaft geschrieben, ohne eigenes Siegel; versiegelt werden sie mit ihrer Epoche (Tim, 2026-11-05). Anlass war der Bench-Test von HMI rc.12: Nach einem harten Reset fehlte ein Eintrag spurlos, und seine Nummer wurde neu vergeben, weil auch journald nur alle fünf Minuten schreibt. Versuch und Betrieb bleiben bei höchstens fünf Sekunden (AL-51).
22. `mp-audit` liegt in `/usr/bin` (Tim, 2026-11-05). Lesen und prüfen dürfen auch die Gruppe adm und damit das Connect-Konto (AL-20); schreiben lässt der Dienst nur root.
23. `mp-audit record` ohne root bricht mit „only root records“ und Exit 2 ab und gibt nichts ins Journal (Tim, 2026-11-05). Ins Journal stellt nur root, und nur wenn der Dienst nicht läuft (AL-35).
24. Dienst, Werkzeug, ihre Tests und der Phasenplan liegen im eigenen Repository [Meltingplot/mp-audit](https://github.com/Meltingplot/mp-audit), das Meltingplot/rpi-image-gen als Submodul `meltingplot/mp-audit` pinnt (Tim, 2026-11-05). Der Layer `mp-audit` und seine Build-Prüfung bleiben im Image-Repository.
25. Auch die Anforderungen liegen in Meltingplot/mp-audit. Eine Änderung an ihnen geht mit Code und Tests in einem PR. Unter dem alten Pfad in Meltingplot/rpi-image-gen bleibt ein kurzer Verweis (Tim, 2026-11-05).
26. Das eigene Log bleibt bei 256 MiB, die Kopie des Partners ebenso. Die Partition ist größer, damit das Dateisystem Platz hat; die Anteile nach AL-40 ändern sich dadurch nicht (Tim, 2026-11-06).

## Grundlagen

- **Maschinenverordnung (EU) 2023/1230, Anhang III 1.1.9 „Schutz gegen Korrumpierung“**, gilt ab 2027-01-20. Die Maschine muss Nachweise über rechtmäßige und unrechtmäßige Eingriffe sammeln: in Hardware, über die man an sicherheitsrelevante Software kommt, und in Software oder Konfiguration. Sie muss außerdem die installierte sicherheitsrelevante Software jederzeit leicht zugänglich angeben können. Den Wortlaut der Verordnung im Amtsblatt (EUR-Lex) prüfen, bevor er in die technische Dokumentation übernommen wird.
- **DGUV-Prüfgrundsatz GS-IFA-M25, Stand 07-2026** („Grundsätze für die Prüfung und Zertifizierung des Schutzes vor Korrumpierung“), Abschnitt „Protokollierung“ mit den Kriterien T31 bis T47. Die Betriebsanleitung behandeln T20 bis T22. Er nennt als zu protokollierende Eingriffe:
  - sicherheitsrelevante Parametrierung und Konfiguration (Identifikation über CRC o. ä.),
  - Update oder Änderung von SRESW und SRASW (Identifikation über CRC, Versionsnummer o. ä.),
  - Parametrierung von HMIs, falls daraus Gefährdungen entstehen können,
  - Update oder Änderung von Software zur Darstellung sicherheitsrelevanter Anweisungen.
- **prEN 50742** (Schutz gegen Korrumpierung). Die Norm ist noch Entwurf, GS-IFA-M25 verwendet ihre Begriffe.
- **Cyber Resilience Act (EU) 2024/2847, Anhang I Teil I Nr. 2 l:** Aufzeichnung und Überwachung relevanter interner Aktivitäten. Laut Sekundärquellen sieht der Text dafür eine Opt-out-Möglichkeit für den Nutzer vor; das ist am Amtsblatt zu prüfen (siehe offene Frage 1).

Die Kriterien von GS-IFA-M25 sind bei den Anforderungen in Klammern genannt. So lässt sich jede Anforderung einem Prüfpunkt zuordnen.

## Begriffe

- **Eingriff:** jede Änderung an Software oder Konfiguration der Maschine, und jeder Zugang über eine Schnittstelle, über den man an solche Software kommt. Erfasst wird auch der versuchte und der abgewiesene Eingriff.
- **System:** ein Rechner der Maschine mit eigener, änderbarer Software. Heute loggen zwei Systeme: der Duet-Pi (SBC) und das HMI (siehe „Systeme der Maschine“).
- **Audit-Log:** das Rückverfolgungsprotokoll im Sinne von GS-IFA-M25 auf einem System. Jedes System führt sein eigenes.
- **Maschinen-Log:** alle Audit-Logs einer Maschine zusammen. Das ist der Nachweis „der Maschine“ im Sinne von Anhang III 1.1.9.
- **SRESW, SRASW:** sicherheitsrelevante eingebettete Software (RepRapFirmware auf Mainboard und Erweiterungsboards) und sicherheitsrelevante Anwendungssoftware (die Druckerkonfiguration `chx350-config` unter `0:/sys`), Begriffe nach prEN 50742.

## Geltungsbereich

- Duet-Pi-Image (`duet-pi5.yaml`) und HMI-Image (`hmi-pi5.yaml`), beide über `mp-base.yaml`.
- Die Installerkarten führen kein eigenes Log. Sie dürfen ein vorhandenes aber nicht stillschweigend löschen (AL-18).
- Die Boards selbst führen kein Log. Ihre Firmware-Updates erfasst der Duet-Pi, der sie flasht.

## Systeme der Maschine

| System | Software, die sich ändern lässt | Log |
|---|---|---|
| Duet-Pi (SBC) | Image (OTA), DSF, DWC, Plugins, Konfiguration `0:/sys`, Firmware der Boards | eigenes Audit-Log |
| HMI | Image (OTA), Kiosk, Netz-Einstellungen am Panel | eigenes Audit-Log |
| Boards (MB6HC, Erweiterungen) | RepRapFirmware | im Log des Duet-Pi (E04) |
| USB-Kamera (rpi-camera) | eigenes Linux mit eigenen Updates, nicht sicherheitsrelevant | im Log des HMI (E23, Festlegung 17) |

Beide Pis werden über Connect getrennt aktualisiert, haben getrennte Zugänge und können getrennt ausfallen oder getauscht werden. Das Log muss deshalb auf jedem System für sich vollständig sein, und die Logs müssen sich zu einem Maschinen-Log zusammenführen lassen (AL-25 bis AL-32).

## Ereignisse

„Quelle heute“ nennt, wo das Ereignis heute schon erkannt oder gemeldet wird. MUSS-Ereignisse sind Eingriffe im Sinne von Anhang III 1.1.9. SOLL-Ereignisse dienen der Einordnung und Korrelation.

### Software und Konfiguration

| ID | Ereignis | Gerät | Quelle heute | Stufe |
|---|---|---|---|---|
| E01 | Inbetriebnahme: Identität übernommen (Rolle, Druckername), Audit-Log angelegt | beide | `mp-identity` | MUSS (T40) |
| E02 | Neues Image gestartet (Version, Slot, Image-ID) und Ausgang des Probestarts: übernommen oder zurückgerollt | beide | `slot-var-init`, `mp-role-guard`, Connect-Updater | MUSS |
| E03 | Update-Auftrag erhalten, gestoppt (falsches Bundle) oder aufgeschoben (Drucker nicht im Leerlauf) | beide (Aufschub nur Duet-Pi) | `mp-bundle-guard`, `mp-ota-gate` | MUSS, Aufschub SOLL |
| E04 | Firmware eines Boards geflasht: Board, alte und neue Version, CRC32 | Duet-Pi | `mp-dsf-firmware` | MUSS (SRESW) |
| E05 | Datei unter `0:/sys` geändert: Datei, Hash vorher und nachher, Herkunft (Image-Update, Rücksetzen beim Boot, Änderung über DWC oder Makro) | Duet-Pi | `mp-dsf-seed` beim Boot; Änderungen über DWC werden heute nicht erfasst | MUSS (SRASW, Parametrierung) |
| E06 | Mainboard-Reset nach Update (`M999`) | Duet-Pi | `mp-dsf` | SOLL |
| E07 | Plugin installiert, entfernt oder von AppArmor am Start gehindert | Duet-Pi | DSF, Kernel (AppArmor) | MUSS (Software zur Darstellung) |
| E08 | Druckernetz-Profil am Panel verändert und beim Boot zurückgesetzt | HMI | `mp-hmi-net-guard` | SOLL |

Zu E05: Was das Image unter `0:/sys` mitbringt, schreibt der Boot jedes Mal über die Kopie auf dem Gerät. Eine Änderung über DWC wirkt also bis zum nächsten Neustart, in `sys/overrides/` dauerhaft. Beides ist ein Eingriff in die Konfiguration.

### Zugänge und Schnittstellen

| ID | Ereignis | Gerät | Quelle heute | Stufe |
|---|---|---|---|---|
| E10 | USB-Gerät angeschlossen und freigegeben oder abgewiesen: Port, VID:PID, Klassen der Schnittstellen, Hersteller- und Produktname | beide; am Duet-Pi ist nur ein USB-Stick zum Export zugelassen (AL-68) | `mp-hmi-usb-guard` (Layer seit PR #119), am Duet-Pi neu | MUSS |
| E11 | USB-Stick eingehängt oder abgezogen | HMI | `mp-hmi-usb-mount` | SOLL |
| E12 | SSH-Anmeldung angenommen oder abgewiesen: Konto, Schlüssel-Fingerabdruck, Quelladresse | beide | sshd | MUSS |
| E13 | Root-Rechte per sudo: Konto, Befehl | beide | sudo | MUSS |
| E14 | Fernzugriff über Raspberry Pi Connect: Shell bzw. Bildschirmfreigabe beginnt oder endet | beide, Bildschirm nur HMI | rpi-connect | MUSS |

### Betrieb des Logs und des Systems

| ID | Ereignis | Gerät | Quelle heute | Stufe |
|---|---|---|---|---|
| E15 | Unerwarteter Neustart: Watchdog, Kernel-Panic, Stromausfall (soweit unterscheidbar) | beide | Reset-Grund des Bootloaders, zu klären | SOLL |
| E16 | Systemuhr springt (mehr als 60 s) oder wird nach dem Boot erstmals synchronisiert | beide | timesyncd (Duet-Pi), chrony (HMI) | MUSS (Korrelation, T45) |
| E17 | Fehler des Audit-Logs: Schreibfehler, Prüfkette gebrochen, Speicher knapp | beide | – | MUSS (T36) |
| E18 | Audit-Log gelöscht oder bei einer Neuinstallation übernommen bzw. verloren | beide | – | MUSS (T43, T44) |
| E19 | Flut erkannt: gleichartige Ereignisse einer Quelle über der Ratengrenze, zusammengefasst (AL-41, AL-43) | beide | – | MUSS |
| E20 | Stand der festen Menge sicherheitsrelevanter Objekte: geänderte Objekte mit Hash, Zugänge je Konto und Schlüssel, Gesamthash (AL-42, AL-45) | beide | – | MUSS (T46) |
| E21 | Verschleiß des Datenträgers, monatlich: bei NVMe „Percentage Used“ und „Data Units Written“ (AL-53) | beide | – | SOLL |
| E22 | Log exportiert: Ziel (USB-Stick), Umfang, letzte laufende Nummer, Ergebnis der Prüfung (AL-21, AL-68) | beide | – | MUSS |
| E23 | USB-Kamera am HMI: anderes Gerät oder neue Softwareversion (Festlegung 17) | HMI | `mp-hmi-camera` | SOLL |

## Anforderungen

### Inhalt eines Eintrags (T45)

- **AL-01** Jeder Eintrag enthält:
  - eine laufende Nummer, die lückenlos ist und nie wiederverwendet wird,
  - den Boot-Zähler und die Boot-ID,
  - die Zeit in UTC (ISO 8601) und die Angabe, ob die Uhr da synchronisiert war,
  - das Gerät: Rolle und Hostname,
  - die Image-Version,
  - die Ereignis-ID,
  - das Ergebnis (zugelassen, abgewiesen, ausgeführt, fehlgeschlagen),
  - den Akteur, soweit bekannt (Konto, Quelladresse, Dienst),
  - das Objekt (Datei, Gerät, Version, Hash),
  - einen kurzen Text.
- **AL-02** Zeichenketten von außen werden begrenzt und maskiert gespeichert und nie ausgewertet: Namen aus USB-Deskriptoren, Dateinamen, Datenträgernamen.
- **AL-03** Ein Eintrag pro Zeile, maschinenlesbar (JSON Lines). Ein Werkzeug zeigt das Log menschenlesbar an (AL-20).

### Speicherung und Aufbewahrung (T37, T38, T39)

- **AL-04** Das Log liegt auf einer eigenen Partition, die nur der Log-Dienst nutzt (Entscheidung Tim, 2026-11-04; Layout siehe AL-33 bis AL-38).
  - Sie steht nicht in der fstab. Der Log-Dienst hängt sie nur in seinem eigenen Mount-Namespace ein, für alle anderen Prozesse ist sie nicht eingehängt.
  - Sie übersteht OTA und Rollback, weil ein Update die Partitionstabelle nicht ändert.
  - Sie übersteht das Zurücksetzen von `/var` und das Neuformatieren der Persistenzpartition.
  - Sie hängt weder von der Rotation des Journals noch vom Füllstand der Persistenzpartition ab.
  - Der Ort steht in der Betriebsanleitung (T37).
- **AL-05** Jeder Eintrag bleibt mindestens fünf Jahre erhalten (T39). Gemessen wird in Betriebszeit (AL-49), also mindestens fünf Kalenderjahre. Jüngere Einträge verschwinden nur über das Verfahren aus AL-17.
- **AL-06** Für jede Ereignis-ID bleibt der letzte Eintrag dauerhaft erhalten, auch wenn er älter als fünf Jahre ist (T38).
- **AL-07** Die Partition hat eine feste Größe: 1 GiB ab Layout gen4 (`docs/meltingplot-layout.md`, Festlegung 5), in gen3 waren es 512 MiB. Großzügig, weil sie sich nach der Installation nicht mehr ändern lässt. 256 MiB sind für das eigene Log, ebenso viel für die Kopie des Partners (AL-29). Die Partition ist größer als diese 512 MiB, weil das Dateisystem selbst Platz braucht (Festlegung 26). Das eigene Log teilt sich nach AL-40 auf die Klassen auf; das Archiv nach einer Löschung (AL-17) zählt zur Reserve. Schätzung im Normalbetrieb: unter 100 Einträge am Tag zu etwa 400 Byte, über fünf Jahre also unter 75 MB. Erst ab 80 % eines Anteils dürfen Einträge gekürzt werden, die älter als fünf Jahre Betriebszeit sind (AL-06, AL-49). Bei 80 % wird außerdem E17 gemeldet. Neue Einträge werden nie verworfen, höchstens nach AL-41 zusammengefasst. Ein volles Log hält die Maschine nicht an.
- **AL-08** Jeder Eintrag geht zusätzlich ins Journal, damit man ihn live sieht. Maßgeblich ist nur das Audit-Log.

### Aktivierung und Schutz vor Deaktivierung (T35, T36, T40, T41)

- **AL-09** Das Log schreibt automatisch, ohne Zutun eines Benutzers, ab dem ersten Boot eines Images, also spätestens ab der Inbetriebnahme (E01). Es gibt keinen Schalter, der es abstellt: weder in `identity.conf` noch in DWC noch in einer Datei auf der Persistenzpartition.
- **AL-10** Einträge nimmt der Log-Dienst nur von root an (AL-34). Das Connect-Konto `meltingplot` darf über den Dienst lesen, aber nicht schreiben oder löschen. DWC-Benutzer erreichen das Log nur über den Export (AL-21).
- **AL-11** Eine Lücke wird erkannt: Läuft ein Boot ohne sauberes Ende oder fehlen laufende Nummern, steht das beim nächsten Start als E17 im Log.
- **AL-12** Schlägt das Schreiben fehl, wird das als E17 im Journal und am nächsten möglichen Zeitpunkt im Log festgehalten. SOLL: Hinweis in DWC bzw. am Panel.

### Schutz vor Manipulation (T42, T48)

- **AL-13** Jeder Eintrag enthält den SHA-256 seines Vorgängers (Prüfkette). Eine geänderte, gelöschte oder eingeschobene Zeile fällt bei der Prüfung auf (`verify`). SHA-256 entspricht BSI TR-02102-1 (T48).
- **AL-14** Die Logdatei ist im Dateisystem nur anhängbar (`chattr +a`). Das schützt gegen versehentliches Ändern.
- **AL-15** Der letzte Hash der Prüfkette jedes Systems wird regelmäßig beim anderen System hinterlegt (AL-28) und in jeden Export geschrieben. Dann fällt auch auf, wenn root auf einem System das ganze Log neu schreibt oder kürzt.
- **AL-16** Restrisiko: root kann das Log zerstören und von dem Zeitpunkt an fälschen, zu dem er root geworden ist. Was davor signiert wurde, kann er nicht unbemerkt ändern (AL-55 bis AL-59). Das Restrisiko ist zu dokumentieren (T27 bis T30). Gemildert wird es durch die Zugangshärtung: `mpadmin` nur aus dem Druckernetz mit Nitrokey. Außerdem erfassen E12 und E13 jede Anmeldung und jedes sudo.

### Löschen (T43, T44)

- **AL-17** Gelöscht wird nur über ein Verfahren, das in der Betriebsanleitung beschrieben ist. Vorschlag: ein Befehl, nur als root, mit Pflichtangabe eines Grundes. Er archiviert das alte Log und beginnt das neue mit einem E18-Eintrag. Dieser enthält Grund, Konto, letzte laufende Nummer und letzten Hash des alten Logs (T44).
- **AL-18** Die Installerkarte (`mp-installer`) erkennt, welche Generation des Layouts sie auf einer belegten NVMe vorfindet (AL-33), und handelt danach:
  - **gen1 und gen2:** Sie überschreibt die NVMe wie bisher mit `overwrite_nvme=yes` und `identity.conf` von der Karte. Diese Geräte haben kein Audit-Log, zu übernehmen ist nichts.
  - **gen3:** Mit dem Layout gen4 bekommt `audit` 1 GiB statt 512 MiB und wird neu angelegt; ein gen3-Log wird nicht übernommen. gen3 hatte nur das Bench-HMI, mit einem Testlog (`docs/meltingplot-layout.md`).
  - **gen4:** Sie lässt den Bereich der Audit-Partition beim Schreiben aus, statt ihn zu kopieren. Der Inhalt bleibt, wo er ist. Das setzt voraus, dass die Partition auf der NVMe genau dort liegt, wo das neue Image sie hat; sonst bricht die Karte ab, ohne zu schreiben. Ein Stromausfall während des Schreibens gefährdet das Log so nicht. Die Reserve dahinter schreibt sie nie (LY-10).
  - **In jedem Fall** gibt sie dem ersten Start über die BOOTCONFIG-Partition mit, was sie vorgefunden hat: Generation, Datum, Image der Karte, übernommen oder nicht. Der erste Start schreibt das als E18 ins Log: „Neuinstallation, Log übernommen“, „Neuinstallation, altes Log nicht lesbar“ oder „Überführung von gen1/gen2, kein früheres Log“. So steht am Anfang jedes Logs, warum es dort beginnt.
- **AL-19** Pi-Tausch: Das neue Gerät übernimmt das Log aus der Kopie beim anderen System und schreibt es weiter (Festlegung 9, AL-64). Der Starthash bleibt. Nur wenn beide Pis zugleich getauscht werden oder keine gültige Kopie da ist, beginnt ein neues Log mit E01 und neuem Starthash (AL-58). Das Verfahren steht in der Betriebsanleitung.

### Lesen und Auswerten (T21, T22, T33, T46, T47)

- **AL-20** Ein Werkzeug auf beiden Geräten zeigt das Log menschenlesbar an, mit Filter nach Ereignis und Zeit, und prüft die Kette. Das Connect-Konto darf es aufrufen. Damit kann der Support über die Connect-Shell lesen.
- **AL-21** Export für Betreiber ohne Shell: eine Seite am Panel, nur an der Maschine selbst erreichbar wie `/hmi/usb/` (Festlegung 12).
  - Sie zeigt das Maschinen-Log, beide Systeme, und die Prüfergebnisse.
  - Sie exportiert es auf einen eingesteckten USB-Stick: beide Logs, die Starthashes und das Prüfergebnis.
  - Der Stick ist für die Jobliste nur lesend eingehängt (`mp-hmi-usb`). Für den Export hängt ihn der Log-Dienst in seinem eigenen Namespace kurz schreibbar ein und danach wieder aus.
  - Jeder Export ist ein Eintrag (E22).
- **AL-22** Software-Identifikation auf Anfrage, menschenlesbar (T46, T47): Image-Version, DSF-, DWC- und RRF-Versionen mit CRC der Firmware, Hashes der Konfiguration unter `0:/sys`.
- **AL-23** Die Betriebsanleitung beschreibt (T20 bis T22, T37, T43):
  - wo das Log liegt, wie man es liest und wie man es interpretiert, mit der Ereignistabelle,
  - welche Rolle was ändern darf,
  - das Verfahren zum Löschen.

### Datenschutz

- **AL-24** Erfasst wird nur, was für den Nachweis nötig ist: Kontonamen, Schlüssel-Fingerabdrücke, Quelladressen von Anmeldungen. Nicht erfasst werden Inhalte von Dateien oder Jobs, Passwörter und WLAN-Zugangsdaten. Rechtsgrundlage ist die rechtliche Pflicht nach Art. 6 Abs. 1 lit. c DSGVO; die Betriebsanleitung legt offen, was das Log festhält und wie lange (Festlegung 15).

### Zwei Systeme einer Maschine

- **AL-25** Beide Systeme loggen mit demselben Werkzeug, demselben Format und denselben Ereignis-IDs, aus einem gemeinsamen Layer. Ein Ereignis, das es nur auf einem System gibt, hat trotzdem eine eindeutige ID.
- **AL-26** Jeder Eintrag nennt neben dem System (Rolle, Hostname) die Maschine, zu der es gehört. Der Druckername kommt aus `identity.conf` bzw. vom Duet-Pi, wie heute beim Hostnamen des HMI. So lassen sich die Logs beider Systeme ohne Raten zusammenführen.
- **AL-27** Gemeinsame Zeitbasis: Der Duet-Pi bezieht seine Zeit vom HMI (chrony auf 10.42.0.1), das HMI aus dem Internet. Jeder Eintrag sagt, ob die Uhr synchron war (AL-01). Die Zeitsprünge beider Systeme (E16) stehen im Log. Damit lassen sich Ereignisse über beide Systeme in eine Reihenfolge bringen, auch nach einem Stromausfall ohne Netz. Künftige Geräte bekommen eine RTC-Batterie in beiden Pis (Festlegung 14).
- **AL-28** Gegenseitige Verankerung: Jedes System hinterlegt regelmäßig seinen letzten Hash, seine laufende Nummer und seinen Boot-Zähler beim anderen System, über das Druckernetz. Das andere System schreibt sie als Eintrag in sein eigenes Log. Wer ein Log neu schreiben will, muss also beide Systeme manipulieren.
- **AL-29** Jedes System hält eine Kopie des Logs des anderen. Dann übersteht der Nachweis den Ausfall oder Tausch eines Pis über die fünf Jahre (T39), und ein Ersatzgerät kann das Log weiterschreiben (AL-64). Die Kopie wird gegen Starthash und Verankerung geprüft (AL-28, AL-58). Sie enthält nie einen privaten Schlüssel. Einträge der Klasse Stand gehen innerhalb einer Minute zum Partner, alle übrigen gebündelt (AL-51).
- **AL-30** Fällt das andere System oder das Druckernetz aus, loggt jedes System ungestört weiter. Verankerung und Kopie werden nachgeholt, sobald die Verbindung wieder steht. Eine Verbindung, die länger als einen Tag fehlt, ist ein Eintrag (E17).
- **AL-31** Ein Export und eine Anzeige liefern das Maschinen-Log: beide Logs, nach Zeit und laufender Nummer zusammengeführt, mit dem Prüfergebnis jeder Kette. Ist ein System nicht erreichbar, sagt das der Export, statt dessen Teil wegzulassen.
- **AL-32** Tausch eines Systems (Pi-Tausch, AL-19): Das verbleibende System beglaubigt die Übergabe an das Ersatzgerät in seinem eigenen Log (AL-64). Es behält die Verankerung des alten Partners.

### Eigene Partition (Layout)

- **AL-33** Neue Partition im A/B-Layout:
  - GPT-Name `audit`, Dateisystem ext4 mit Label `AUDIT`, Größe nach AL-07.
  - Sie liegt hinter `system_b` und vor `persistent`. `persistent` bleibt die letzte Partition, weil `mp-growfs` sie bis ans Ende des Datenträgers vergrößert.
  - Die Boot-Partitionen behalten die Nummern 2 und 3, die Tryboot braucht.
  - Alles findet die Partitionen über ihren GPT-Namen, die neue über `/dev/disk/by-slot/audit`.
  - SD und NVMe bekommen dasselbe Layout.
  - Generationen des Layouts:
    - **gen1:** Systemslots 1G (Duet-Pi) bzw. 2G (HMI), ohne Audit-Partition.
    - **gen2:** Systemslots 4G (PR #111, seit Duet rc.69 und HMI rc.8), ohne Audit-Partition.
    - **gen3:** gen2 mit der Partition `audit` (512 MiB).
    - **gen4:** `audit` mit 1 GiB ohne Dateisystem und dahinter die Partition `reserve` mit 16 GiB (`docs/meltingplot-layout.md`).

    Die Installerkarte erkennt die Generation an den GPT-Namen und den Slotgrößen (AL-18); ab gen4 steht sie außerdem in `meltingplot/layout.txt` auf `bootconfig` (LY-05).
- **AL-34** Zugriff nur über den Log-Dienst:
  - Der Dienst hängt die Partition in seinem eigenen Mount-Namespace ein (`PrivateMounts=`) und ist ihr einziger Schreiber.
  - Einträge nimmt er über einen Socket nur von root an, Lesen erlaubt er der Gruppe `adm`.
  - Das Blockgerät bleibt root vorbehalten.
  - Für root ist die Partition sichtbar (`lsblk`) und einhängbar; dagegen schützen AL-13 bis AL-16 und AL-28.
- **AL-35** Was vor dem Start des Dienstes oder während eines Ausfalls geschieht, geben die Wächter mit einer Kennung ins Journal. Der Dienst übernimmt es beim Start in der richtigen Reihenfolge. So sind auch Wächter erfasst, die früh im Boot laufen, etwa `mp-role-guard`.
- **AL-36** Geräte mit gen1 oder gen2 haben keine Audit-Partition, und ein OTA kann sie nicht anlegen. Sie werden mit der Installerkarte überführt (Festlegung 7, AL-18). Bis dahin schreibt der Dienst auf ihnen nur ins Journal und meldet bei jedem Boot E17 „keine Audit-Partition, Überführung mit der Installerkarte nötig“. Ab Phase 2b verweigern sie außerdem die Eingriffe nach AL-48, Updates eingeschlossen (Festlegung 20). Von außen sieht ein gen3-Gerät, dessen Partition entfernt wurde, genauso aus. Deshalb gibt es für fehlende Partitionen keine Ausnahme.
- **AL-37** Der Dienst formatiert die Partition nur, wenn sie keinerlei Dateisystem-Signatur trägt (erster Start nach Installation). Ein beschädigtes Dateisystem wird nie neu formatiert, sondern als E17 gemeldet: Es kann der Nachweis sein.
- **AL-38** Die Änderung an `image-rota` wird allgemein gebaut: eine optionale, nicht eingehängte Partition, deren Name und Größe Variablen sind und die standardmäßig fehlt. So lässt sie sich Upstream (raspberrypi/rpi-image-gen) vorschlagen, statt dauerhaft als eigene Abweichung mitgeführt zu werden.

### Schutz gegen Fluten und gestellte Uhren

Wer das Verfahren kennt, kann auf mehreren Wegen versuchen, den Nachweis zu beseitigen. Er kennt dabei auch Partitionsgröße, Anteile und Budgets:

1. Er flutet, bis ein Ringpuffer umläuft und ältere Einträge überschreibt.
2. Er erzeugt rollierend viele verschiedene Ereignisse, verteilt auf alle Klassen, damit sich nichts zusammenfassen lässt.
3. Er flutet alle Klassen, in die er schreiben kann, bis kein Platz mehr für Wesentliches bleibt, und ändert erst dann.
4. Er dreht die Uhr vor, damit Einträge als älter als fünf Jahre gelten und gelöscht werden, oder damit sich die Budgets schneller auffüllen.
5. Er versteckt den eigentlichen Eingriff in der Masse.

Billig zu erzeugen sind zum Beispiel:
- USB-Geräte, auch ein zugelassener Stick, die sich im Sekundentakt anmelden,
- SSH-Fehlversuche mit wechselnden Konten und Adressen,
- Dateien, die über DWC in einer Schleife unter immer neuen Namen geschrieben werden.

Der Schutz beruht nicht darauf, Muster zu erkennen. Er beruht auf vier Grenzen, die durch die Konstruktion gelten:
- **Fester Speicher für Wesentliches:** Nur eine echte Änderung an einer festen Menge von Objekten kann hineinschreiben.
- **Feste Anteile mit Budgets:** Jede Klasse kann höchstens ihren Anteil verbrauchen.
- **Zusammenfassen nur nach Werten des Systems,** nie nach Werten, die der Angreifer wählt.
- **Betriebszeit statt Uhrzeit,** für alles, was löscht oder Budget gewährt.

- **AL-39** Jede Ereignis-ID gehört zu einer Klasse:
  - **Stand:** das Wesentliche. Zustand und Zugänge der festen Menge (AL-45), geschrieben nach AL-42. Kein anderes Ereignis schreibt in diese Klasse.
  - **Änderung:** die Einzelheiten ausgeführter Eingriffe und gewährter Zugänge. E01, E02, E04, E05, E06, E07 (installiert, entfernt), E10 (freigegeben), E12 (angenommen), E13, E14, E18, E23.
  - **Versuch:** etwas, das abgewiesen wurde. E03 (gestoppt), E07 (blockiert), E10 (abgewiesen), E12 (abgewiesen).
  - **Betrieb:** alles Übrige. E03 (aufgeschoben), E08, E11, E15, E16, E17, E19, E21, E22.
- **AL-40** Jede Klasse hat einen festen Anteil des eigenen Logs. Die Anteile sind nicht gleich verteilt: Der Anteil von Stand ergibt sich aus der Größe der festen Menge (AL-42). Vorschlag bei 256 MiB für das eigene Log: Stand 32 MiB, Änderung 96 MiB, Versuch 52 MiB, Betrieb 24 MiB, Reserve 52 MiB.
  - Jeder Schreibvorgang wird dem Budget seiner Klasse angerechnet. Das Budget füllt sich mit der Betriebszeit auf (AL-49), um den Anteil geteilt durch fünf Jahre, dazu ein Vorrat für kurze Spitzen.
  - Keine Klasse kann damit mehr als ihren Anteil verbrauchen, gleich wie viele und welche Ereignisse kommen. Den Anteil einer anderen Klasse erreicht sie nie.
  - Die Klasse Änderung hat im Mittel etwa 54 KB am Tag, rund 135 einzelne Einträge am Tag über fünf Jahre. Das ist ein Vielfaches des Normalbetriebs.
- **AL-41** Über dem Budget sinkt nur die Detailtiefe, nie die Aufbewahrung.
  - Zusammengefasst wird nur nach Werten, die das System festlegt: Klasse und Ereignis-ID. Die Liste der Ereignis-IDs ist fest und kurz (E01 bis E23); ein Angreifer kann sie nicht verlängern.
  - Was der Angreifer wählt (Quelle, Objekt, Text), geht nie in die Gruppierung ein. Wer rollierend verschiedene Ereignisse erzeugt, landet trotzdem im selben Sammeleintrag.
  - Ein Sammeleintrag hat feste Größe: Anzahl, Zeitraum, laufende Nummern, die zehn häufigsten Quellen und Objekte, die Zahl der übrigen, eine Prüfsumme über alle.
  - Bleibt das Budget leer, wächst sein Zeitfenster: Minute, Stunde, Tag. Bis dahin zählt der Dienst in einem Zählerstand fester Größe. Er übersteht einen Neustart und wird höchstens einmal pro Minute geschrieben (AL-51).
  - Der erste und der letzte Eintrag je Ereignis-ID bleiben einzeln erhalten. Das ist mehr, als T38 verlangt.
  - Jedes zusammengefasste Ereignis zählt in der laufenden Nummer und der Prüfkette mit.
- **AL-42** Das Wesentliche hat einen eigenen Speicher, den keine Flut erreicht: die Klasse Stand.
  - In ein Zeitfenster schreibt sie für jedes Objekt der festen Menge, das sich geändert hat: den neuen Hash (SHA-256), die Zahl der Änderungen, die erste und die letzte Zeit.
  - Für jedes feste Konto und jeden zugelassenen Schlüssel schreibt sie: die Zahl der angenommenen Anmeldungen und der sudo-Aufrufe, die erste und die letzte Quelle.
  - Im Normalbetrieb ist das Zeitfenster eine einzelne Änderung. Unter Dauerlast wächst es höchstens bis auf einen Tag.
  - Ein Boot ohne Änderung ist kein Eintrag, sondern ein Zähler.
  - Hineinschreiben kann ein Angreifer nur, indem er wirklich ein Objekt der Menge ändert oder sich wirklich über ein festes Konto anmeldet. Jedes Byte in dieser Klasse ist also Nachweis, nichts davon Rauschen.
  - Der Anteil ist so bemessen, dass er fünf Jahre lang reicht, auch wenn sich jedes Objekt der Menge jeden Tag ändert. Rechnung: etwa 160 Objekte, ausgelegt auf 256 Objekte zu je 48 Byte. 256 × 48 Byte × 1826 Tage ≈ 22 MB, dazu die Zugänge mit unter 3 MB. Das passt in 32 MiB.
  - Wer alle anderen Klassen flutet, ändert an dieser Klasse nichts.
- **AL-43** Eine Flut ist selbst ein Ereignis (E19): Klasse, Ereignis-ID, Rate, Beginn, häufigste Quellen. Höchstens einmal je Ereignis-ID und Zeitfenster. SOLL: Hinweis am Panel bzw. in DWC.
- **AL-44** Die Anzeige zeigt standardmäßig die Klassen Stand und Änderung sowie die Sammeleinträge; Versuch und Betrieb auf Wunsch. Ein Bericht „Änderungen seit …“ beruht auf der Klasse Stand.
- **AL-45** Die feste Menge sicherheitsrelevanter Objekte legt das Image fest. Ein Angreifer kann sie nicht vergrößern. Sie umfasst:
  - Image-Version,
  - Firmware-Versionen und CRCs der Boards,
  - die Dateien, die das Image unter `0:/sys` und `0:/macros` mitbringt,
  - die bekannten Dateien unter `sys/overrides/` (`global-override.g`, `machine-override`, `dsf-config-override.g`, `spool-catalog.csv`, `printer-name.g`),
  - die installierten Plugins,
  - die Konten (`meltingplot`, `mpadmin`, root) und die zugelassenen SSH-Schlüssel,
  - die Freigabeliste des USB-Wächters.

  Alle übrigen Dateien, auch neue unter `sys/overrides/`, gehen nur als Anzahl und Gesamthash ein. Bei jedem Boot und täglich schreibt die Klasse Stand einen Gesamthash über die ganze Menge. Zwei Stände zeigen jede Änderung an einem sicherheitsrelevanten Objekt, gleich wie viele und wie verschiedene Ereignisse dazwischen lagen.
- **AL-46** Kein Ringpuffer. Kein Eintrag, der jünger als fünf Jahre Betriebszeit ist (AL-49), wird überschrieben oder gekürzt, auch nicht unter einer Flut.
- **AL-47** SOLL: Schutz schon an der Quelle.
  - Der USB-Wächter legt einen Port still, an dem sich ein Gerät immer wieder anmeldet, bis es abgezogen wird.
  - sshd begrenzt Anmeldeversuche je Quelle (`PerSourcePenalties`, `MaxStartups`).
- **AL-48** Kein Eingriff ohne Nachweis. Kann die Klasse Stand eine Änderung nicht mehr festhalten, verweigert das System die Eingriffe, die es selbst steuert:
  - Anlass: Partition fehlt (gen1, gen2 oder entfernt, Festlegung 20), ist nicht schreibbar, oder der Dienst ist gestört. Nach AL-42 ist ein voller Anteil nicht möglich.
  - Verweigert werden: Updates (Bundle-Wächter), Firmware-Flash, USB-Freigaben, Schreiben unter `0:/sys` über DWC.
  - Anmeldungen bleiben möglich, damit der Support das Gerät erreicht. Sie stehen als E17 im Journal (Festlegung 18).
- **AL-49** Betriebszeit statt Uhrzeit. Was löscht oder Budget gewährt, richtet sich nie nach der Systemuhr. Maßgeblich ist die aufsummierte Betriebszeit:
  - Sie zählt die Laufzeit jedes Boots (`CLOCK_BOOTTIME`, lässt sich nicht stellen) und wird laufend in die Partition fortgeschrieben.
  - Nach einem Absturz fehlt höchstens das letzte Intervall. Das ist die sichere Richtung: weniger Zeit heißt später löschen und weniger Budget.
  - Die Betriebszeit ist nie größer als die Kalenderzeit. Eintrag „älter als fünf Jahre“ heißt also mindestens fünf Kalenderjahre.
  - Die Systemuhr dient nur der Anzeige und der Zuordnung zwischen den Systemen. Jeder Sprung steht als E16 im Log.
  - Die Reihenfolge ergibt sich aus laufender Nummer und Boot-Zähler, nicht aus der Uhr.

**Was ein Angreifer erreicht, der alles kennt:**

- **Umlauf erzwingen: nein.** Es gibt keinen Ringpuffer (AL-46).
- **Rollierend verschiedene Ereignisse: nein.** Es zählt nur Klasse und Ereignis-ID (AL-41).
- **Alle Klassen fluten, dann ändern: nein.** Wesentliches steht in der Klasse Stand. Dort kann er nur hineinschreiben, indem er wirklich ändert, und der Platz reicht auch dann fünf Jahre (AL-42). Die übrigen Klassen werden durch die Flut gröber, nicht voll.
- **Uhr vordrehen: nein.** Löschen und Budget hängen an der Betriebszeit (AL-49). Der Sprung selbst steht als E16 im Log.
- **Alte Einträge verdrängen oder unbrauchbar machen: nein.** Geschriebenes wird weder gelöscht noch nachträglich zusammengefasst.
- **Was die Flut kostet:**
  - Während der Flut werden Versuche, Betriebsereignisse und Einzelheiten von Änderungen (genaue Zeit, Quelle, Befehl) nur noch gezählt.
  - Welches sicherheitsrelevante Objekt sich geändert hat und welchen Stand es danach hatte, bleibt erhalten, im schlechtesten Fall auf den Tag genau.
  - Die Flut steht als E19 im Log und ist selbst ein Nachweis für den Angriff.
- **Restrisiko:** root kann das Log zerstören, und fälschen kann er nur, was nach seinem Zugriff kommt (AL-16). Das Zerstören fällt über die Verankerung auf (AL-28, AL-58).

### Verschleiß des Datenträgers

Eine SSD verschleißt nicht an bestimmten Zellen einer Partition. Ihr Controller verteilt jeden Schreibvorgang über die ganze Platte (Wear Leveling), unabhängig von Partitionsgrenzen und davon, ob dieselbe Adresse immer wieder beschrieben wird. Begrenzt ist die gesamte Schreibmenge über die Lebensdauer (TBW). Eine größere Partition verringert den Verschleiß deshalb nicht. Es kommt darauf an, wie viel das Log insgesamt schreibt.

Bezug Labor-HMI (2026-11-04):
- Samsung MZ9LQ256HBJD (PM991a, 256 GB).
- `fstrim.timer` aktiv.
- Das ganze System schreibt etwa 800 MB am Tag (475 MB in 14,3 h Laufzeit).

Die TBW dieses Modells ist dem Datenblatt zu entnehmen; Geräte dieser Klasse liegen typischerweise bei über 100 TB.

Die Gefahr ist die Flut: Schriebe jedes Ereignis einzeln mit `fsync`, kostet das wegen Blockgröße und ext4-Journal etwa 16 KiB pro Ereignis. Bei 1000 Ereignissen pro Sekunde wären das etwa 1,4 TB am Tag, und die SSD wäre in Monaten verbraucht. Eine Flut ist also auch ein Angriff auf den Datenträger.

- **AL-50** Die Schreiblast des Logs ist durch die Konstruktion begrenzt, unabhängig davon, wie viele Ereignisse ankommen. Auf den Datenträger geht nur, was das Budget erlaubt (AL-40, AL-41). Alles andere wird im Speicher gezählt.
- **AL-51** Schreiben in festen Abständen:
  - Einträge der Klasse Stand werden sofort und einzeln dauerhaft geschrieben; sie sind selten und durch die feste Menge begrenzt.
  - Einträge der Klasse Änderung werden sofort geschrieben, ohne eigenes Siegel; versiegelt werden sie mit ihrer Epoche (Festlegung 21). Ihre Menge begrenzt das Budget der Klasse; AL-52 rechnet ohnehin mit einem Schreibvorgang je Eintrag.
  - Einträge der Klassen Versuch und Betrieb werden gesammelt und höchstens alle fünf Sekunden geschrieben. Stürzt nur der Dienst ab, zeigt die laufende Nummer die Lücke, und er holt die Einträge aus dem Journal zurück (AL-11). Bei einem Stromausfall können Versuche und Betrieb der letzten fünf Sekunden ohne Spur fehlen, weil auch das Journal sie dann noch nicht geschrieben hat; E15 zeigt nur den unsauberen Neustart.
  - Zählerstände der Zusammenfassung: höchstens einmal pro Minute.
  - Betriebszeit (AL-49): höchstens alle zehn Minuten.
  - Kopie des Partners (AL-29): Einträge der Klasse Stand innerhalb einer Minute, alle übrigen höchstens stündlich, gebündelt.
- **AL-52** Obergrenze, nachzuweisen über fünf Jahre im schlechtesten Fall, Dauerflut mit vollem Budget in allen Klassen:
  - etwa 1,3 Mio. Einträge mit je 16 KiB auf dem Gerät, also etwa 21 GB,
  - Zählerstände 42 GB, Betriebszeit 4 GB, Kopie des Partners 3 GB,
  - zusammen unter 75 GB.

  Das sind etwa 40 MB am Tag, rund 5 % dessen, was das HMI heute ohnehin schreibt, und weit unter 0,1 % einer TBW von 100 TB. Die Partition muss dafür nicht größer werden; sie ist es ab gen4 wegen des Dateisystems (AL-07).
- **AL-53** SOLL: Das System schreibt monatlich den Verschleiß des Datenträgers ins Log (E21): bei NVMe „Percentage Used“ und „Data Units Written“ aus den SMART-Daten. Das ist auch ein Nachweis, falls jemand den Datenträger zu verschleißen versucht. Die Audit-Partition ist nur im Namespace des Dienstes eingehängt. Der Dienst stößt TRIM für sie deshalb selbst an, weil `fstrim.timer` sie nicht sieht.
- **AL-54** Läuft ein System von einer SD-Karte statt von NVMe, gilt dieselbe Grenze. Billige Karten verteilen Schreibvorgänge oft schlechter; für den Dauerbetrieb von SD sind Industriekarten (pSLC) vorzusehen. Die Betriebsanleitung nennt das.

### Versiegelung mit Vorwärtssicherheit (statt WORM)

Echtes WORM, also ein Speicher, den man physisch nicht mehr überschreiben kann, gibt die verbaute NVMe nicht her. Nötig wäre ein Schreibschutz in der Hardware, etwa der permanente Schreibschutz von eMMC; NVMe-Namespace-Schreibschutz beherrscht die verbaute Samsung PM991a nach meinem Wissen nicht (am Datenblatt zu prüfen). Ein Schutz im Dateisystem (`chattr +a`) und eine reine Hash-Kette (AL-13) halten root nicht auf: Er ändert einen Eintrag und rechnet die Kette in Sekunden neu.

Das Neurechnen absichtlich teuer zu machen, etwa mit langsamen Hashes, hilft nicht. Der Angreifer rechnet auf einem PC und hat Zeit, das Gerät hat beides nicht. Wirksam ist eine Kette von Signaturen, deren private Schlüssel nach Gebrauch vernichtet werden.

Prüfen lässt sie sich ohne jedes Geheimnis, nur mit dem öffentlichen Startwert. Der muss echt sein, nicht geheim (Tim, 2026-11-04). Anders als bei einer Versiegelung mit HMAC, wie journald sie macht, braucht der Prüfer keinen Schlüssel, mit dem er selbst Siegel erzeugen könnte.

- **AL-55** Das Log wird schichtweise signiert, in Epochen, die an der Betriebszeit hängen (AL-49). Vorschlag: 15 Minuten Betriebszeit je Epoche.
  - Am Ende einer Epoche signiert das System:
    - den Hash ihrer Einträge,
    - den Hash der vorigen Epoche,
    - die Epochennummer, die Betriebszeit und den Boot-Zähler,
    - den öffentlichen Schlüssel der nächsten Epoche.
  - Jede Schicht bestätigt also die vorige und kündigt den Schlüssel der nächsten an.
- **AL-56** Jede Epoche hat ihr eigenes Schlüsselpaar.
  - Vor dem Abschluss einer Epoche erzeugt das System das Paar der nächsten.
  - Mit dem privaten Schlüssel der laufenden Epoche signiert es den Abschluss und überschreibt diesen Schlüssel dann, im Speicher wie auf der Partition. Eine signierte Epoche lässt sich danach von niemandem mehr neu signieren, auch nicht vom Gerät selbst.
  - Einträge der Klasse Stand schließen ihre Epoche sofort ab.
  - Anmeldungen werden beim Aufbau der Sitzung über PAM synchron erfasst und signiert, bevor die Shell startet. Wer sich root verschafft, findet seine eigene Anmeldung schon unveränderlich vor.
- **AL-57** Der Anfang (Genesis) entsteht bei der Inbetriebnahme.
  - Das System erzeugt das erste Schlüsselpaar.
  - Der erste Eintrag enthält dessen öffentlichen Schlüssel, die Identität des Geräts (Rolle, Druckername, Seriennummer), die Angaben der Installerkarte (AL-18) und die Betriebszeit.
  - Sein Hash ist der Starthash.
  - Kein geheimer Schlüssel verlässt das Gerät, und nichts muss hinterlegt werden.
  - Die Verfahren richten sich nach BSI TR-02102-1 (T48), z. B. ECDSA auf P-256 oder brainpoolP256r1 mit SHA-256.
- **AL-58** Der Starthash wird außerhalb verankert. Er muss echt sein, nicht geheim (Festlegung 8).
  - Bei der Inbetriebnahme entsteht er auf dem Gerät und wird dort ausgelesen:
    - Das Panel zeigt die Starthashes beider Systeme an, als Text und als QR-Code. Den des Duet-Pi kennt es über den Partner-Abgleich (AL-28).
    - Auf beiden Systemen gibt ihn `mp-audit genesis` aus.
  - Er wird an vier Stellen festgehalten:
    - in der Betriebsanleitung der Maschine,
    - im ERP von Meltingplot,
    - auf dem Typenschild,
    - beim Partner-System.
  - Auf dem Typenschild stehen je System (HMI, Duet-Pi):
    - der volle SHA-256 als QR-Code,
    - ein Fingerabdruck aus den ersten 128 Bit als Text, 32 Hex-Zeichen in Vierergruppen.

    128 Bit reichen für den Abgleich von Hand: Ein Log mit passendem Fingerabdruck zu erzeugen kostet etwa 2^128 Versuche.
  - Mit Gerätebindung (AL-60) ist er zusätzlich vom Gerät signiert.
  - Ein komplett neu angelegtes Log hat einen anderen Starthash und fällt beim Abgleich mit Typenschild, Betriebsanleitung oder ERP auf.
  - Eine Neuinstallation, die das Log übernimmt (AL-18), behält den Starthash. Das Typenschild bleibt also gültig.
  - Ein Pi-Tausch mit Übergabe (AL-64) behält den Starthash ebenfalls.
  - Beginnt ein Log neu, geht der neue Starthash denselben Weg: ins ERP, als Nachtrag in die Betriebsanleitung und als zusätzliches Schild neben das Typenschild. Gründe für einen Neubeginn:
    - beide Pis zugleich getauscht, oder keine gültige Kopie beim Partner (AL-19),
    - ein altes Log, das nicht lesbar war (AL-18),
    - eine Löschung nach AL-17,
    - die Überführung eines Bestandsgeräts.

    Der alte Starthash bleibt für das alte Log gültig.
- **AL-59** Was daraus folgt:
  - Prüfen kann jeder, der den Starthash hat: Meltingplot, der Betreiber, eine Prüfstelle, auch das Gerät selbst. Es braucht dazu kein Geheimnis.
  - Wer zum Zeitpunkt T root wird, kann nichts unbemerkt ändern, was vor T signiert wurde, auch seine eigene Anmeldung nicht. Die privaten Schlüssel dafür gibt es nicht mehr.
  - Er kann ab T fälschen.
  - Er kann das Log löschen oder ein neues anlegen. Beides fällt über den verankerten Starthash auf (AL-58).
- **AL-60** SOLL: Bindung an das Gerät.
  - Der Pi 5 signiert den Starthash zusätzlich mit seinem gerätegebundenen Schlüssel im OTP, über die Firmware (`rpi-fw-crypto`, ECDSA P-256, Steckplatz 1). Linux kann damit signieren lassen, den Schlüssel aber nicht lesen.
  - Ein Prüfer prüft diese Signatur mit dem öffentlichen Schlüssel des Geräts.
  - Ein neu angelegtes Log müsste dann auf genau diesem Gerät entstehen.
  - Befund an den Laborgeräten (2026-11-04, nur lesend geprüft, HMI rc.7 und Duet-Pi rc.73, beide gleich):
    - `rpi-fw-crypto get-num-otp-keys` meldet einen Steckplatz.
    - `get-key-status 1` meldet `0x101` (`DEVICE READ_LOCKED`).
    - `pubkey` und `sign --key-id 1` schlagen mit „Key not set (all zeros)“ fehl. Der Schlüssel ist also nicht erzeugt.
    - Das rohe Auslesen über die Mailbox ist gesperrt. Die Sperre kommt aus `lock_device_private_key=1` im Upstream-Template `templates/rpi/boot-firmware/config.txt` und steht in der `config.txt` in `boot.img`.
    - `rpi-eeprom-config` zeigt kein `SIGNED_BOOT`. Ohne Secure Boot kann root `boot.img` tauschen, die Sperre entfernen und nach einem Neustart den Rohschlüssel lesen.
  - Voraussetzungen, damit die Bindung trägt:
    - der Schlüssel wird in der Firmware erzeugt (`rpi-fw-crypto genkey --key-id 1 --alg ec`; ein OTP-Schreibvorgang, unwiderruflich),
    - Secure Boot ist aktiv, damit die Sperre in `boot.img` bleibt.
  - Entscheidung (Tim, 2026-11-04, Festlegung 19): Die Bindung kommt mit der Secure-Boot-Provisionierung (rpi-sb-provisioner). Dort ist der Geräteschlüssel ohnehin für die Verschlüsselung von `/persistent` vorgesehen. Vorher wird kein Schlüssel einzeln erzeugt. Bis dahin hängt die Verankerung allein am Starthash (AL-58).
- **AL-61** Das Prüfwerkzeug ist öffentlich und braucht nur Log und Starthash.
  - Es rechnet die Kette der Schlüssel und Signaturen nach und meldet je Epoche: gültig, verändert oder fehlend.
  - Es läuft auf dem Gerät (`mp-audit verify`) wie außerhalb.
  - Platz: etwa 150 Byte je Epoche für Signatur und nächsten öffentlichen Schlüssel. Bei einer Epoche je 15 Minuten Betriebszeit sind das rund 5 MB im Jahr, 25 MB in fünf Jahren. Das liegt im Anteil Reserve (AL-40). Epochen, die eine Änderung sofort abschließt, zählen zum Budget ihrer Klasse.

### Warum nicht journald mit Forward-Secure Sealing allein

Geprüft am Quelltext von systemd v257, der Version in trixie (Tim, 2026-11-04: `journalctl --setup-keys` mit eigenen Filtern statt eines eigenen Logs?):

- **Die Versiegelung hängt an der Systemuhr.**
  - `journal_file_get_epoch` (`src/libsystemd/sd-journal/journal-authenticate.c`) berechnet die Epoche aus `CLOCK_REALTIME`.
  - Der Schlüssel wird beim Fortschreiben in der Schlüsseldatei überschrieben. Das ist gewollt, sonst wäre er nicht vorwärtssicher.
  - Wird die Uhr einmal vorgedreht, steht der Schlüssel danach unwiderruflich in der Zukunft. Mit wieder richtiger Zeit liefert `journal_file_fsprg_need_evolve` `-ESTALE`, und `journal_file_maybe_append_tag` hängt dann ohne Fehlermeldung kein Siegel mehr an, bis die echte Zeit aufgeholt hat. Uhr zehn Jahre vor heißt zehn Jahre ohne Siegel.
  - Das widerspricht AL-49.
- **Die Aufbewahrung ist ein Ringpuffer.** journald löscht die ältesten Dateien, sobald `SystemMaxUse` oder `SystemKeepFree` erreicht ist. Eine Flut verdrängt also alte Einträge (gegen AL-46). Ohne dieses Löschen gehen bei voller Platte neue Einträge verloren. Klassen, Budgets, Stand und „letzter Eintrag je Art“ (T38) gibt es nicht. `RateLimitBurst` verwirft Meldungen je Dienst, statt sie zu zählen.
- **Ein Schlüssel für die ganze Maschine.** Er liegt fest unter `/var/log/journal/<machine-id>/fss` (`journal_file_fss_load`, `--setup-keys`) und gilt für alle Namespaces, also auf der Persistenzpartition, nicht auf der Audit-Partition. Gelöscht wird über `journalctl --vacuum-*` oder `rm`, ohne eigenen Eintrag (gegen T43, T44).

Was journald gut kann und wir nutzen:

- **AL-62** Die Filter für fremde Ereignisse sind journald-Matches auf das normale Journal. Der Collector (`mp-audit-collect`) liest nur diese, zum Beispiel:
  - `_SYSTEMD_UNIT=ssh.service`, `SYSLOG_IDENTIFIER=sudo`,
  - die AppArmor-Meldungen des Kernels,
  - die Meldungen von rpi-connect.

  Was er übernimmt, geht durch Budget und Klassen (AL-39 bis AL-48).
- **AL-63** SOLL: Zusätzlich wird das normale Journal versiegelt, als zweite, unabhängige Schicht über alles, auch über die Quellen des Collectors. Das kostet wenig:
  - `Seal=yes` ist Standard; es fehlt nur `journalctl --setup-keys` bei der Inbetriebnahme.
  - Anders als beim Audit-Log ist der „verification key“ von journald ein Geheimnis: Er ist der Seed, aus dem sich alle Siegel erzeugen lassen (`--setup-keys`, `format_key(seed, …)`). Er darf das Gerät nur verschlüsselt an Meltingplot verlassen und muss dort geheim bleiben.
  - Die Abhängigkeit von der Uhr bleibt bei dieser Schicht bestehen. Ein Sprung steht als E16 im Audit-Log.
- Das Audit-Log selbst bleibt eigen, aber klein:
  - der Dienst mit Budgets, Zusammenfassung und Stand,
  - die Ablage auf der privaten Partition,
  - die Signaturkette nach Betriebszeit (AL-55 bis AL-61) und das Prüfwerkzeug.

  Gemeinsam mit journald ist der vorwärtssichere Schlüssel. Anders sind zwei Dinge: Das Audit-Log hängt an der Betriebszeit statt an der Uhr, und es ist mit einem öffentlichen Startwert prüfbar statt mit einem geheimen Schlüssel.

### Übergabe beim Pi-Tausch

Tauscht man einen Pi, kann das Ersatzgerät das Log weiterschreiben. Der Starthash bleibt dann gleich, und das Typenschild bleibt gültig (Festlegung 9). Den privaten Schlüssel der letzten Epoche hat das Ersatzgerät nicht: Er lag nur auf dem alten Gerät und darf nie kopiert werden (AL-56). Die Übergabe beglaubigt deshalb das verbleibende System mit seiner eigenen, signierten Kette.

- **AL-64** Ablauf der Übergabe:
  1. Das Ersatzgerät wird mit der Installerkarte als Ersatz in Betrieb genommen, ausdrücklich angestoßen durch einen Eintrag in `identity.conf`. Eine Übergabe geschieht nie von selbst.
  2. Es holt die Kopie seines Logs vom Partner (AL-29). Es prüft sie vom Starthash aus, mit dem Starthash vom Typenschild (AL-58, AL-61). Ist sie nicht gültig, beginnt ein neues Log (AL-19).
  3. Es erzeugt ein neues Schlüsselpaar. Das verbleibende System schreibt einen Übergabe-Eintrag in sein eigenes Log (Klasse Stand) und signiert ihn mit seinem laufenden Epochenschlüssel. Der Eintrag nennt:
     - den letzten Eintrag des alten Geräts in der Kopie: laufende Nummer, Hash, Epoche,
     - die Identität des alten und des neuen Geräts: Seriennummer der NVMe, bei Gerätebindung der öffentliche OTP-Schlüssel (AL-60),
     - den ersten öffentlichen Schlüssel des Ersatzgeräts,
     - Datum und Image der Installerkarte.
  4. Das Ersatzgerät setzt die Kette mit einem Übergabe-Eintrag fort. Dieser verweist auf den letzten übernommenen Eintrag und auf den Übergabe-Eintrag des Partners.
  5. Das Prüfwerkzeug geht so vor: Bis zur Übergabe prüft es die alte Kette mit den alten Schlüsseln. Die Übergabe prüft es über die Kette des Partners, die es von dessen Starthash aus prüft. Danach prüft es mit den Schlüsseln des Ersatzgeräts weiter.
- **AL-65** Lücke: Einträge, die das alte Gerät nach dem letzten Abgleich geschrieben hat, sind nicht in der Kopie.
  - Der Übergabe-Eintrag nennt die Lücke ausdrücklich: Er sagt, ab welcher laufenden Nummer nichts übernommen ist.
  - Ist der Datenträger des alten Geräts noch lesbar, werden diese Einträge nachträglich übernommen und gegen die alten Schlüssel geprüft.
  - Einträge der Klasse Stand gehen innerhalb einer Minute zum Partner (AL-29). Wesentliches fehlt deshalb höchstens aus der letzten Minute.
- **AL-66** Schutz gegen einen vorgetäuschten Tausch. Wer einen Tausch vortäuscht, könnte damit die jüngsten Einträge verschwinden lassen. Deshalb:
  - Eine Übergabe ist nur möglich, wenn sich die Geräteidentität vom alten Gerät unterscheidet: Seriennummer der NVMe bzw. OTP-Schlüssel.
  - Eine Übergabe ist ein Eintrag der Klasse Stand in beiden Logs.
  - Das alte Gerät, falls es noch läuft, schreibt den Versuch als E17.
  - Jede Übergabe kommt wie ein neuer Starthash ins ERP und als Nachtrag in die Betriebsanleitung.
- **AL-67** Werden beide Pis zugleich getauscht, gibt es niemanden, der die Übergabe beglaubigen kann. Dann beginnen beide Logs neu, mit neuem Starthash (AL-58). Die alten Logs bleiben auf den alten Datenträgern.

### USB am Duet-Pi: nur zum Export

- **AL-68** Der Duet-Pi lässt an USB nur einen einfachen USB-Stick zu (Festlegung 12). Es gilt dieselbe Regel wie beim USB-Wächter am HMI, aber ohne Kamera. Alles andere bleibt ohne Treiber und steht als E10 im Log.
  - Ein zugelassener Stick dient nur dem Export, nicht der Jobliste und nicht zum Einspielen von Dateien.
  - Steckt man ihn ein, exportiert der Duet-Pi automatisch das Maschinen-Log darauf: sein eigenes Log und die Kopie des HMI-Logs (AL-29), mit beiden Starthashes und dem Prüfergebnis.
  - Der Log-Dienst hängt den Stick dafür nur in seinem eigenen Namespace schreibbar ein und danach wieder aus.
  - Das Ende meldet er im Journal und als Hinweis am Panel. Dorthin gelangt der Hinweis über das Druckernetz, weil der Duet-Pi keinen Bildschirm hat.
  - Jeder Export ist ein Eintrag (E22).
  - So bleibt der Nachweis lesbar, auch wenn das HMI ausgefallen ist (T33).

## Nicht-Ziele

- Sammeln außerhalb der Maschine (Cloud, Server von Meltingplot).
- Alarmierung in Echtzeit.
- Sicherheitsrelevante G-Codes aus der DWC-Konsole, vorerst. Sie kommen später als eigenes Paket (Festlegung 13).
- Physische Siegel am Gehäuse. Das ist eine eigene Maßnahme (T31, T34).

## Offene Fragen

Alle Fragen sind beantwortet (Interview mit Tim, 2026-11-04). Sie bleiben hier mit ihrer Antwort stehen, damit die Nummern in den Verweisen gültig bleiben.

1. **CRA-Opt-out gegen MVO-Pflicht:** Beantwortet (Tim, 2026-11-04): kein Opt-out (Festlegung 10).
2. **Aufbewahrung:** Beantwortet (Tim, 2026-11-04): fünf Jahre für alle (Festlegung 11).
3. **Export für Betreiber (AL-21):** Beantwortet (Tim, 2026-11-04): Seite am Panel mit Export auf USB-Stick (Festlegung 12).
4. **Parameter zur Laufzeit:** Beantwortet (Tim, 2026-11-04): später, eigenes Thema (Festlegung 13).
5. **Uhr ohne Netz:** Beantwortet (Tim, 2026-11-04): nachrüsten; bis dahin reicht die Markierung (Festlegung 14).
6. **Datenschutz:** Beantwortet (Tim, 2026-11-04): die rechtliche Pflicht reicht (Festlegung 15).
7. **Zwei Systeme:** Beantwortet (Tim, 2026-11-04): beides Pflicht (Festlegung 16).
8. **USB-Wächter auch auf dem Duet-Pi?** Beantwortet (Tim, 2026-11-04): Der Duet-Pi nimmt nur einen USB-Stick an, nur zum Export der Logs, automatisch beim Einstecken (Festlegung 12, AL-68).
9. **USB-Kamera:** Beantwortet (Tim, 2026-11-04): Updates und Gerätewechsel der Kamera stehen im HMI-Log (Festlegung 17).
10. **Bestandsgeräte (AL-36):** Beantwortet (Tim, 2026-11-04). Ja, alle werden mit der Installerkarte überführt. Sie haben noch kein Log, die Karte muss nur das Layout gen1 oder gen2 überführen (Festlegung 7, AL-18).
11. **Anmeldung bei vollem Log (AL-48):** Beantwortet (Tim, 2026-11-04): Anmeldungen bleiben erlaubt (Festlegung 18).
12. **Verankerung des Starthashes (AL-58):** Beantwortet (Tim, 2026-11-04). Ein Prüfschlüssel entfällt, weil die Kette mit öffentlichen Schlüsseln prüfbar ist. Der Starthash entsteht bei der Inbetriebnahme auf dem Gerät, wird ausgelesen und in Betriebsanleitung, ERP und Typenschild festgehalten (Festlegung 8). Für das normale Journal (AL-63) bleibt der geheime Schlüssel von journald zu verwahren.
13. **Gerätebindung (AL-60):** Beantwortet (Tim, 2026-11-04). Am Laborgerät geprüft: Der Schlüssel ist nicht erzeugt, Secure Boot ist nicht aktiv. Die Bindung kommt mit der Secure-Boot-Provisionierung (Festlegung 19, Befund in AL-60).

## Umsetzung

Der Phasenplan steht in [phase-plan.md](phase-plan.md). Dort steht auch, was in jeder Phase umgesetzt ist.

## Nachweis

| Kriterium GS-IFA-M25 | Anforderung | Prüfung |
|---|---|---|
| T33 lesbar und zugänglich | AL-20, AL-21, AL-68 | Log über Connect-Shell anzeigen. Am Panel auf einen USB-Stick exportieren: Der Stick enthält beide Logs, die Starthashes und das Prüfergebnis, E22 steht im Log. Einen Stick am Duet-Pi einstecken: Export ohne weiteres Zutun, Hinweis am Panel. Eine Tastatur am Duet-Pi: abgewiesen, E10. |
| T21, T22 Zugriff und Auswertung laut Betriebsanleitung | AL-23, AL-58, AL-61 | Nach der Betriebsanleitung: QR-Code vom Typenschild scannen, `mp-audit verify` mit diesem Starthash ausführen. Das Ergebnis meldet je System, ob die Kette lückenlos von genau diesem Anfang ausgeht. |
| T35 automatisch | AL-09 | Tastatur anstecken, Eintrag E10 ohne weiteres Zutun |
| T36 Schutz vor Deaktivierung | AL-09 bis AL-12 | Dienst als `meltingplot` stoppen: verweigert; als root stoppen: Lücke beim nächsten Boot als E17 |
| T37 Speicherort dokumentiert | AL-04, AL-23 | Betriebsanleitung |
| T38 letzter Eintrag je Art | AL-06 | Test mit gekürztem Log |
| T39 fünf Jahre | AL-05, AL-07 | Budgetrechnung, Test mit gealterten Einträgen |
| T40, T41 aktiv ab Inbetriebnahme | AL-09, E01 | frisch installierte Karte: E01 im Log |
| T42 Manipulationsschutz | AL-13 bis AL-16 | Zeile ändern oder löschen: `verify` meldet die Stelle |
| T43, T44 Löschen | AL-17, AL-18 | Löschen per Befehl und Neuinstallation: E18 im neuen Log |
| T45 Inhalt | AL-01 | Test |
| T46, T47 Software-Identifikation | AL-22 | Ausgabe am Gerät |
| T36, T37 eigene Partition | AL-04, AL-33 bis AL-37 | `findmnt` in einer Shell zeigt keinen Einhängepunkt, `lsblk` die Partition. Persistenzpartition vollschreiben oder neu formatieren: Das Log schreibt weiter bzw. bleibt erhalten. Neuinstallation über eine belegte NVMe: Das alte Log ist danach da, mit E18. |
| T36, T42 gegen Fluten | AL-39 bis AL-48 | Test mit simulierter Betriebszeit: fünf Jahre Dauerflut über alle Klassen, in die man schreiben kann, mit rollierend wechselnden Quellen, Objekten und Texten (USB-Kennungen, auch ein zugelassener Stick, SSH-Konten und Adressen, Dateinamen unter `0:/sys`). Vorher, mittendrin und am Ende je eine Anmeldung als `mpadmin` und eine Änderung an `config.g`. Danach: kein Anteil über seiner Grenze; alle Einträge von vor der Flut unverändert (Prüfkette); in der Klasse Stand jede der Änderungen und Anmeldungen mindestens auf den Tag genau; die Flut als E19 mit Sammeleinträgen. Zusätzlich jedes Objekt der festen Menge täglich geändert: Die Klasse Stand bleibt unter ihrem Anteil. Partition nicht schreibbar simuliert: Update und Firmware-Flash werden verweigert. |
| Verschleiß (kein eigenes Kriterium, Voraussetzung für T39) | AL-50 bis AL-54 | Eine Stunde lang 1000 Ereignisse pro Sekunde: Die Schreibmenge auf den Datenträger laut `/sys/block/*/stat` bleibt unter 5 MB für diese Stunde. Rechnung AL-52 gegen die TBW aus dem Datenblatt der verbauten SSD. |
| T42, T48 Signaturkette | AL-55 bis AL-61 | Auf einem Testgerät als root einen Eintrag einer früheren Epoche ändern und Kette sowie Signaturen mit allem neu rechnen, was auf dem Gerät liegt: Das Prüfwerkzeug meldet die Epoche als verändert, geprüft nur mit dem Starthash. Log löschen und neu anlegen: Der Starthash passt nicht zum Inbetriebnahmeprotokoll. Nach einem Login als `mpadmin`: Die Anmeldung ist signiert, bevor die Shell kommt. |
| T39, T43 Pi-Tausch | AL-19, AL-29, AL-64 bis AL-67 | Ein System durch einen leeren Pi ersetzen, Übergabe über `identity.conf`. Danach: `mp-audit verify` mit dem Starthash vom Typenschild meldet die Kette als gültig über die Übergabe hinweg; der Übergabe-Eintrag steht in beiden Logs und nennt die Lücke. Dieselbe Übergabe mit demselben Gerät (gleiche Identität) wird abgewiesen. |
| T39, T42 gegen gestellte Uhr | AL-46, AL-49 | Uhr um sechs Jahre vordrehen, dann fluten: Nichts wird gelöscht, kein Budget füllt sich schneller auf, E16 steht im Log. Uhr zurückdrehen: Reihenfolge nach laufender Nummer bleibt richtig. |
| T37, T42 über beide Systeme | AL-25 bis AL-32 | Log auf einem System kürzen: das andere meldet die Abweichung. Druckernetz eine Stunde trennen: beide loggen weiter, die Verankerung wird nachgeholt. Export am HMI enthält beide Logs. |
