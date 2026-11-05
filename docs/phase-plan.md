# Phasenplan: Audit-Log

Die Anforderungen stehen in [docs/meltingplot-audit-log.md](https://github.com/Meltingplot/rpi-image-gen/blob/meltingplot/docs/meltingplot-audit-log.md) im Repository Meltingplot/rpi-image-gen; darauf beziehen sich AL-nn, E01 bis E23, T-Nummern und „Festlegung nn“. LY-nn steht in [docs/meltingplot-layout.md](https://github.com/Meltingplot/rpi-image-gen/blob/meltingplot/docs/meltingplot-layout.md) dort.

**Zwei Phasen (Tim, 2026-11-04):**
- **Phase 1:** Layout gen3 mit der Partition `audit` und eine Installerkarte, die gen1 und gen2 überführt und auf gen3 die Partition stehen lässt.
- **Phase 2:** Der Log-Dienst kommt danach per OTA auf Geräte, die die Partition schon haben.

Phase 1 im Einzelnen:
- `image-rota` hat die Variablen `image.private_part_name` und `image.private_part_size`.
- Die Provisioning-Map unterstützt die Partition vorerst nur mit `pmap: clear`.
- Die Karte vermisst beim Bauen Lage und Größe der Partition im Image (`mp-installer-measure`) und prüft das Rücklesen ohne diesen Bereich.
- Was sie vorgefunden hat, schreibt sie in `meltingplot/installer.txt` auf der BOOTCONFIG-Partition: `layout_before`, `keep_part`, `kept`.

Phase 1 ist seit Duet rc.75 / HMI rc.11 gebaut und am 2026-11-04 auf dem Bench-HMI installiert.

Phase 2 in Schritten, jeder ein eigener PR und per OTA einspielbar:

- **2a Kern** (Layer `mp-audit`):
  - `mp-audit.service` (`mp-auditd`): hängt die Partition nur im eigenen Namespace ein und formatiert nur ohne Dateisystem-Signatur (AL-04, AL-34, AL-37); ohne Partition nur Journal und E17 bei jedem Boot (AL-36).
  - Eintragsformat (AL-01 bis AL-03), Prüfkette (AL-13), `chattr +a` (AL-14), Spiegel ins Journal (AL-08).
  - Klassen, Budgets nach Betriebszeit, Sammeleinträge mit E19 (AL-39 bis AL-43, AL-46, AL-49), Schreiben in festen Abständen (AL-50, AL-51).
  - Epochen mit Schlüsselpaar je Epoche, Genesis und Starthash (AL-55 bis AL-57), Prüfung ohne Geheimnis (AL-61).
  - Lücken nach Absturz, abgebrochene Schreibvorgänge, verlorener Schlüssel (AL-11), Einträge aus dem Journal übernehmen (AL-35), Löschen mit E18 (AL-17).
  - Eigene Ereignisse: E01, E02, E15, E16, E17, E18 aus `installer.txt`.
  - Werkzeug `mp-audit` mit `record`, `show`, `verify`, `genesis`, `status`, `reset`.
  - Test `test/test-mp-audit.sh`.
- **2b Quellen:** die Wächter rufen `mp-audit record` (USB-Wächter, `mp-bundle-guard`, `mp-role-guard`, `mp-hmi-net-guard`, `mp-dsf-firmware`, `mp-dsf-seed`, `mp-ota-gate`, `mp-hmi-usb`, Kamera); Collector für sshd, sudo, rpi-connect, AppArmor (AL-62); Anmeldung über PAM synchron versiegelt (AL-56); kein Eingriff ohne Nachweis (AL-48), auch ohne Audit-Partition (Festlegung 20), daher vorher alle Bestandsgeräte auf gen3 überführen; USB am Duet-Pi nur für den Stick (AL-68, ohne Export).
- **2c Stand:** feste Menge (AL-42, AL-45), E20 bei jedem Boot und täglich, Änderungen unter `0:/sys` (E05), Verschleiß (E21, AL-53), Kürzen nach fünf Jahren (AL-05 bis AL-07).
- **2d Partner:** Verankerung und Kopie zwischen HMI und Duet-Pi (AL-28 bis AL-32), Starthash des Partners am Panel. Entwurf mit Corosync unter „Entwurf für 2d“, zurückgestellt hinter 2b (Tim, 2026-11-05).
- **2e Anzeige und Export:** Seite am Panel, Export auf USB-Stick an beiden Systemen (AL-21, AL-31, AL-68, E22), Übergabe beim Pi-Tausch (AL-64 bis AL-67).

Abweichungen in 2a von der Skizze unten:

- Die Signatur einer Epoche deckt über `prev` die ganze Kette bis zu ihr ab. Ein eigener Hash „ihrer Einträge“ und „der vorigen Epoche“ (AL-55) steckt darin.
- Zusammengefasste Ereignisse bekommen ihre laufende Nummer beim Eintreffen. Ein Sammeleintrag nennt Anzahl, erste und letzte Nummer. Die Prüfung zählt: Jede Nummer bis zur höchsten ist ein Eintrag, steckt in einem Sammeleintrag oder ist als verloren gemeldet (E17 mit `lost`).
- Ein Sammeleintrag ist höchstens etwa 1 KB groß. Nach einem Tag wird er auch ohne Budget geschrieben (AL-41). Jede Klasse verdient täglich genug für einen Sammeleintrag je Ereignis-ID; das prüft der Test.
- Epochen ohne neue Einträge werden nicht versiegelt. Ist der Anteil Reserve aufgebraucht, wird stündlich statt alle 15 Minuten versiegelt.
- Ein Sammeleintrag, der noch nicht geschrieben ist, ist keine Lücke. Nach einer Flut kann das bis zu einen Tag dauern, auch über Neustarts hinweg. E19 nennt die erste Nummer, die der Sammeleintrag zählt (`from`). Die Prüfung über den Dienst bekommt die offenen Sammeleinträge mitgeliefert und zählt jede Nummer genau. Eine Prüfung aus Dateien nimmt eine Lücke nur hin, soweit E19 offene Sammeleinträge ankündigt, und meldet dann `pending` statt `valid`. Nummern vor dem ersten offenen Sammeleintrag müssen in geschriebenen Sammeleinträgen stecken oder als verloren gemeldet sein.
- Das Löschen nach AL-17 schreibt zuerst die offenen Sammeleinträge und vernichtet danach alle Schlüssel des alten Logs. Das archivierte Log ist damit abgeschlossen und lässt sich nicht unbemerkt fortsetzen.
- Ein Stopp des Dienstes, während das System läuft, ist ein E17 (T36), ebenso der Start danach im selben Boot, mit der Dauer der Lücke. Beim Herunterfahren gibt es keinen Eintrag.
- E02 steht auch im Boot, der das Log anlegt. Das ist meist der Probestart des ersten Images mit Audit-Log, also gehört auch sein Ausgang hinein. Der Ausgang wird auch dann eingetragen, wenn der Dienst ihn erst beim nächsten Start sieht: Commit in der letzten Minute oder Rückfall auf ein Image ohne Audit-Log.

Bench-Test 2026-11-04 (HMI rc.12 per OTA auf dem Bench-HMI, Log im Probestart angelegt): Namespace, `chattr +a`, Schlüssel je Epoche, Rechte, Journal-Übernahme, Absturz des Dienstes mit zurückgeholtem Eintrag, E15 nach hartem Reset, E16 bei Zeitsprüngen, Flut mit E19, periodisches Versiegeln und Prüfung einer Kopie auf einem anderen Rechner liefen wie beschrieben. Die vier Punkte oben kamen aus diesem Test.

## Entwurf für 2d: Abgleich über Corosync

Stand 2026-11-05, zurückgestellt: erst Phase 2b. Grundlage ist ein Gespräch mit Tim.

Vorgaben:

- Alle Teilnehmer hängen per Ethernet am selben Switch im Druckernetz. Weitere Teilnehmer sollen später dazukommen können, nicht nur HMI und Duet-Pi.
- Kein Peer-to-Peer-Geflecht. Jeder Teilnehmer verteilt sein eigenes Log an die Gruppe; keiner reicht Logs anderer weiter.
- Standard-Software statt eines eigenen Transportprotokolls: Corosync, wie es Proxmox für sein Cluster-Dateisystem `pmxcfs` nutzt.

Ablauf:

- **Transport:** Corosync 3 (Debian trixie: 3.1.9) mit Closed Process Groups (CPG). Das bringt zuverlässige Zustellung an alle Mitglieder in fester Reihenfolge und Meldungen, wer dazukommt oder ausfällt. Als Transport dient knet mit fester Teilnehmerliste (`nodelist`) aus dem Image, nach den festen Adressen im Druckernetz (10.42.0.1, .2, später weitere). Ein neuer Teilnehmertyp kommt mit einem Update auf alle Geräte. Das Quorum von Corosync wird nicht gebraucht. UDP-Port 5405 nur im Druckernetz.
- **Laufend:** Jede neue Zeile eines Logs, Eintrag oder Siegel, geht als CPG-Nachricht an die Gruppe: Starthash als Name des Logs, Zeilennummer, die Zeile so, wie sie auf der Platte steht. Die Empfänger hängen sie nur lückenlos und in Reihenfolge an ihre Kopie unter `partner/<Starthash>/` an. Die Kopie ist nur anhängbar (`chattr +a`). Vor dem Anhängen prüfen sie die Kette, abgeschlossene Epochen an ihren Siegeln.
- **Nachholen:** Corosync hält keine Historie, Nachrichten erreichen nur verbundene Mitglieder. Deshalb senden bei jeder Änderung der Mitgliedschaft alle ihren Stand: Starthash, Zeilenzahl, letzter Hash, Epoche, Boot-Zähler. Wer zurückliegt, fordert die fehlenden Zeilen über die Gruppe an, und nur der Eigentümer des Logs schickt sie nach, gedrosselt. So holt auch ein neuer Teilnehmer auf. Proxmox gleicht in `pmxcfs` ebenso bei jeder Änderung der Mitgliedschaft ab.
- **Verankerung (AL-28):** Aus den Ständen schreibt jeder Teilnehmer regelmäßig Anker der anderen in sein eigenes Log, und sofort nach einem Eintrag der Klasse Stand beim Partner.
- **Bindung:** Beim ersten Kontakt hält jeder den Starthash jedes anderen Teilnehmers fest, als Eintrag der Klasse Stand. Ein anderer Starthash unter derselben Teilnehmerkennung ist ein E17, außer bei einer angestoßenen Übergabe (AL-64).
- **Platz:** Jeder Teilnehmer hält eine Kopie jedes Logs der Gruppe. Bei zwei Teilnehmern passt das in 1 GiB (2 × 256 MiB). Bei mehr wächst `audit` in die Reserve (Layout LY-03).
- **Anbindung:** Debian hat keine Python-Anbindung für Corosync. `mp-auditd` spricht `libcpg` über `ctypes` an, oder über ein kleines C-Hilfsprogramm.

Verworfen:

- Abholen per TCP zwischen den Geräten: keine Gruppe, jedes Paar einzeln.
- Ein Geflecht nach dem Vorbild von Secure Scuttlebutt, bei dem jeder Logs anderer weiterreicht: kein Peer-to-Peer.
- Ein eigenes Protokoll über UDP-Broadcast nach dem Muster von RTPS oder NORM: Es müsste Verluste, Reihenfolge und Zerlegung selbst lösen, die Corosync schon löst.

Offen:

1. Verschlüsselung in knet mit einem `authkey` je Drucker, der bei der Inbetriebnahme verteilt wird, oder ohne. Ohne bleiben die Daten fälschungssicher, weil Kette, Siegel und Starthash sie schützen; nur die Gruppe ließe sich dann am Switch stören.
2. Ereignis-ID und Klasse des Ankers: Unter E01 bis E23 passt keine. Vorschlag: E24, Klasse Betrieb.
3. Ob jedes Log auf jedem Teilnehmer liegt oder bei vielen Teilnehmern nur auf einigen.

Eine Skizze für das Ganze, nicht bindend:

- Layout (`image/gpt/ab_userdata`, `image-rota`), allgemein für Upstream (AL-38):
  - neue Variable in `image.yaml`, etwa `image.private_part_name` und `image.private_part_size`, standardmäßig leer;
  - die Partition in `genimage.cfg.in.erofs` und `.ext4` sowie die Größe in `preimage05-templates`;
  - je ein Eintrag in den vier `provisionmap-*.json`;
  - die udev-Regel für `/dev/disk/by-slot/<name>` in `99-rpi-05-image.rules`.
  - `mp-base.yaml` setzt dann `audit` und `256M`.
- Neuer Layer `mp-audit` in `mp-base.yaml`, also für beide Geräte, wie `mp-watchdog`.
  - `mp-audit.service`: hängt die Partition privat ein (`PrivateMounts=yes`, AL-34), formatiert sie nur nach AL-37 und nimmt Einträge über einen Socket an. Er führt laufende Nummer, Boot-Zähler, Prüfkette und den letzten Eintrag je Ereignis-ID und gibt jeden Eintrag zusätzlich ins Journal.
  - `/usr/bin/mp-audit` (Festlegung 22) mit den Unterbefehlen `record`, `show`, `verify`, `reset` und `export`, alle über den Socket des Dienstes. Läuft der Dienst nicht, gibt `record` den Eintrag gekennzeichnet ins Journal (AL-35).
- Unsere Wächter rufen `mp-audit record` direkt auf: USB-Wächter, `mp-bundle-guard`, `mp-role-guard`, `mp-hmi-net-guard`, `mp-dsf-firmware`, `mp-dsf-seed`.
- `mp-audit-boot.service`, früh im Boot:
  - zählt den Boot-Zähler hoch,
  - prüft das saubere Ende des letzten Boots und den Image-Wechsel (E02, E15, E17),
  - prüft die Kette.
- `mp-audit-collect.service` liest das Journal mit und übernimmt Ereignisse fremder Programme: sshd (E12), sudo (E13), rpi-connect (E14), AppArmor-Meldungen des Kernels (E07), Zeitsprünge (E16).
- Änderungen unter `0:/sys` außerhalb des Boots (E05): ein Dienst, der das Verzeichnis per inotify überwacht und Hashes vergleicht.
- `mp-audit-peer.service` auf beiden Systemen, über das Druckernetz:
  - tauscht Verankerung und Kopie aus (AL-28 bis AL-30),
  - nur zwischen 10.42.0.1 und 10.42.0.2 erreichbar,
  - liest beim Partner nur, schreibt nie in dessen Log.
- Die Anzeige und der Export des Maschinen-Logs (AL-31) liegen am HMI, weil der Bediener dort steht. Über die Connect-Shell gibt es sie auf beiden Systemen.
- Installer: schreibt auf gen3 um die Audit-Partition herum (AL-18), Phase 1.
- Test `test/test-mp-audit.sh`, deckt ab:
  - Kette, Prüfung und gezielte Manipulation,
  - Löschen mit E18,
  - Maskierung fremder Zeichenketten,
  - paralleles Schreiben,
  - Budget und Kürzung mit AL-06.
