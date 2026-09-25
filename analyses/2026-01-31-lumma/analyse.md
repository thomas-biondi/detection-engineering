# Rapport d'incident. Infection par voleur d'informations Lumma Stealer

Source de la capture : exercice public malware-traffic-analysis.net du 31 janvier 2026,
portant sur un trafic du 27 janvier 2026. Capture non versionnée, disponible auprès de
l'éditeur.

Tous les horodatages de ce document sont exprimés en UTC.

## Résumé exécutif

Le mardi 27 janvier 2026 vers 23h05 UTC, un poste de travail Windows du réseau a été
infecté par Lumma Stealer, un logiciel malveillant spécialisé dans le vol d'informations.
L'infection a été signalée par une alerte de détection réseau.

Le programme a été téléchargé depuis un site de partage de fichiers, puis s'est déclaré
auprès de son serveur de contrôle en transmettant une empreinte détaillée du poste. Il a
ensuite tenté de transmettre une archive de données collectées sur le poste. La réponse
du serveur indique un échec de lecture de cette archive, de sorte que la réception
effective des données volées n'est pas établie.

Cette incertitude ne modifie pas la réponse. Un voleur d'informations a accès aux mots de
passe enregistrés dans les navigateurs et aux jetons de session actifs, lesquels
permettent d'accéder aux comptes sans repasser par l'authentification multifacteur.
L'ensemble des comptes utilisés depuis ce poste doit être considéré comme compromis.

Un trafic chiffré vers deux domaines supplémentaires a été observé immédiatement après,
compatible avec le chargement d'un second logiciel malveillant.

## Cadrage

| Élément | Valeur |
| --- | --- |
| Segment | 10.1.21.0/24 |
| Passerelle | 10.1.21.1 |
| Contrôleur de domaine | 10.1.21.2, WIN-LU4L24X3UB7 |
| Domaine Active Directory | WIN11OFFICE, win11office.com |
| Alerte d'origine | ET MALWARE Lumma Stealer Victim Fingerprinting Activity, 153.92.1.49 port 80 |
| Volume de la capture | Environ 51 000 paquets |
| Fenêtre couverte | 23:04:03 à 23:14:27 UTC, soit 10 minutes |

## Détails de la victime

| Élément | Valeur | Source |
| --- | --- | --- |
| Adresse IP | 10.1.21.58 | Hôte interne en communication avec l'adresse de l'alerte |
| Adresse MAC | 00:21:5d:c8:0e:f2 | Couche Ethernet |
| Nom d'hôte | DESKTOP-ES9F3ML | Enregistrement NetBIOS |
| Compte utilisateur | gwyatt | Principal de la requête d'authentification Kerberos |
| Nom complet | Gabriel Wyatt | Recherche de chaîne dans le détail des paquets |

Aucune requête LDAP portant les attributs du compte n'est présente dans la fenêtre de la
capture. Le nom complet a été retrouvé par une recherche de chaîne sensible à la casse,
construite à partir du format apparent du compte, initiale du prénom suivie du nom.

## Chronologie

| Heure UTC | Événement | Écart |
| --- | --- | --- |
| 23:04:03 | Début de la capture | |
| 23:04:52 | Téléchargement depuis `arch.filemegahab4.sbs`, environ 17 Mo | T0 |
| 23:05:36 | Premier échange avec `whitepepper.su`, 153.92.1.49 port 80 | T0 + 44 s |
| Période suivante | Enregistrement de l'implant, envoi de l'empreinte, tentative d'envoi d'archive | |
| Après la fin des échanges avec le C2 | Sessions TLS vers `holiday-forever.cc` et `communicationfirewall-security.cc` | |
| 23:14:27 | Fin de la capture | T0 + 9 min 35 s |

## Chaîne d'infection

### Distribution

Un fichier d'environ 17 Mo a été téléchargé depuis `arch.filemegahab4.sbs`. L'adresse
associée, 104.21.46.67, appartient à un réseau de distribution de contenu et ne désigne
pas l'hébergement réel.

Le moyen par lequel l'utilisateur a été conduit vers ce site n'est pas établi depuis la
capture, dont la fenêtre débute moins d'une minute avant le téléchargement.

### Enregistrement de l'implant

Le trafic avec `whitepepper.su` circule en HTTP clair sur le port 80.

| Requête | Rôle observé |
| --- | --- |
| `GET /api/set_agent?id=...&agent=Chrome` | Déclaration de l'implant, navigateur ciblé Chrome |
| `GET /api/set_agent?id=...&agent=Edge` | Même déclaration, navigateur ciblé Edge |
| `POST /api/set_agent?...&act=log` | Transmission de données, environ 8 Ko par requête |

La mention du navigateur dans le paramètre `agent` indique que l'implant énumère les
navigateurs installés, cibles habituelles d'un voleur d'informations.

### Contenu transmis

Le contenu des requêtes `act=log`, encodé en paramètres de formulaire, est lisible dans
le flux. Il comporte une empreinte matérielle et logicielle détaillée du poste : carte
graphique, résolution d'affichage, extensions installées, entre autres.

Cet envoi correspond à la signature de détection à l'origine de l'alerte.

### Tentative de transmission d'une archive

Une réponse du serveur à une requête POST contient le message suivant :

```
cant open archive 172.56.88.98-038485b1855ec7a1ba5bbda042ad17a1.zip
```

Deux enseignements.

Le nom de l'archive associe une adresse IP publique à un identifiant. L'adresse est
vraisemblablement l'adresse de sortie Internet du site, telle que vue par le serveur. Ce
point constitue une hypothèse.

Le serveur signale un échec d'ouverture. La réception effective des données collectées
n'est donc pas établie par la capture.

Le message établit que le serveur attendait une archive et la référence par son nom. Il
n'établit pas que l'archive a été transmise. Elle n'a pas été observée dans le flux
examiné, et sa présence dans un autre flux de la capture reste à vérifier par recherche
de la signature d'en tête des archives ZIP, filtre `frame contains 50:4b:03:04`.

> Une réponse d'erreur d'un serveur malveillant ne constitue pas une garantie. Elle
> établit seulement que l'aboutissement de l'exfiltration n'est pas démontré. Le
> message peut être erroné, et une nouvelle tentative hors de la fenêtre de capture reste
> possible.

### Activité consécutive

Immédiatement après la fin des échanges avec `whitepepper.su`, le poste a établi des
sessions TLS vers `holiday-forever.cc` et `communicationfirewall-security.cc`.

Le lien avec l'infection repose sur l'adjacence temporelle et sur la correspondance avec
des schémas documentés publiquement pour cette famille. Le trafic étant chiffré, aucune
observation directe n'établit que ces sessions ont été initiées par l'implant ni qu'un
second programme a été installé.

Formulation retenue : activité compatible avec le chargement d'un second logiciel
malveillant.

## Indicateurs de compromission

Export exploitable : `iocs.csv`.

| Valeur | Rôle | Qualification |
| --- | --- | --- |
| `whitepepper.su`, 153.92.1.49 | Commande et contrôle Lumma Stealer | Malveillant |
| `arch.filemegahab4.sbs` | Distribution du fichier initial | Malveillant |
| 104.21.46.67 | Réseau de distribution de contenu devant le site de distribution | Observée, non actionnable |
| `holiday-forever.cc` | Activité consécutive | Suspect |
| `communicationfirewall-security.cc` | Activité consécutive | Suspect |
| `/api/set_agent` en HTTP clair | Motif d'enregistrement et de transmission | Comportemental |

## Empreintes de fichiers

Aucune empreinte n'a été établie. Le fichier initial provient d'un site servi par un
réseau de distribution de contenu, et son extraction depuis la capture n'a pas été
réalisée dans le cadre de cette analyse.

## Recommandations

| Priorité | Mesure |
| --- | --- |
| Immédiate | Isolement du poste, réinstallation. |
| Immédiate | Réinitialisation des mots de passe de tous les comptes utilisés depuis ce poste, y compris les comptes personnels enregistrés dans les navigateurs. |
| Immédiate | Révocation des sessions actives sur les services concernés. Un jeton de session volé permet l'accès sans nouvelle authentification multifacteur. |
| Immédiate | Recherche rétroactive des indicateurs sur l'ensemble du parc. |
| À court terme | Blocage des domaines en sortie, au niveau de la résolution de noms. |
| À court terme | Analyse de l'activité consécutive pour identifier un éventuel second logiciel malveillant. |

## Limites de l'analyse

| Point | Limite |
| --- | --- |
| Périmètre temporel | 10 minutes. La fenêtre débute moins d'une minute avant le téléchargement. |
| Accès initial | Moyen par lequel l'utilisateur a atteint le site de distribution non établi. |
| Exfiltration | Archive référencée par le serveur, transmission non observée à ce stade, aboutissement non démontré. |
| Activité consécutive | Lien causal non établi, trafic chiffré. |
| Nom complet | Obtenu par recherche de chaîne. Le protocole porteur reste à préciser. |

## Référence

Analyse de référence publiée par l'éditeur de la capture. Une partie des constats a été
établie en autonomie, une autre avec assistance. La répartition est consignée dans le
journal de session.

L'analyse de référence comporte deux incohérences internes, sur l'adresse de la victime
et sur celle du serveur de contrôle. Les valeurs retenues dans le présent document sont
celles observées dans la capture.
