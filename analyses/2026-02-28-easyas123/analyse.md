# Rapport d'incident. Poste sous contrôle d'un outil d'administration à distance détourné

Source de la capture : exercice public malware-traffic-analysis.net du 28 février 2026.
Capture non versionnée, disponible auprès de l'éditeur.

Tous les horodatages de ce document sont exprimés en UTC.

## Résumé exécutif

Le samedi 28 février 2026 à 19h55 UTC, des alertes de détection ont signalé une
communication entre un poste de travail Windows du réseau et un serveur connu pour
piloter l'outil NetSupport Manager détourné à des fins malveillantes.

L'analyse du trafic confirme que le poste est sous le contrôle d'un tiers. La capture
débute au démarrage du poste. L'outil s'active 28 secondes après l'ouverture de session
de l'utilisateur, sans aucun téléchargement préalable, ce qui établit qu'il était déjà
installé et configuré pour démarrer automatiquement. L'infection est donc antérieure à la
collecte, et la manière dont elle s'est produite n'apparaît pas dans le trafic examiné.

Le poste a maintenu le contact avec le serveur de contrôle à raison d'environ une
requête par minute jusqu'à la fin de la période observée.

L'attaquant dispose d'un accès interactif au poste avec les droits de l'utilisateur
connecté. Aucun transfert de volume significatif n'a été observé sur les quatre heures
couvertes, mais la durée réelle de la compromission est inconnue.

## Cadrage

| Élément | Valeur |
| --- | --- |
| Segment | 10.2.28.0/24 |
| Passerelle | 10.2.28.1 |
| Contrôleur de domaine | 10.2.28.2, EASYAS123-DC |
| Domaine Active Directory | EASYAS123, easyas123.tech |
| Alerte d'origine | Signatures NetSupport Manager RAT, 45.131.214.85 port 443 |
| Volume de la capture | Environ 15 000 paquets |
| Fenêtre couverte | 28 février 19:55:06 au 1er mars 00:16:35 UTC, soit 4 h 21 |

## Détails de la victime

| Élément | Valeur | Source |
| --- | --- | --- |
| Adresse IP | 10.2.28.88 | Hôte interne en communication avec l'adresse de l'alerte |
| Adresse MAC | 00:19:d1:b2:4d:ad | Couche Ethernet |
| Nom d'hôte | DESKTOP-TEYQ2NR | Option 12 du bail DHCP, transaction de 19:55:06 |
| Compte utilisateur | brolf | Principal de la requête d'authentification Kerberos |
| Nom complet | Becka Rolf | Champ de nom complet d'une réponse SAMR |

SAMR est l'interface distante de gestion des comptes du contrôleur de domaine, transportée
en DCE/RPC sur un canal nommé SMB. Les réponses aux requêtes d'interrogation d'un compte
portent le nom complet de l'utilisateur.

## Chronologie

| Heure UTC | Événement |
| --- | --- |
| 28/02 19:55:06 | Début de la capture. Transaction DHCP complète, le poste rejoint le réseau |
| 28/02 19:55:23 | Authentification Kerberos du compte `brolf`, ouverture de session |
| 28/02 19:55:50 | Requête vers un site institutionnel légitime, voir ci dessous |
| 28/02 19:55:51 | Résolution de `vadusa.xyz` vers 45.131.214.85 |
| 28/02 19:55:51 | Première requête `POST /fakeurl.htm` vers 45.131.214.85 port 443, en HTTP clair |
| 28/02 20:18:55 | Téléchargement d'une extension de navigateur depuis l'infrastructure de l'éditeur du navigateur, activité légitime |
| Période couverte | Échanges avec le serveur de contrôle à raison d'environ une requête par minute |
| 01/03 00:16:28 | Dernier contact avec le serveur de contrôle |
| 01/03 00:16:35 | Fin de la capture, 7 secondes après le dernier contact |

## Analyse

### Un implant déjà en place, activé au démarrage

La capture couvre la séquence de démarrage du poste.

| Heure UTC | Étape | Écart |
| --- | --- | --- |
| 19:55:06 | Transaction DHCP, arrivée du poste sur le réseau | |
| 19:55:23 | Authentification Kerberos du compte utilisateur | Ouverture de session |
| 19:55:51 | Premier contact avec le serveur de contrôle | Ouverture + 28 s |

La première communication avec le serveur de contrôle est une requête `POST /fakeurl.htm`,
caractéristique du client NetSupport en fonctionnement. Elle suit immédiatement l'unique
résolution du domaine configuré comme passerelle. Aucun téléchargement de programme
n'est observé entre l'ouverture de session et ce premier contact.

Deux conclusions en découlent. L'implant était installé avant le début de la collecte.
Un mécanisme de démarrage automatique existe sur le poste, puisque l'implant s'active
après ouverture de session sans intervention observable. La nature de ce mécanisme,
raccourci de démarrage, clé de registre ou tâche planifiée, n'est pas déterminable depuis
le réseau.

> Un implant qui s'active après ouverture de session sans aucun téléchargement préalable
> établit l'existence d'un mécanisme de persistance, sans en révéler la nature.

### Requête vers un site légitime une seconde avant le premier contact

Une requête vers `www.fmcsa.dot.gov`, site d'une agence fédérale américaine, précède d'une
seconde la résolution du domaine de contrôle. Cette proximité a été examinée comme
possible vecteur d'infection, puis écartée.

| Critère | Constat |
| --- | --- |
| Délai jusqu'au premier contact | 1 seconde, incompatible avec un téléchargement suivi d'une exécution |
| Étape de distribution intermédiaire | Aucune |
| Nature du premier contact | Trafic d'un implant déjà opérationnel |

Hypothèse retenue : les deux événements sont simultanés sans être liés. Une ouverture de
session déclenche au même instant les programmes lancés au démarrage, dont l'implant, et
la réouverture de la page d'accueil ou des onglets du navigateur.

L'hypothèse est corroborée par l'horodatage de l'authentification Kerberos du compte, à
19:55:23. La requête vers le site et le premier contact avec le serveur de contrôle
surviennent tous deux 27 à 28 secondes après, délai cohérent avec le chargement de la
session et le lancement des programmes de démarrage.

> Une adjacence temporelle génère une hypothèse. Elle n'établit un lien qu'en présence
> d'un mécanisme plausible reliant les deux événements. En l'absence d'étape de
> distribution, deux événements proches ne forment pas une chaîne.

Aucun élément de la capture n'indique une compromission de ce site. Il ne figure pas
parmi les indicateurs.

### Commande et contrôle

| Caractéristique | Observation |
| --- | --- |
| Domaine | `vadusa.xyz`, résolu une seule fois sur la période |
| Hôte | 45.131.214.85, hébergeur MHost LLC, Allemagne, selon consultation de réputation |
| Port | 443 |
| Protocole effectif | HTTP en clair |
| Ressource | `POST /fakeurl.htm` |
| Rythme | Environ une requête par minute |
| Premier et dernier contact | 19:55:51 et 00:16:28 |
| Volume total | 550 paquets, 96 Ko sur plus de quatre heures |

Contrôle de cohérence : 550 paquets sur 261 minutes à raison d'une requête par minute
représentent environ deux paquets par échange, soit une requête et sa réponse sur une
connexion maintenue. Les relevés sont cohérents entre eux.

Le volume moyen, de l'ordre de 22 Ko par heure, correspond à un maintien de session et à
des échanges de commandes. Aucune exfiltration de volume significatif n'a été observée
sur la période couverte. L'implant était actif à la fin de la capture.

Le transport de HTTP en clair sur le port 443 et la ressource `/fakeurl.htm` sont
identiques à ceux observés dans l'analyse du 26 novembre 2024, portant sur une campagne
distincte quinze mois plus tôt, avec une adresse et un domaine différents.

> Les adresses et les domaines changent d'une campagne à l'autre. Les artefacts propres à
> l'outil persistent. C'est à ce niveau qu'une détection conserve sa valeur dans la durée.

## Indicateurs de compromission

Export exploitable : `iocs.csv`.

| Valeur | Rôle | Qualification |
| --- | --- | --- |
| `vadusa.xyz` | Passerelle NetSupport configurée dans l'implant | Malveillant |
| 45.131.214.85 | Serveur de commande et contrôle | Malveillant |
| `POST /fakeurl.htm` en HTTP clair sur port 443 | Artefact de l'outil | Comportemental, stable entre campagnes |

## Empreintes de fichiers

Aucun binaire n'a été extrait. L'implant était installé avant le début de la capture et
n'a pas transité dans le trafic observé.

## Recommandations

| Priorité | Mesure |
| --- | --- |
| Immédiate | Isolement du poste, réinstallation. |
| Immédiate | Réinitialisation du mot de passe du compte concerné et révocation des sessions. |
| Immédiate | Recherche rétroactive des indicateurs sur l'ensemble du parc, sur une période étendue en amont de l'alerte, la date d'infection étant inconnue. |
| À court terme | Blocage du domaine et de l'adresse de contrôle en sortie. |
| À court terme | Examen du poste pour identifier le vecteur initial et le mécanisme de démarrage automatique, dont l'existence est établie par le trafic. |
| Structurelle | Liste des outils d'administration à distance autorisés, alerte sur tout autre outil de ce type. |

## Limites de l'analyse

| Point | Limite |
| --- | --- |
| Vecteur initial | Absent de la capture. L'infection est antérieure à la collecte. |
| Date d'infection | Inconnue. La compromission peut dater de plusieurs jours. |
| Lien avec le site institutionnel | Écarté faute de mécanisme. Hypothèse d'ouverture de session corroborée. |
| Mécanisme de persistance | Existence établie, nature non déterminable depuis le réseau. |
| Réputation de l'adresse | Issue d'une consultation externe, susceptible d'évoluer. |

## Référence

Analyse de référence publiée par l'éditeur de la capture. Les réponses aux questions
posées ont été établies en autonomie avant consultation. L'analyse de référence comporte
deux incohérences internes, sur l'adresse du serveur de contrôle et sur le nom de
l'utilisateur dans une légende.
