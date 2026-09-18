# Analyse d'incident. Chaîne d'infection par faux site logiciel

Source de la capture : exercice public malware-traffic-analysis.net du 22 janvier 2025.
Capture non versionnée, disponible auprès de l'éditeur.

Tous les horodatages de ce document sont exprimés en UTC.

## Cadrage

| Élément | Valeur |
| --- | --- |
| Segment | 10.1.17.0/24 |
| Passerelle | 10.1.17.1 |
| Contrôleur de domaine et serveur DNS | 10.1.17.2, WIN-GSH54QLW48D |
| Domaine Active Directory | BLUEMOONTUESDAY |
| Volume de la capture | 39 427 paquets, 26 Mo |
| Fenêtre couverte | 19:44:56 à 20:38:18 UTC, soit 53 minutes |

La machine observée apparaît dans la totalité des paquets de la capture. La collecte a
donc été filtrée en amont sur cet hôte et ne couvre pas l'ensemble du segment.

## Identification de la machine concernée

| Élément | Valeur | Source |
| --- | --- | --- |
| Adresse IP | 10.1.17.215 | Inventaire des points de terminaison |
| Adresse MAC | 00:d0:b7:26:4a:74 | Couche Ethernet |
| Nom d'hôte | DESKTOP-L8C5GSJ | Bail DHCP, confirmé par enregistrement NetBIOS embarqué dans une requête Kerberos |
| Compte utilisateur | shutchenson | Principal de la requête d'authentification Kerberos |

## Résolution du référentiel temporel

Un écart d'une heure a été constaté entre l'affichage de Wireshark et celui de
`capinfos` et Suricata. L'en tête `Date` des réponses HTTP, émis par le serveur en temps
universel, a servi de référence pour trancher : les valeurs coïncident avec l'affichage
de Wireshark, les deux autres outils appliquaient le fuseau local du poste d'analyse.

> Lorsque deux outils divergent sur l'horodatage, un champ de protocole horodaté par un
> tiers constitue une référence de contrôle. L'en tête `Date` d'une réponse HTTP est
> exprimé en temps universel.

## Chronologie

| Heure UTC | Événement |
| --- | --- |
| 19:44:56 | Premier paquet de la capture |
| 19:45:35 | Résolution DNS de `authenticatoor.org` vers 82.221.136.26 |
| 19:45:56 | Requête HTTP vers 5.252.153.241, ressource `/api/file/get-file/264872`, réponse de 417 octets |
| 19:45:58 | Requête HTTP vers la même adresse, ressource `/api/file/get-file/29842.ps1`, réponse de 1 512 octets |
| 19:45:58 | Début des requêtes répétées vers `/1517096937`, intervalle de 5 secondes, réponses 404 |
| 19:47:01 | Première réponse 200 sur `/1517096937`, contenu de 2 761 octets constituant un script d'installation |
| 19:47:01 | Téléchargement de `TeamViewer.exe`, 4 380 968 octets |
| 19:47:01 et suivantes | Téléchargement de `Teamviewer_Resource_fr.dll`, `TV.dll`, `pas.ps1` |
| 19:47:01 et suivantes | Écriture dans `C:\ProgramData\huo`, création d'un raccourci de démarrage |
| 19:55:07 | Résolution DNS puis trafic vers l'infrastructure TeamViewer, en tête d'agent utilisateur DynGate |
| 19:59:46 | Première session TLS vers 45.125.66.32 port 2917, nom de serveur constitué de l'adresse IP |
| 20:00:14 | Session TLS vers 45.125.66.252 port 443, extension de nom de serveur absente |
| 20:28:22 | Dernière session TLS observée vers 45.125.66.32 |
| 20:38:18 | Dernier paquet de la capture |

## Chaîne d'infection

### Accès initial

Publicité malveillante sur moteur de recherche, redirection en cascade jusqu'à une page
imitant un éditeur logiciel. Le domaine final, `authenticatoor.org`, repose sur une
substitution de caractère par rapport au nom légitime attendu.

La chaîne de redirection complète est visible dans l'inventaire des noms de serveur TLS
de la capture.

### Exécution

Le fichier initial est un fichier de script de 72 octets contenant un unique appel
`GetObject` assorti du moniker `scriptlet:`, exécuté par l'interpréteur de script
Windows. Le code effectif est récupéré à distance et exécuté sans écriture sur le
disque.

> Le fichier téléchargé par l'utilisateur ne contient pas de code malveillant au sens
> classique. Il ne contient qu'une référence. La détection fondée sur l'analyse du
> fichier seul est inopérante sur ce procédé.

### Second étage

Charge PowerShell obfusquée par deux procédés cumulés : fragmentation du nom de la
méthode de décodage et pollution de la chaîne encodée. Une fois décodée, la charge
réalise trois opérations.

| Opération | Détail |
| --- | --- |
| Construction d'un identifiant | Numéro de série du volume système converti en décimal |
| Boucle de sollicitation | Requête vers l'adresse du serveur suffixée de cet identifiant, temporisation de 5 secondes |
| Exécution du retour | Le contenu reçu est passé directement à l'interprétation, sans écriture sur disque |

L'identifiant observé dans cette capture est `1517096937`. Il correspond au chemin
sollicité de façon répétée, et explique la structure de l'URL de commande et contrôle.

> La temporisation observée dans le code correspond exactement à l'intervalle relevé
> dans les horodatages réseau. Une caractérisation du comportement d'un implant est
> réalisable à partir du seul trafic, sans accès au code.

> Une réponse 404 répétée à intervalle régulier ne traduit pas un défaut. Elle traduit
> une absence d'instruction en attente. Le passage à une réponse 200 marque la prise en
> main par l'opérateur.

### Persistance et accès distant

Le script reçu à 19:47:01 déploie les binaires d'un outil d'administration à distance
légitime dans `C:\ProgramData\huo`, puis crée un raccourci dans le répertoire de
démarrage du profil utilisateur. La machine se connecte ensuite à l'infrastructure
officielle de l'éditeur.

> L'indicateur n'est pas l'outil d'administration à distance lui même, dont les binaires
> sont signés et le trafic légitime. L'indicateur est l'origine des binaires, téléchargés
> en HTTP depuis un hôte tiers désigné par son adresse IP.

Le mécanisme de persistance retenu ne requiert aucun privilège d'administration et ne
modifie ni le registre ni les services.

### Commande et contrôle

| Adresse | Port | Protocole | Caractéristique |
| --- | --- | --- | --- |
| 5.252.153.241 | 80 | HTTP en clair | Distribution des charges puis sollicitation périodique |
| 45.125.66.32 | 2917 | TLS | Nom de serveur constitué de l'adresse IP, certificat auto signé, aucune résolution DNS préalable |
| 45.125.66.252 | 443 | TLS | Extension de nom de serveur absente, certificat auto signé, aucune résolution DNS préalable |

Les deux dernières adresses appartiennent au même bloc d'adressage.

L'adresse 82.221.136.26 héberge la page de distribution et n'assure pas de fonction de
commande et contrôle. La distinction conditionne la qualification de l'incident, la
sollicitation d'un serveur de commande établissant que la machine était pilotable.

## Indicateurs de compromission

| Type | Valeur |
| --- | --- |
| Domaine | authenticatoor.org |
| Adresse IP, distribution | 82.221.136.26 |
| Adresse IP, commande et contrôle | 5.252.153.241, 45.125.66.32, 45.125.66.252 |
| Port non standard | 2917 en TLS |
| Chemin HTTP | Chemin constitué d'un entier décimal sans extension, sollicité toutes les 5 secondes |
| Chemin disque | `C:\ProgramData\huo` |
| Persistance | Raccourci `TeamViewer.lnk` dans le répertoire de démarrage du profil |

## Couverture par le jeu de signatures public

Rejeu de la capture avec le jeu Emerging Threats Open.

| Catégorie | Constat |
| --- | --- |
| Signatures propres à la campagne | Présentes, publiées peu après la divulgation publique de la campagne |
| Réputation d'adresse | Les trois adresses de commande et contrôle figurent sur une liste de blocage publique |
| Comportements génériques | Requête de fichier PowerShell, commandes de téléchargement PowerShell, récupération d'un exécutable depuis un hôte désigné par son adresse, outil d'administration à distance |
| Non couvert | Régularité des sollicitations, nom de serveur TLS anormal, certificat auto signé, domaines de la chaîne de redirection |

> Les préfixes de catégorie constituent une hiérarchie de confiance. Une alerte de niveau
> informatif isolée n'établit rien. Un faisceau d'alertes informatives concentrées sur un
> même hôte dans un intervalle court constitue un signal. Le regroupement relève de
> l'analyste.

## Suites données

Une règle de détection locale a été écrite et validée à partir de ce dossier. Voir
`docs/regles-detection.md` et `regles/suricata/local.rules`.

## Référence

Analyse de référence publiée par l'éditeur de la capture et publication associée de
Unit 42. Les constats du présent document ont été établis avant consultation de ces
sources, puis confrontés à elles.
