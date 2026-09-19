# Rapport d'incident. Infection par outil d'administration à distance détourné

Source de la capture : exercice public malware-traffic-analysis.net du 26 novembre 2024.
Capture et fichier d'alertes non versionnés, disponibles auprès de l'éditeur.

Tous les horodatages de ce document sont exprimés en UTC.

## Résumé exécutif

Le mardi 26 novembre 2024 vers 04h50 UTC, un poste de travail Windows du réseau a été
placé sous le contrôle d'un tiers au moyen d'un outil d'administration à distance
détourné, identifié comme NetSupport RAT.

La chaîne a débuté par la consultation d'un site légitime dont les pages ont été
compromises par l'injection d'un script tiers. Cette consultation a conduit, sans action
particulière de l'utilisateur, à une page proposant une fausse mise à jour de
navigateur. Trente-quatre secondes se sont écoulées entre le début de la chaîne et
l'établissement du contrôle à distance.

L'attaquant dispose d'un accès interactif au poste avec les droits de l'utilisateur
connecté : lecture et exfiltration des fichiers accessibles, exécution de commandes,
tentative de progression vers d'autres ressources du domaine. Compte tenu de l'activité
de l'établissement, une exposition de données de recherche doit être considérée comme
possible.

Le trafic de commande et contrôle était toujours actif à la fin de la période observée.
L'incident n'était donc pas terminé au moment de la collecte.

## Cadrage

| Élément | Valeur |
| --- | --- |
| Segment | 10.11.26.0/24 |
| Passerelle | 10.11.26.1 |
| Contrôleur de domaine et serveur DNS | 10.11.26.3, NEMOTODES-DC |
| Domaine Active Directory | NEMOTODES, nemotodes.health |
| Volume de la capture | Environ 26 000 paquets |
| Fenêtre couverte | 04:49:38 à 05:43:58 UTC, soit 54 minutes |

La machine concernée apparaît dans la quasi-totalité des paquets. La collecte a été
filtrée en amont sur cet hôte.

## Détails de la victime

| Élément | Valeur | Source |
| --- | --- | --- |
| Adresse IP | 10.11.26.183 | Inventaire des points de terminaison |
| Adresse MAC | d0:57:7b:ce:fc:8b | Couche Ethernet |
| Nom d'hôte | DESKTOP-B8TQK49 | Résolution de nom |
| Compte utilisateur | oboomwald | Principal de la requête d'authentification Kerberos |
| Nom complet | Oliver Q. Boomwald | Attribut `givenName` observé dans le trafic LDAP vers le contrôleur de domaine |

## Chronologie

| Heure UTC | Événement | Écart |
| --- | --- | --- |
| 04:49:38 | Début de la capture | |
| 04:50:11 | Résolution de `classicgrand.com` vers 213.246.109.5 | T0 |
| 04:50:14 | Résolution de `modandcrackedapk.com` vers 193.42.38.139 | T0 + 3 s |
| 04:50:15 et 04:50:40 | Résolutions complémentaires du même domaine | |
| 04:50:45 | Première requête POST vers 194.180.191.64, ressource `/fakeurl.htm` | T0 + 34 s |
| Période suivante | Sollicitations périodiques vers le même hôte, environ 50 occurrences | |
| 05:43:58 | Fin de la capture, trafic de commande et contrôle toujours actif | T0 + 53 min |

## Chaîne d'infection

### Point de départ

Le site `classicgrand.com` est un site légitime. Aucune caractéristique propre observable
dans la capture ne le distingue d'un site ordinaire : certificat valide, hébergement
conventionnel, volume de trafic cohérent avec le chargement d'une page.

Sa qualification repose exclusivement sur sa position dans la séquence. Trois secondes
séparent sa résolution de celle du domaine de distribution, intervalle incompatible avec
une saisie manuelle par l'utilisateur.

> Un indicateur ne se qualifie pas toujours par ses caractéristiques propres. Il se
> qualifie parfois uniquement par sa position dans une séquence temporelle.

Limite d'observation à noter. Le trafic étant chiffré, l'en-tête `Referer` n'est pas
accessible. Le lien entre les deux domaines est établi par corrélation temporelle et non
par une observation directe de la redirection.

### Distribution

Le domaine `modandcrackedapk.com` sert une page de fausse mise à jour de navigateur. Le
volume échangé avec cet hôte, de l'ordre de 11 Mo, est cohérent avec le téléchargement
d'un fichier.

L'intervalle de 31 secondes entre le contact avec ce domaine et l'établissement du
contrôle à distance correspond au téléchargement, à une action de l'utilisateur et à
l'installation. Cette interprétation constitue une hypothèse : le réseau ne permet pas
d'observer l'action de l'utilisateur.

### Identification de la famille

L'inventaire des objets HTTP de la capture comporte une sollicitation de
`geo.netsupportsoftware.com`. Le client NetSupport interroge le service de
géolocalisation de son éditeur à son démarrage. Cette observation établit la famille de
l'outil employé indépendamment de toute signature.

NetSupport Manager est un produit commercial légitime d'administration à distance. Son
détournement présente les mêmes caractéristiques que celui d'autres outils du même type :
binaires signés, trafic sortant vers une infrastructure d'apparence légitime, absence de
déclenchement sur la réputation du fichier.

### Commande et contrôle

| Caractéristique | Observation |
| --- | --- |
| Hôte | 194.180.191.64 |
| Port | 443 |
| Protocole effectif | HTTP en clair |
| Méthode | POST vers `/fakeurl.htm` |
| Type de contenu | `application/x-www-form-urlencoded` |
| Volumes observés | Environ 50 requêtes de 36 octets, quelques requêtes de 22 à 250 octets |
| Autres ressources sollicitées | `loca.asp`, `ProcessMAU.txt` |

L'emploi de HTTP en clair sur le port 443 constitue une anomalie exploitable en
détection. Un port ne détermine pas un protocole, il le suggère. Le choix du port 443
pour transporter du texte clair vise un filtrage autorisant ce port sans l'inspecter.

> Le protocole effectif d'une session se constate, il ne se déduit pas du numéro de port.
> L'écart entre les deux est en soi un indicateur.

Les volumes observés ne permettent pas de conclure à une exfiltration. Les requêtes de
36 octets répétées correspondent à un maintien de session. Les requêtes de taille
variable correspondent à des échanges de commandes ou à des remontées d'état. Aucune
exfiltration de volume significatif n'a été observée sur la période couverte par la
capture.

## Indicateurs de compromission

Export exploitable : `iocs.csv`.

| Valeur | Rôle | Qualification |
| --- | --- | --- |
| `194.180.191.64` | Commande et contrôle | Malveillant |
| `modandcrackedapk.com`, 193.42.38.139 | Distribution de la fausse mise à jour | Malveillant |
| `classicgrand.com`, 213.246.109.5 | Site légitime porteur d'un script injecté | Compromis, non malveillant |
| `POST /fakeurl.htm` en HTTP clair sur port 443 | Motif de commande et contrôle | Comportemental |

La distinction entre hôte malveillant et hôte compromis conditionne la réponse. Le
blocage permanent d'un site légitime au motif d'une compromission temporaire n'est pas
une mesure appropriée. La conduite retenue est la notification du propriétaire et la
surveillance.

## Empreintes de fichiers

Aucun binaire n'a pu être extrait de la capture. Le fichier de fausse mise à jour a
transité sur une session TLS vers `modandcrackedapk.com` et n'est pas récupérable depuis
le trafic. L'inventaire des objets HTTP ne comporte aucun exécutable ni script.

> Une section vide et justifiée constitue un résultat. L'absence de preuve extractible
> est une information à consigner, non une lacune à masquer.

## Recommandations

| Priorité | Mesure |
| --- | --- |
| Immédiate | Isolement du poste, réinstallation. L'outil déployé permet une action interactive, la désinfection ciblée n'offre pas de garantie. |
| Immédiate | Réinitialisation du mot de passe du compte concerné et révocation des sessions actives. |
| Immédiate | Recherche rétroactive des trois indicateurs sur l'ensemble du parc. Rien n'établit que ce poste soit le seul concerné. |
| À court terme | Blocage de l'hôte de commande et contrôle et du domaine de distribution en sortie. |
| À court terme | Notification au propriétaire du site compromis. |
| Structurelle | Liste blanche des outils d'administration à distance autorisés, avec alerte sur tout autre outil de ce type. |

## Limites de l'analyse

| Point | Limite |
| --- | --- |
| Périmètre temporel | 54 minutes. L'activité était en cours à la fin de la capture, la suite n'est pas documentée. |
| Périmètre réseau | Capture filtrée sur un seul hôte. Une progression vers d'autres machines du segment ne serait pas visible. |
| Lien entre domaines | Établi par corrélation temporelle, en l'absence d'en-tête accessible sur session chiffrée. |
| Vecteur d'exécution | Hypothèse d'une action de l'utilisateur sur la page de fausse mise à jour, non observable depuis le réseau. |

## Référence

Analyse de référence publiée par l'éditeur de la capture. Les constats du présent
document ont été établis avant consultation de cette source, puis confrontés à elle.
