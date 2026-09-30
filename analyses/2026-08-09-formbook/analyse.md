# Rapport d'incident. Infection par voleur d'informations FormBook

Source de la capture : exercice public malware-traffic-analysis.net du 9 août 2026.
Capture non versionnée, disponible auprès de l'éditeur. Aucune analyse de référence
n'était publiée au moment de la rédaction : les constats de ce document n'ont pas été
confrontés à une source externe.

Tous les horodatages de ce document sont exprimés en UTC.

## Résumé exécutif

Vers 02h13 UTC, des alertes de détection ont signalé les communications caractéristiques
de FormBook, un logiciel malveillant spécialisé dans le vol d'informations, depuis un
poste de travail Windows du réseau.

L'analyse du trafic identifie le poste et son utilisateur. Le logiciel s'est manifesté
un peu plus de cinq minutes après l'ouverture de session de l'utilisateur, puis a
communiqué de façon soutenue avec un ensemble de serveurs distants. Une partie de ces
serveurs sont des leurres, sollicités par le logiciel pour masquer ses véritables
destinations.

La manière dont le poste a été infecté n'est pas établie. Le scénario le plus probable
est une infection antérieure à la période observée, le logiciel se réactivant à
l'ouverture de session : aucune communication avec un service de messagerie ou un
hébergeur de fichiers n'a précédé sa première manifestation. Ce scénario n'est toutefois
pas démontré, l'ouverture d'un fichier déjà présent sur le poste ne produisant aucun
trafic.

Ce type de logiciel capture les informations saisies par l'utilisateur, notamment les
identifiants entrés dans les formulaires et les navigateurs. L'ensemble des comptes
utilisés depuis ce poste doit être considéré comme compromis.

## Cadrage

| Élément | Valeur |
| --- | --- |
| Segment | 172.16.8.0/24 |
| Passerelle | 172.16.8.1 |
| Contrôleur de domaine | 172.16.8.2, FIRSTTOLAST-DC |
| Domaine Active Directory | FIRSTTOLAST, firsttolast.tech |
| Alertes d'origine | ET MALWARE FormBook CnC Checkin (GET), six destinations entre 02:13 et 02:16 |
| Volume de la capture | `<à compléter, capinfos>` |
| Fenêtre couverte | `<à compléter, capinfos>` |

La capture contient le trafic de plusieurs hôtes internes, contrairement aux analyses
précédentes du dépôt.

## Détails de la victime

| Élément | Valeur | Source |
| --- | --- | --- |
| Adresse IP | 172.16.8.49 | Seul hôte interne en communication avec les destinations signalées, vérifié par filtrage |
| Adresse MAC | 00:12:f0:28:d4:34 | Couche Ethernet |
| Nom d'hôte | DESKTOP-5NLV63K | Résolution DNS inverse, corroborée par le compte machine Kerberos `desktop-5nlv63k$` |
| Compte utilisateur | rvance | Principal de la requête d'authentification Kerberos |
| Nom complet | Raymond Vance | `<source à préciser>` |

Le nom obtenu par résolution inverse est celui enregistré dans le DNS, susceptible d'être
obsolète en cas de réattribution d'adresse. Le compte machine présenté par le poste dans
ses requêtes Kerberos en constitue une corroboration indépendante.

Les hôtes 172.16.8.8 et 172.16.8.53 présentent un volume de trafic élevé. Ils sont
exclus : le filtrage sur les six destinations signalées ne fait apparaître aucune
communication de leur part.

## Chronologie

| Heure UTC | Événement |
| --- | --- |
| 02:08:12 | Requêtes DNS de localisation du contrôleur de domaine, authentification Kerberos du compte machine puis du compte `rvance`, ouverture de session |
| 02:08:12 à 02:13:28 | Aucune communication attribuable au logiciel malveillant. Sessions TLS limitées à des services système, aucun service de messagerie ni hébergeur de fichiers identifié |
| 02:13:28 | Début des requêtes HTTP à chemins aléatoires, par exemple `/ujvq/` et `/1rpm/` |
| 02:13 à 02:16 | Six alertes de détection sur six destinations distinctes |
| Minutes suivantes | Poursuite des alertes du même type |

## Analyse

### Intervalle entre l'ouverture de session et la première communication

Cinq minutes et seize secondes séparent l'ouverture de session de la première
communication du logiciel. Deux hypothèses sont compatibles avec cette observation.

| Hypothèse | Mécanisme | Élément discriminant dans la capture |
| --- | --- | --- |
| Infection antérieure | Programme installé, lancé à l'ouverture de session puis mis en attente avant toute communication | Absence de toute activité susceptible de livrer un fichier dans l'intervalle |
| Infection pendant la capture | Ouverture par l'utilisateur d'un fichier reçu, par exemple une pièce jointe | Sessions TLS vers un service de messagerie ou un hébergeur de fichiers juste avant 02:13:28 |

Résultat de l'examen de l'intervalle. Les sessions TLS observées entre 02:08:12 et
02:13:28 relèvent de services système. Aucune session vers un service de messagerie ou
un hébergeur de fichiers n'est identifiée.

Conclusion. La première hypothèse est corroborée. Elle n'est pas établie : l'ouverture
par l'utilisateur d'un fichier déjà présent sur le poste, reçu avant la période
observée, ne produirait aucun trafic et donnerait une capture identique.

> Une recherche infructueuse renforce une hypothèse sans l'établir. Elle écarte les
> variantes qui auraient laissé une trace, pas celles qui n'en laissent aucune.

La mise en attente prolongée avant toute communication est un comportement documenté de
plusieurs familles, destiné à dépasser la durée d'observation des environnements
d'analyse automatisée. Cette connaissance porte sur la famille et non sur la capture :
elle rend la première hypothèse plausible sans l'établir.

> Une conclusion établie dans un cas précédent ne constitue pas une conclusion par défaut.
> Le même raisonnement appliqué à une forme différente peut conduire à une conclusion
> erronée.

### Commande et contrôle et leurres

FormBook adresse des requêtes de même structure à un ensemble de domaines, dont la plupart
sont des leurres. Ce procédé vise à noyer les véritables serveurs de contrôle parmi des
destinations sans rapport avec l'attaquant.

Conséquence sur la lecture des alertes. La signature de détection repose sur la structure
des requêtes, identique pour les vrais serveurs et pour les leurres. Les six destinations
signalées ne sont donc pas toutes des serveurs malveillants.

> Une alerte de ce type qualifie l'hôte interne comme infecté. Elle ne qualifie pas la
> destination comme malveillante.

Deux destinations des alertes relèvent en outre d'un réseau de distribution de contenu,
172.64.155.76 et 172.67.162.153. Elles sont mutualisées et non actionnables.

Distinction entre leurres et serveurs de contrôle, établie par les réponses observées.

| Destination | Requêtes reçues | Réponse observée | Qualification |
| --- | --- | --- | --- |
| Leurres, par exemple 172.64.155.76 | GET à chemin aléatoire | `301 Moved Permanently` ou `404 Not Found` | Sites légitimes utilisés à leur insu |
| `www.grinswakebthu.info` | GET et POST | `<code de réponse aux POST à compléter>` | Serveur de contrôle |
| `www.taibeinan.cc` | GET et POST | `<code de réponse aux POST à compléter>` | Serveur de contrôle |

La réponse `301` est une redirection, non une erreur. Sur un site servi par un réseau de
distribution de contenu, elle correspond typiquement à la redirection vers la version
chiffrée du site, comportement ordinaire d'un site légitime. Elle confirme la nature de
leurre de la destination.

Les deux domaines de contrôle se distinguent par la réception des requêtes POST de
transmission de données, absentes vers les leurres.

Des requêtes vers `www.independent.ie`, site d'information légitime, figurent dans le
trafic. Si leur structure de chemin est identique à celle des autres requêtes du logiciel,
le site est une cible de leurre, utilisée sans avoir été compromise. Dans le cas
contraire, il s'agit de navigation de l'utilisateur. Dans les deux cas, il ne constitue
pas un indicateur de compromission.

## Indicateurs de compromission

Export exploitable : `iocs.csv`.

| Valeur | Rôle | Qualification |
| --- | --- | --- |
| `www.grinswakebthu.info` | Commande et contrôle | Malveillant, reçoit les requêtes POST |
| `www.taibeinan.cc` | Commande et contrôle | Malveillant, reçoit les requêtes POST |
| 172.64.155.76 | Leurre, réponses 301 ou 404, réseau de distribution de contenu | Non malveillant, non actionnable |
| 172.67.162.153 | Destination signalée, réseau de distribution de contenu | Non actionnable |
| 146.59.71.167, 38.182.168.246, 45.130.41.161, 121.54.163.148 | Destinations signalées par les alertes | Leurre ou contrôle, selon le domaine associé |
| Requêtes HTTP à chemin court aléatoire vers de multiples domaines | Comportement de l'implant | Comportemental |

## Empreintes de fichiers

Aucun binaire n'a été extrait. Aucun téléchargement en clair n'a été observé.

## Recommandations

| Priorité | Mesure |
| --- | --- |
| Immédiate | Isolement du poste, réinstallation. |
| Immédiate | Réinitialisation des mots de passe de tous les comptes utilisés depuis ce poste, révocation des sessions actives. |
| Immédiate | Examen de la messagerie et des fichiers récents de l'utilisateur, à la recherche du fichier d'origine. |
| Immédiate | Recherche rétroactive sur l'ensemble du parc de requêtes vers les deux domaines de contrôle, sur une période étendue en amont. |
| À court terme | Blocage des deux domaines de contrôle au niveau de la résolution de noms. |

Le blocage des destinations signalées n'est pas recommandé sans distinction préalable :
bloquer un leurre interrompt l'accès à un site légitime sans effet sur l'infection.

## Limites de l'analyse

| Point | Limite |
| --- | --- |
| Vecteur initial | Non établi. Infection antérieure corroborée, ouverture d'un fichier local non exclue. |
| Sessions vers des domaines Microsoft | Classées comme services système. Une synchronisation de messagerie emprunterait des domaines de même éditeur, à exclure par examen des noms de serveur. |
| Adresses des destinations signalées | Correspondance entre chaque adresse et son domaine non établie pour l'ensemble. |
| Référence externe | Aucune analyse de référence disponible pour confrontation. |
