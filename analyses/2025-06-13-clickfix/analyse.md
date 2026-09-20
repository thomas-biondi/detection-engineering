# Rapport d'incident. Compromission par technique ClickFix et déploiement d'un interpréteur portable

Source de la capture : exercice public malware-traffic-analysis.net du 13 juin 2025.
Capture non versionnée, disponible auprès de l'éditeur.

Tous les horodatages de ce document sont exprimés en UTC.

## Résumé exécutif

Le vendredi 13 juin 2025 vers 15h35 UTC, un poste de travail Windows du réseau a été
compromis. L'utilisateur a consulté un site légitime dont les pages étaient porteuses
d'un script injecté. Ce script a affiché une fausse page de vérification humaine invitant
l'utilisateur à exécuter lui même une commande présentée comme une étape de validation.

Cette méthode, connue sous le nom de ClickFix, ne repose sur aucune vulnérabilité
technique et ne fait transiter aucune pièce jointe. L'utilisateur est l'exécutant de la
commande initiale.

L'attaquant a ensuite déployé sur le poste un interpréteur PHP officiel, téléchargé
depuis le site de l'éditeur, afin d'exécuter ses propres programmes au moyen d'un
composant légitime et signé. Un mécanisme de démarrage automatique a été installé, et le
poste a établi une communication périodique avec une infrastructure distante. Des
informations de configuration du système ont été transmises à un domaine imitant celui
d'un éditeur connu.

L'attaquant dispose d'une exécution de code persistante sur le poste avec les droits de
l'utilisateur. Le trafic de commande et contrôle était actif à la fin de la période
observée.

## Cadrage

| Élément | Valeur |
| --- | --- |
| Volume de la capture | Environ 48 000 paquets, 42 Mo |
| Fenêtre couverte | 15:33:55 à 16:08:28 UTC, soit 35 minutes |

## Détails de la victime

| Élément | Valeur | Source |
| --- | --- | --- |
| Adresse IP | 10.6.13.133 | Inventaire des points de terminaison |
| Adresse MAC | 24:77:03:ac:97:df | Couche Ethernet |
| Nom d'hôte | DESKTOP-5AVE44C | Séquence d'attribution DHCP |
| Compte utilisateur | rgaines | Principal de la requête d'authentification Kerberos |

## Chronologie

| Heure UTC | Événement | Écart |
| --- | --- | --- |
| 15:33:55 | Début de la capture | |
| Avant 15:35:48 | Consultation de `truglomedspa.com`, chargement du script injecté `5h7o.js` | |
| 15:35:48 | Requête GET vers `event-time-microsoft.org/zh0GPFZdKt`, récupération du script de premier étage | T0 |
| 15:35:58 | Requête POST vers `eventdata-microsoft.live/NV4RgNeU` | T0 + 10 s |
| Période suivante | Téléchargement d'un environnement PHP depuis `windows.php.net`, environ 34 Mo | |
| 15:37:25 | Début des requêtes POST périodiques à chemin variable | T0 + 1 min 37 s |
| 16:08:28 | Fin de la capture, trafic de commande et contrôle toujours actif | T0 + 33 min |

## Chaîne d'infection

### Vecteur d'accès initial

Le site `truglomedspa.com` est un site légitime dont les pages étaient porteuses d'un
script injecté, `5h7o.js`. Le script affiche une fausse page de vérification humaine.

Le procédé, désigné sous le nom de ClickFix, consiste à présenter à l'utilisateur une
séquence de touches à reproduire, sous couvert d'une étape de validation. La séquence
copie une commande dans le presse papier et la fait exécuter par l'utilisateur au moyen
de la boîte de dialogue d'exécution de Windows.

> Aucune pièce jointe ne transite, aucune vulnérabilité n'est exploitée, et le poste
> n'exécute que ce que son utilisateur a lui même saisi. Les contrôles portant sur les
> fichiers entrants sont sans effet sur ce vecteur.

Conséquence en matière de détection. La chaîne ne devient observable qu'à partir de la
première requête sortante du script de premier étage. En amont, seule la consultation du
site compromis figure dans le trafic, sans caractéristique distinctive.

### Premier étage

La ressource `/zh0GPFZdKt`, récupérée en HTTP clair, est un script PowerShell obfusqué
par encodage en base64. Après décodage, il exécute une commande de recensement système et
transmet le résultat au domaine `eventdata-microsoft.live`.

Ce domaine repose sur une construction imitant celle d'un éditeur connu. Le nom n'est
enregistré par aucune entité légitime associée à cet éditeur.

### Déploiement d'un interpréteur portable

Un volume d'environ 34 Mo a été transféré depuis 83.137.149.15. Le nom de serveur
présenté dans la session TLS correspond à `windows.php.net`, site officiel de
distribution de l'interpréteur PHP pour Windows.

Le fichier téléchargé n'est pas malveillant. Il s'agit d'une distribution officielle,
déployée dans un répertoire du profil utilisateur, et employée ensuite pour exécuter les
programmes de l'attaquant.

> Un volume élevé n'est pas un indicateur. Ce transfert provient d'un éditeur légitime,
> vers une destination légitime, et n'aurait déclenché aucun contrôle de réputation. Ce
> qui le qualifie n'est ni sa taille ni son origine, mais le fait qu'un poste bureautique
> n'a aucune raison de télécharger un environnement d'exécution.

La technique relève de l'emploi de composants légitimes pour l'exécution de code. Elle
prive la détection fondée sur la signature ou la réputation de tout point d'accroche.

### Persistance

Un raccourci `ycBFVIbLl.lnk` a été créé dans le répertoire de démarrage du profil
utilisateur. Il déclenche l'exécution de `c2.exe` en s'appuyant sur l'environnement
déployé dans `AppData\Roaming\php`.

Le mécanisme ne requiert aucun privilège d'administration et ne modifie ni le registre ni
les services. Il est identique dans son principe à celui observé lors d'une analyse
précédente du dépôt.

### Commande et contrôle

| Étape | Domaine | Adresse observée |
| --- | --- | --- |
| Récupération du premier étage | `event-time-microsoft.org` | 104.21.24.186 |
| Premier contact | `eventdata-microsoft.live` | 104.21.112.1 |
| Sollicitations périodiques | `event-datamicrosoft.live` | 104.21.16.1 |
| Sollicitations périodiques | `varying-rentals-calgary-predict.trycloudflare.com` | 104.16.230.132 |

| Caractéristique | Observation |
| --- | --- |
| Méthode | POST |
| Chemins | Variables, d'apparence aléatoire, par exemple `/YSEpJj/CPZldd...` |
| Début | 15:37:25 |
| Régime | Requêtes périodiques jusqu'à la fin de la capture |

Trois domaines distincts reposent sur une construction imitant celle d'un éditeur connu,
avec des variations mineures entre eux. L'emploi de plusieurs domaines pour des étapes
différentes de la même chaîne limite la portée d'un blocage unitaire.

La dernière destination est un sous domaine d'un service de tunnel éphémère gratuit. Ce
service expose un hôte local sur Internet derrière un nom généré automatiquement, sans
enregistrement de domaine ni certificat à obtenir.

> Un sous domaine de service de tunnel éphémère dans un environnement d'entreprise
> constitue une anomalie à très faible taux de faux positifs. Aucun usage professionnel
> courant ne repose sur ces noms générés.

La variabilité des chemins constitue une contre mesure aux détections fondées sur une
ressource fixe. Le motif exploitable n'est donc pas le chemin lui même, mais la
périodicité des requêtes et la structure des chemins.

### Nature des adresses observées

Les adresses associées à ces domaines appartiennent à un réseau de distribution de
contenu. Elles ne désignent pas le serveur de l'attaquant mais un intermédiaire mutualisé
placé devant lui.

> Une adresse appartenant à un réseau de distribution de contenu est mutualisée entre un
> très grand nombre de sites légitimes. Elle se consigne à titre d'observation, mais ne
> constitue pas un indicateur actionnable. Un blocage au niveau du pare feu sur une telle
> adresse interrompt l'accès à des services sans rapport avec l'incident.

L'indicateur actionnable est ici le nom de domaine, et non l'adresse.

## Indicateurs de compromission

Export exploitable : `iocs.csv`.

| Valeur | Rôle | Qualification |
| --- | --- | --- |
| `event-time-microsoft.org` | Distribution du script de premier étage | Malveillant |
| `eventdata-microsoft.live` | Premier contact et réception du recensement système | Malveillant |
| `event-datamicrosoft.live` | Sollicitations périodiques | Malveillant |
| `varying-rentals-calgary-predict.trycloudflare.com` | Sollicitations périodiques via tunnel éphémère | Malveillant |
| 104.21.24.186, 104.21.112.1, 104.21.16.1, 104.16.230.132 | Adresses du réseau de distribution de contenu | Observées, non actionnables |
| `truglomedspa.com` | Site légitime porteur d'un script injecté | Compromis, non malveillant |
| `5h7o.js` | Script injecté affichant la fausse vérification | Malveillant |
| `/zh0GPFZdKt` | Script de premier étage | Malveillant |
| `ycBFVIbLl.lnk` | Raccourci de démarrage | Persistance |
| `c2.exe`, `AppData\Roaming\php` | Programme et environnement d'exécution | Persistance |
| `windows.php.net`, 83.137.149.15 | Distribution officielle de l'interpréteur | Légitime, détourné |

Le site de l'éditeur PHP ne constitue pas un indicateur de compromission et ne doit pas
être traité comme tel. L'élément pertinent en détection est le téléchargement d'un
environnement d'exécution par un poste bureautique, quelle qu'en soit l'origine.

## Empreintes de fichiers

| Artefact | SHA256 |
| --- | --- |
| Script de premier étage, ressource `/zh0GPFZdKt` | `d13971294a836862ffaf212c6f6aa8bea3818aab28120ec3b9bffa181ce0d429` |

Le fichier a transité en HTTP clair et a été extrait de la capture au moyen de la
fonction d'export d'objets. Seule l'empreinte est conservée, le fichier n'est pas
versionné.

> Une empreinte est l'indicateur le plus précis et le moins durable. Un octet modifié la
> rend caduque, et une charge générée pour chaque victime en produit une différente à
> chaque infection. Elle se consigne, mais la détection ne peut pas reposer sur elle
> seule.

## Recommandations

| Priorité | Mesure |
| --- | --- |
| Immédiate | Isolement du poste, réinstallation. |
| Immédiate | Réinitialisation du mot de passe du compte concerné. |
| Immédiate | Recherche rétroactive des indicateurs sur l'ensemble du parc. |
| À court terme | Blocage des quatre domaines en sortie, au niveau de la résolution de noms ou du proxy. Ne pas bloquer les adresses, qui relèvent d'un réseau de distribution mutualisé. |
| À court terme | Notification au propriétaire du site compromis. |
| Structurelle | Alerte sur toute résolution d'un sous domaine de service de tunnel éphémère. |
| Structurelle | Journalisation des blocs de script PowerShell, qui capture le contenu après désobfuscation. |
| Structurelle | Détection du téléchargement d'environnements d'exécution par des postes bureautiques. |
| Structurelle | Sensibilisation des utilisateurs à la technique ClickFix. Aucun contrôle technique portant sur les fichiers entrants n'intercepte ce vecteur. |

## Limites de l'analyse

| Point | Limite |
| --- | --- |
| Périmètre temporel | 35 minutes. L'activité était en cours à la fin de la capture. |
| Contenu du premier étage | Décodé et interprété, sans exécution. Le comportement complet du programme déployé n'est pas établi depuis le réseau. |
| Action de l'utilisateur | La saisie de la commande est déduite du procédé employé par le script, et non observée. |

## Référence

Analyse de référence publiée par l'éditeur de la capture. Une partie des constats a été
établie en autonomie, une autre avec assistance. La répartition est consignée dans le
journal de session.
