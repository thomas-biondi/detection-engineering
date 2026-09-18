# Méthodologie de triage d'une capture réseau

Document de référence. Décrit la séquence appliquée à toute capture inconnue, avant
toute recherche ciblée.

## Principe

Une capture ne s'explore pas à la recherche de l'anomalie. L'anomalie ne se distingue
que par rapport à un état normal, lequel doit être établi en premier. La séquence
ci-dessous construit d'abord une carte du terrain, identifie les acteurs, fixe le
référentiel temporel, et ne descend au niveau du paquet qu'en dernier.

> Une observation isolée n'a pas de valeur. Une observation rapportée à un contexte
> connu en a une.

## Séquence

### Temps 1. Contexte fourni

Relever avant toute commande les éléments de cadrage disponibles : plage du segment,
domaine Active Directory, adresse du contrôleur de domaine, passerelle, adresse de
diffusion. Ces éléments déterminent ce qui relève du fonctionnement normal et ce qui
constitue un écart.

### Temps 2. Métadonnées du fichier

Un fichier de capture comporte deux couches d'information dont le coût de lecture
diffère.

| Couche | Contenu | Coût de lecture |
| --- | --- | --- |
| Métadonnées | Nombre de paquets, bornes temporelles, débit moyen | Immédiat |
| Contenu | Octets des trames, à dissocier par dissecteur | Proportionnel au volume |

```bash
capinfos -a -e -c -x capture.pcap
```

| Option | Rôle |
| --- | --- |
| `-c` | Nombre de paquets |
| `-a` | Horodatage du premier paquet |
| `-e` | Horodatage du dernier paquet |
| `-x` | Débit moyen |

La volumétrie détermine la stratégie d'analyse.

| Volume | Approche |
| --- | --- |
| Inférieur à quelques centaines de milliers de paquets | Exploration visuelle sous Wireshark |
| Au delà | Filtrage préalable en ligne de commande, `tshark` et Zeek |

Le premier horodatage constitue le référentiel temporel de tous les événements
ultérieurs.

### Temps 3. Inventaire et identification

Objectif : déterminer quelle machine est concernée, puis établir son identité complète.

`Statistics` puis `Endpoints`, onglet IPv4, tri par nombre de paquets décroissant.

Contrôle à effectuer systématiquement : comparer le total de la machine la plus active
au nombre total de paquets de la capture. Une égalité indique que la capture a été
filtrée en amont sur cet hôte et non collectée sur l'ensemble du segment.

Une adresse IP ne suffit pas à un rapport d'incident, elle est révocable au bail
suivant. Trois compléments sont à extraire.

| Élément | Source | Filtre |
| --- | --- | --- |
| Adresse MAC | Couche Ethernet d'un paquet émis par l'hôte | Aucun |
| Nom d'hôte | Option 12 du bail DHCP, à défaut enregistrement NetBIOS | `dhcp`, `nbns` |
| Compte utilisateur | Principal de la requête d'authentification Kerberos | `kerberos.CNameString` |

Sur le filtre Kerberos, les valeurs terminées par le caractère `$` désignent des comptes
machine. La valeur sans ce suffixe désigne le compte utilisateur.

> L'adresse MAC n'est exploitable que si la capture a été réalisée sur le même segment
> que la machine observée. Au franchissement du premier routeur, l'adresse source est
> réécrite.

> Le nom du principal Kerberos circule en clair dans la requête initiale, avant toute
> préauthentification. Cette propriété du protocole est exploitable en analyse, et
> constitue par ailleurs la base des attaques de type AS-REP roasting.

### Temps 4. Chronologie

Reconstitution ordonnée : point d'entrée, téléchargement, exécution, persistance,
communication de commande et contrôle.

## Techniques transverses

### Mise en colonne d'un champ

Clic droit sur un champ dans le panneau de détail, puis `Appliquer comme colonne`. Le
champ est alimenté pour tous les paquets qui le contiennent.

> Dès qu'une valeur recherchée varie sur un grand nombre de paquets, la mise en colonne
> remplace l'ouverture paquet par paquet.

Équivalent en ligne de commande, applicable à tout champ :

```bash
tshark -r capture.pcap -Y "<filtre>" -T fields -e <champ> | sort -u
```

| Option | Rôle |
| --- | --- |
| `-r` | Lecture depuis un fichier |
| `-Y` | Filtre d'affichage, syntaxe identique à celle de Wireshark |
| `-T fields -e` | Extraction du champ désigné au lieu du résumé de paquet |

### Priorité au trafic non chiffré

Le trafic en clair documente le reste de la chaîne. Il est à rechercher en premier.

```
http.request
```

### Fenêtres sur le trafic chiffré

Deux éléments d'une session TLS circulent en clair avant l'établissement du chiffrement.

| Élément | Filtre | Apport |
| --- | --- | --- |
| Nom de serveur demandé | `tls.handshake.extensions_server_name` | Destination réelle d'une session chiffrée |
| Certificat serveur | `tls.handshake.type == 11` | Émetteur, sujet, validité, caractère auto-signé |

### Pivot et inventaire

Deux mouvements complémentaires, dont l'un ne remplace pas l'autre.

| Mouvement | Principe | Portée |
| --- | --- | --- |
| Pivot | Partir d'un indicateur connu pour en obtenir un autre, par exemple `dns.a == <ip suspecte>` | Confirme et étend une piste existante |
| Inventaire | Lire la liste complète et dédoublonnée des domaines interrogés et des noms de serveur TLS | Fait apparaître ce qui n'était pas soupçonné |

> Le pivot est borné par ce que l'analyste connaît déjà. Les éléments d'une chaîne
> d'infection hébergés derrière un service de distribution de contenu présentent des
> adresses IP banales et ne sont atteints que par l'inventaire.

### Exploitation des sorties structurées

Suricata en mode hors ligne produit un journal d'événements structuré couvrant les flux,
le DNS, le HTTP et le TLS, indépendamment de toute alerte.

```bash
jq -r 'select(.event_type=="tls") | .tls.sni' eve.json | sort -u
```

> Un moteur de signature teste la présence d'un motif. Il ne sait pas constater l'absence
> d'un champ, ni la régularité temporelle d'une série d'événements. Ces deux classes
> d'anomalie relèvent d'une requête sur données structurées, donc du SIEM.

## Documentation de l'analyse

Le journal d'analyse est ouvert avant la première commande et alimenté au fil de l'eau,
hypothèses et pistes écartées comprises. Une analyse d'incident se restitue, et une
reconstitution a posteriori ne conserve pas le cheminement.

Convention d'horodatage : UTC, mention explicite en tête de document. Les outils
n'appliquent pas tous le même réglage d'affichage par défaut, un écart entre deux
sorties est à vérifier avant publication.
