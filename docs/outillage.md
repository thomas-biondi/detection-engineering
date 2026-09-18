# Environnement et outillage d'analyse

Document de référence. Décrit le poste d'analyse, les arbitrages de configuration et le
rôle de chaque outil.

## Poste d'analyse

Machine virtuelle dédiée sous Debian, hyperviseur VMware Workstation. Instantané
`base-propre` pris à l'issue de l'installation, restauré avant chaque nouvel exercice.

Distribution généraliste retenue plutôt qu'une distribution spécialisée. Les outils sont
installés à la demande, ce qui maintient un inventaire connu du poste et prolonge
l'environnement Debian déjà employé sur les projets d'infrastructure.

| Paramètre | Valeur |
| --- | --- |
| Mémoire | 4 Go |
| Processeurs virtuels | 2 |
| Disque | 50 Go, allocation dynamique |
| Dossiers partagés | Désactivés |
| Glisser déposer | Désactivé |

## Arbitrages d'isolement

Les outils d'intégration invité et le presse papier partagé constituent un canal de
communication entre l'invité et l'hôte. Ce canal réduit l'isolement en échange d'un
confort d'usage. L'arbitrage est fonction de ce qui sera exécuté, non de ce qui sera
téléchargé.

| Phase | Presse papier | Mode réseau | Justification |
| --- | --- | --- | --- |
| Analyse de capture, analyse statique | Bidirectionnel | NAT | Aucun code de l'échantillon n'est exécuté. Le NAT est requis pour l'installation des outils et la mise à jour des jeux de règles. |
| Exécution d'un échantillon | Désactivé | Hôte seul ou coupé, simulation de services | L'échantillon ne doit pas pouvoir atteindre son infrastructure depuis l'adresse publique de l'analyste. |

Les dossiers partagés et le glisser déposer restent désactivés dans les deux cas. Ils
constituent les vecteurs de transfert effectifs, et aucune phase d'analyse ne les
nécessite.

> Le risque associé à une capture n'est pas limité à son contenu. Wireshark embarque
> plusieurs centaines de dissecteurs traitant des données arbitraires, historiquement
> source de vulnérabilités. L'outil n'est jamais exécuté avec les privilèges
> d'administration.

## Manipulation des archives d'exercice

```bash
7z l archive.zip     # inventaire du contenu, sans extraction
7z x archive.zip
sha256sum *.pcap | tee hashes.txt
chmod 444 *.pcap
```

L'inventaire préalable évite d'écrire sur le disque des artefacts non attendus.
L'empreinte identifie l'élément de preuve de manière non ambiguë et permet d'établir
qu'il n'a pas été modifié pendant l'analyse. Le passage en lecture seule prévient une
altération accidentelle par un outil mal paramétré.

## Outils et rôles

| Outil | Rôle | Couche traitée |
| --- | --- | --- |
| `capinfos` | Métadonnées de la capture | En tête de fichier uniquement |
| Wireshark | Exploration interactive, dissection, suivi de flux | Contenu |
| `tshark` | Extraction de champs, traitement par lot | Contenu |
| Suricata | Application d'un jeu de signatures, production d'événements structurés | Contenu |
| `jq` | Interrogation des événements structurés | Sortie Suricata |
| `7z`, `sha256sum` | Manipulation des archives, intégrité des éléments de preuve | Fichier |

## Désobfuscation

Les charges obfusquées sont décodées dans un langage dépourvu de moyen d'exécuter le
résultat, jamais dans l'interpréteur ciblé par la charge.

Procédé observé et méthode appliquée :

| Procédé d'obfuscation | Traitement |
| --- | --- |
| Nom de méthode fragmenté par insertion de caractères, reconstitué par `.replace()` en chaîne | Appliquer les substitutions manuellement |
| Charge encodée en base64 polluée par des caractères parasites | Retirer les caractères parasites, décoder hors de l'interpréteur cible |

> Remplacer l'appel d'exécution par une commande d'affichage et relancer le script dans
> son interpréteur d'origine ne constitue pas une méthode de désobfuscation. Une couche
> mal identifiée suffit à provoquer l'exécution.

## Suricata en mode hors ligne

Suricata dispose de trois modes d'emploi. Celui retenu pour l'analyse n'interagit avec
aucune interface réseau.

| Mode | Placement | Capacité de blocage |
| --- | --- | --- |
| Hors ligne | Lecture d'un fichier de capture | Aucune |
| Détection | Observation d'une copie du trafic | Aucune |
| Prévention | En coupure, via `nfqueue` ou `af-packet` inline | Effective, sur configuration explicite |

> Le préfixe `ET DROP` désigne une catégorie de règles, non une action. Hors mode
> prévention, une règle portant l'action `drop` produit une alerte et rien d'autre.

```bash
suricata-update                                  # jeu Emerging Threats Open
suricata -r capture.pcap -l ./sortie             # exécution
chown -R $USER: ./sortie                         # les sorties appartiennent à root
```

| Option | Rôle |
| --- | --- |
| `-r` | Lecture depuis un fichier |
| `-l` | Répertoire de journalisation |
| `-S` | Charge exclusivement le fichier de règles indiqué, ignore le jeu public |
| `-s` | Ajoute le fichier de règles indiqué au jeu public |

L'option `-S` est employée en développement de règle, pour isoler le résultat. L'option
`-s` correspond à l'usage en déploiement.

| Fichier produit | Contenu |
| --- | --- |
| `fast.log` | Une ligne par alerte, format texte |
| `eve.json` | Un objet par événement, alertes et métadonnées de protocole |
| `stats.log`, `suricata.log` | Compteurs et journal de fonctionnement |

> Le fichier `fast.log` est alimenté en ajout. Entre deux itérations sur une règle, il
> doit être supprimé ou le répertoire de sortie changé, faute de quoi les alertes des
> exécutions précédentes sont relues comme un résultat courant.

> La relecture d'une capture constitue une boucle de test déterministe. À entrée
> constante, la sortie est reproductible, ce qui permet d'itérer sur une règle jusqu'à
> obtention du comportement attendu.
