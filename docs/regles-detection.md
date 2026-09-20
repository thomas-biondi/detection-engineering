# Règles de détection locales

Document de référence, état courant. Décrit les règles écrites, le raisonnement qui les
justifie et les résultats de validation.

Le fichier de règles se trouve dans `regles/suricata/local.rules`.

## Principe directeur

Les jeux de signatures publics couvrent les indicateurs propres à une campagne et un
ensemble de comportements génériques. Ils couvrent mal les anomalies dont le caractère
normal ou anormal dépend de l'environnement, faute de pouvoir arbitrer un taux de faux
positifs acceptable pour tous.

> Une règle locale ne réécrit pas ce que le jeu public couvre déjà. Elle exploite la
> connaissance de l'environnement supervisé pour traiter ce que le jeu public ne peut
> pas trancher.

## Convention

| Élément | Convention retenue |
| --- | --- |
| Plage d'identifiants | 1000000 à 1999999, réservée aux règles locales |
| Préfixe de message | `LOCAL`, pour distinction immédiate dans un journal mélangé |
| Révision | Incrémentée à chaque modification de la règle |

## Anatomie d'une règle

```
alert tls $HOME_NET any -> $EXTERNAL_NET any ( \
  msg:"..."; \
  flow:established,to_server; \
  tls.sni; \
  pcre:"/.../"; \
  classtype:trojan-activity; \
  sid:1000001; rev:1; )
```

| Composant | Rôle |
| --- | --- |
| En tête | Action, protocole, source et port, direction, destination et port |
| `$HOME_NET`, `$EXTERNAL_NET` | Variables définies dans `suricata.yaml`, couvrant par défaut les plages privées |
| `flow` | Restreint aux paquets d'une session établie et à un sens de circulation |
| Tampon collant | Bascule l'évaluation dans un champ décodé, par exemple `tls.sni`, `http.uri`, `dns.query` |
| `content`, `pcre` | Condition appliquée au tampon courant |
| `classtype` | Catégorie, détermine la priorité affichée |

## État des règles

| Identifiant | Objet | Statut | Validation |
| --- | --- | --- | --- |
| 1000001 | Nom de serveur TLS constitué d'une adresse IP littérale | Opérationnelle | 9 alertes, 1 hôte, 0 faux positif sur la capture de référence |
| 1000002 | Absence d'extension de nom de serveur dans le ClientHello | Non retenue | Aucune alerte, limite du moteur documentée ci dessous |

### 1000001. Nom de serveur TLS constitué d'une adresse IP littérale

Raisonnement. L'extension de nom de serveur d'une session TLS sert à désigner un hôte
par son nom, afin que le serveur présente le certificat correspondant. Un client qui y
place une adresse IP littérale n'a jamais disposé d'un nom. Recoupée avec l'absence de
toute résolution DNS préalable vers cette adresse, l'observation indique un programme
portant son infrastructure en dur, et non un navigateur piloté par un utilisateur.

Couverture du jeu public. Aucune alerte du jeu Emerging Threats Open sur ce critère pour
la capture de référence.

Faux positifs attendus. Certains équipements industriels, sondes et outils
d'administration établissent des sessions TLS vers une adresse sans nom. La règle est
destinée à un usage de chasse et d'alerte, non à un blocage.

Validation. Rejeu de la capture de référence, 9 alertes portant toutes sur la même
adresse de destination, aucune alerte sur le reste des 39 427 paquets.

> Une absence de faux positif sur une capture de 53 minutes portant sur un unique poste
> ne constitue pas une validation à l'échelle. La qualification définitive suppose une
> période d'observation sur trafic de production.

### 1000002. Absence d'extension de nom de serveur

Raisonnement. Un ClientHello dépourvu d'extension de nom de serveur est plus rare encore
qu'un nom de serveur contenant une adresse IP. Les navigateurs la renseignent
systématiquement, la joignabilité des hébergements mutualisés en dépend. Une
bibliothèque TLS de bas niveau ne la renseigne que si le développeur l'a prévu.

Formulation testée :

```
tls.sni; content:!".";
```

Résultat. Aucune alerte, alors que la capture de référence comporte un hôte
correspondant au critère.

Analyse du résultat. Les tampons collants de Suricata ne sont évalués que s'ils sont
alimentés. En l'absence d'extension de nom de serveur, le tampon `tls.sni` n'est pas
renseigné et la condition n'est jamais soumise au moteur. Une condition de non présence
sur un tampon vide ne peut pas produire d'alerte.

> Le langage de règles exprime la présence d'un motif dans un champ. Il n'exprime pas
> l'absence du champ lui même.

Contournements identifiés, à traiter en session ultérieure :

| Voie | Principe | Moteur concerné |
| --- | --- | --- |
| Certificat serveur | Exploiter le certificat présenté en réponse, notamment son caractère auto signé | Suricata |
| Événements structurés | Sélectionner les événements TLS dépourvus du champ de nom de serveur | SIEM |

Formulation de contournement validée sur les événements structurés :

```bash
jq -r 'select(.event_type=="tls" and (.tls.sni | not)) | "\(.timestamp) \(.dest_ip):\(.dest_port)"' eve.json
```

## Hiérarchie des indicateurs

Le coût de contournement d'un indicateur pour l'attaquant détermine sa durée de vie
utile. Le modèle de référence est la pyramide de la douleur.

| Indicateur | Coût de contournement | Emploi en détection |
| --- | --- | --- |
| Empreinte de fichier | Trivial | Consigner, ne pas fonder une détection dessus |
| Adresse IP | Faible | Inexploitable si l'adresse relève d'une infrastructure mutualisée |
| Nom de domaine | Modéré | Actionnable, à privilégier sur l'adresse |
| Artefact réseau ou système | Élevé | Base des règles locales |
| Technique, comportement | Très élevé | Objectif à atteindre |

> Une adresse appartenant à un réseau de distribution de contenu est mutualisée entre un
> très grand nombre de sites légitimes. Son blocage au niveau du pare feu interrompt des
> services sans rapport avec l'incident. L'indicateur actionnable est alors le domaine.

## Pistes non traitées

| Piste | Nature de l'anomalie | Moteur pertinent | Origine |
| --- | --- | --- | --- |
| Sous domaine de service de tunnel éphémère | Motif sur le nom sollicité | Suricata | Session 03 |
| Requêtes répétées à intervalle fixe | Régularité temporelle | SIEM | Session 01 |
| Certificat serveur auto signé | Comparaison entre deux champs du certificat | Suricata avec extension, ou SIEM | Session 01 |
| Session TLS vers une adresse jamais résolue par DNS | Corrélation entre deux protocoles | SIEM | Session 01 |
| HTTP en clair sur port réservé au chiffrement | Écart entre port et protocole décodé | Suricata | Session 02 |
| Téléchargement d'un environnement d'exécution par un poste bureautique | Motif sur la ressource sollicitée | Suricata | Session 03 |

La première piste est la plus immédiatement réalisable en signature : elle s'exprime sur
un champ unique, le nom sollicité en DNS ou en TLS, et le taux de faux positifs attendu
est très faible en environnement d'entreprise. Elle constitue la prochaine règle locale à
écrire.

Les pistes de régularité temporelle, de non présence de champ et de corrélation entre
protocoles ne s'expriment pas sur un paquet isolé. Elles relèvent de l'ingestion des
événements structurés par le SIEM.
