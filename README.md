# detection-engineering

Analyse de trafic réseau et ingénierie de détection. Ce dépôt documente une démarche
appliquée à des captures d'incidents publiques, avec pour objectif de produire des
règles de détection réutilisables et validées.

## Objet

Le dépôt ne rassemble pas des solutions d'exercices. Il documente une méthode et les
artefacts qu'elle produit :

| Production | Contenu |
| --- | --- |
| Méthodologie | Séquence de triage, filtres de référence, outillage et hygiène d'analyse |
| Dossier d'analyse | Chronologie d'incident, indicateurs de compromission, éléments de preuve |
| Règles de détection | Signatures locales, raisonnement associé, résultats de validation |
| Journal de bord | Déroulé factuel de chaque session, constats techniques, limites rencontrées |

La démarche prolonge deux travaux d'infrastructure documentés dans les dépôts
`lab-infrastructure` et `homelab` : la finalité est de boucler le cycle complet, de
l'observation d'un incident jusqu'au déploiement d'une détection sur une infrastructure
supervisée.

## Structure

```
detection-engineering/
├── README.md
├── .gitignore
├── docs/          documents de référence, état courant
├── analyses/      dossier d'analyse par exercice, avec export d'indicateurs
├── regles/        règles de détection et preuves de validation, par moteur
└── journal/       journal de bord par session
```

## Politique de publication

Les plateformes d'entraînement n'ont pas toutes la même licence. La règle appliquée est
la suivante :

| Source | Publication |
| --- | --- |
| malware-traffic-analysis.net | Analyse complète publiée. Les réponses sont diffusées par l'auteur du site. |
| Plateformes dont les conditions d'utilisation interdisent la diffusion de solutions | Méthodologie et règles de détection uniquement. Aucun cheminement de résolution, aucun drapeau. |

Aucun échantillon malveillant, aucune capture brute et aucun artefact exécutable ne sont
versionnés. Les fichiers d'origine restent disponibles auprès de leur éditeur. Les
valeurs sensibles sont remplacées par des marqueurs et la méthode est décrite à la place.

## Index des sessions

| Date | Session | Objet |
| --- | --- | --- |
| 2026-09-18 | 01 | Analyse d'une chaîne d'infection par faux site logiciel, première règle Suricata locale |
| 2026-09-19 | 02 | Analyse en autonomie, rapport d'incident complet, infection par outil d'administration à distance détourné |

## Dossiers d'analyse

| Dossier | Objet | Livrables |
| --- | --- | --- |
| `analyses/2025-01-22-authenticatoor/` | Publicité malveillante, faux site logiciel, implant PowerShell et outil d'administration à distance détourné | Analyse, indicateurs, règle de détection validée |
| `analyses/2024-11-26-nemotodes/` | Site légitime compromis, fausse mise à jour de navigateur, NetSupport RAT | Rapport d'incident, indicateurs |
# detection-engineering

Analyse de trafic réseau et ingénierie de détection. Ce dépôt documente une démarche
appliquée à des captures d'incidents publiques, avec pour objectif de produire des
règles de détection réutilisables et validées.

## Objet

Le dépôt ne rassemble pas des solutions d'exercices. Il documente une méthode et les
artefacts qu'elle produit :

| Production | Contenu |
| --- | --- |
| Méthodologie | Séquence de triage, filtres de référence, outillage et hygiène d'analyse |
| Dossier d'analyse | Chronologie d'incident, indicateurs de compromission, éléments de preuve |
| Règles de détection | Signatures locales, raisonnement associé, résultats de validation |
| Journal de bord | Déroulé factuel de chaque session, constats techniques, limites rencontrées |

La démarche prolonge deux travaux d'infrastructure documentés dans les dépôts
`lab-infrastructure` et `homelab` : la finalité est de boucler le cycle complet, de
l'observation d'un incident jusqu'au déploiement d'une détection sur une infrastructure
supervisée.

## Structure

```
detection-engineering/
├── README.md
├── .gitignore
├── docs/          documents de référence, état courant
├── analyses/      dossier d'analyse par exercice
├── regles/        règles de détection, par moteur
└── journal/       journal de bord par session
```

## Politique de publication

Les plateformes d'entraînement n'ont pas toutes la même licence. La règle appliquée est
la suivante :

| Source | Publication |
| --- | --- |
| malware-traffic-analysis.net | Analyse complète publiée. Les réponses sont diffusées par l'auteur du site. |
| Plateformes dont les conditions d'utilisation interdisent la diffusion de solutions | Méthodologie et règles de détection uniquement. Aucun cheminement de résolution, aucun drapeau. |

Aucun échantillon malveillant, aucune capture brute et aucun artefact exécutable ne sont
versionnés. Les fichiers d'origine restent disponibles auprès de leur éditeur. Les
valeurs sensibles sont remplacées par des marqueurs et la méthode est décrite à la place.

## Index des sessions

| Date | Session | Objet |
| --- | --- | --- |
| 2026-09-18 | 01 | Analyse d'une chaîne d'infection par faux site logiciel, première règle Suricata locale |
