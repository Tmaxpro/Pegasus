# Scorpio — Autonomous Grey-Box DAST for REST APIs

> Projet de Fin d'Études — M2 Cybersécurité
> Framework de test d'intrusion dynamique multi-agents pour APIs REST, fondé sur LangGraph, le checkpointing SQLite et une sandbox Docker isolée embarquant `ffuf`, `sqlmap`, `jwt-tool` et SecLists.

## Pourquoi Scorpio ?

Les fuzzers classiques (ffuf, wfuzz) ignorent la sémantique des APIs : ils ne savent pas qu'un `card_id` désigne une ressource à protéger, qu'un champ `is_admin` absent du schéma OpenAPI peut signaler une attaque Mass Assignment, ou qu'une route `/admin/*` mérite un test BFLA dédié. Scorpio se positionne en **Grey-Box** : il consomme la spec OpenAPI, en reconstruit le graphe de ressources, puis orchestre une équipe d'agents LLM qui *raisonnent* sur chaque endpoint avant d'invoquer des outils offensifs réels dans une sandbox.

## Architecture

```
┌──────────┐      ┌────────────┐      ┌──────────┐     ┌──────────┐     ┌──────────┐
│ Analyst  │ ──▶  │ Supervisor │ ──▶  │ Attacker │ ──▶ │ Auditor  │ ──▶ │ Reporter │
└──────────┘      └─────┬──────┘      └────┬─────┘     └────┬─────┘     └──────────┘
                        ▲                  │ tools           │
                        └──────────────────┴─────────────────┘
                              (cycle LangGraph + SqliteSaver)
```

| Agent       | Rôle |
|-------------|------|
| Analyst     | Parse l'OpenAPI, enrichit chaque endpoint avec `resource_type`, `id_parameters`, dépendances inter-opérations. |
| Supervisor  | Pré-filtre les attaques OWASP API Top 10 applicables (heuristiques), puis demande au LLM de prioriser. Route conditionnellement vers Attacker ou Reporter. |
| Attacker    | Boucle RAOA (Réflexion → Action → Observation → Ajustement). Seul agent ayant accès à l'outil `execute_sandbox_tool`. |
| Auditor     | Élimine les faux positifs (WAF, échappement, 200 OK trivial). Valide la sévérité et le CVSS. |
| Reporter    | Génère le rapport Markdown final (`./reports/api_pentest_report.md`). |

Toutes les transitions transitent par un `ScannerState` typé (TypedDict) ; chaque transition est persistée par `SqliteSaver` → un crash en plein scan est reprenable avec `python main.py resume --thread <id>`.

## Installation

```bash
# Pré-requis : Python 3.11+, Docker daemon accessible
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# éditer .env pour y mettre la clé Anthropic

# Construction de la sandbox (ffuf, sqlmap, jwt-tool, SecLists)
python main.py sandbox build
```

## Utilisation

```bash
# Scan complet contre une API locale
python main.py scan \
    --spec examples/vulnerable_api.yaml \
    --base-url http://localhost:8000 \
    --token-a "Bearer <jwt_user_A>" \
    --token-b "Bearer <jwt_user_B>"
```

Pendant le scan :
- chaque étape est journalisée avec `rich`,
- l'état est checkpointé après chaque nœud (durée moyenne d'une mission ≈ 30 s),
- un rapport intermédiaire reste lisible à tout moment dans `reports/`.

Options utiles :

```bash
python main.py sandbox shell     # shell interactif dans la sandbox
python main.py sandbox stop      # arrêt propre du conteneur
python main.py resume --thread <uuid>   # reprise d'un scan interrompu
```

## Apport sémantique vs. fuzzer traditionnel

| Capacité                                      | Fuzzer classique | Scorpio |
|-----------------------------------------------|:----------------:|:-------:|
| Parsing OpenAPI                               |        ◐         |    ●    |
| Classification sémantique des ressources      |        ✗         |    ●    |
| Détection BOLA inter-comptes (token A vs B)   |        ✗         |    ●    |
| Mass Assignment de champs *non spécifiés*     |        ✗         |    ●    |
| Validation auditée (anti-faux positifs)       |        ✗         |    ●    |
| Reprise sur panne (checkpoint)                |        ✗         |    ●    |
| Rapport CVSS + impact métier + remédiation    |        ✗         |    ●    |

## Sécurité

- Les commandes invoquées par l'Attacker passent par `Docker exec` **en mode liste** (`execve` direct, jamais `/bin/sh`).
- Une allow-list de binaires (`ffuf`, `sqlmap`, `jwt-tool`, `curl`, `jq`, `python3`, …) est appliquée *avant* tout appel à Docker.
- Le conteneur est lancé avec `cap_drop=ALL` et `no-new-privileges:true`.
- Scorpio est destiné à être utilisé **uniquement** contre des APIs que vous êtes autorisé à tester. Le projet inclut une cible vulnérable factice (`examples/vulnerable_api.yaml`).

## Étendre Scorpio

Ajouter une nouvelle classe d'attaque OWASP revient à :
1. ajouter une entrée à `OWASP_API_TOP_10` dans `scorpio/owasp.py` (heuristique `applies_to`, CVSS de base, gabarit de justification) ;
2. (optionnel) enrichir le prompt de l'Attacker s'il faut introduire un nouvel outil dans la sandbox ;
3. rebuilder l'image de la sandbox si un nouveau binaire est requis.

Aucun changement n'est requis ni dans le graphe ni dans les autres agents.

## Structure du dépôt

```
.
├── docker/Dockerfile.sandbox       # image de la sandbox offensive
├── examples/vulnerable_api.yaml    # spec OpenAPI vulnérable par construction
├── main.py                         # CLI Typer (scan / resume / sandbox)
├── requirements.txt
└── scorpio/
    ├── agents/                     # 5 nœuds LangGraph
    ├── tools/                      # tool LangChain "execute_sandbox_tool"
    ├── config.py                   # paramètres (pydantic-settings)
    ├── graph.py                    # compilation du StateGraph + SqliteSaver
    ├── llm.py                      # factory ChatAnthropic
    ├── owasp.py                    # catalogue OWASP API Top 10 (2023)
    ├── prompts.py                  # prompts système des agents
    └── state.py                    # ScannerState (TypedDict + add_messages)
```
