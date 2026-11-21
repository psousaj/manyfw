# Investigação do PR #43 e verificação de afirmações sobre Netfilter

Data: 2026-11-20. Branch: `chore/phase-2-issue-reconciliation` (HEAD `5bb685d`) → base `main`.
Escopo: somente leitura. Nenhum comando privilegiado foi executado e o firewall do host não foi alterado.
Nota não versionada: este arquivo não foi adicionado ao git.

Siglas: **ADR** = `docs/adr/0005-scoped-experimental-nftables-apply.md`; **SPEC24** = `docs/specs/issue-24-linux-enforcement.md`; **NFT** = `crates/manyfw-cli/src/nft_apply.rs`; **man nft** = `man nft(8)` local, nftables v1.1.6.

## 1. Estado do PR #43

| Item | Resultado | Fonte |
|---|---|---|
| Título/estado | "ManyFW v0.4.0: Experimental Guarded Enforcement", OPEN, sem reviews e sem comentários | `gh pr view 43` |
| Tamanho | 188 arquivos, +21.476/−624 | `git diff --stat origin/main...HEAD` |
| CI hospedado | Os jobs executados passaram: Rust stable/1.85, unit, fixtures, discovery em namespace, planner isolado, auditoria de dependências e GitGuardian. Os jobs de integração/recuperação, a verificação de evidência e os smokes/builds de release foram **SKIPPED** | `gh pr view 43 --json statusCheckRollup` |
| fmt local | OK (exit 0) | `cargo fmt --all -- --check` |
| clippy local | OK | `cargo clippy --workspace --all-targets -- -D warnings` |
| testes locais | 38 + 21 + 117 + 13 + 24 + 1 passaram. Houve 0 falhas. 2 testes ficaram ignorados (`planner_netns`, porque exigem CAP_NET_ADMIN/KVM) | `cargo test --workspace` |

Escopo declarado: um Apply experimental que cria apenas a tabela `inet manyfw` com uma base chain no hook **input** com prioridade −300, guardado por checkpoint, lock, token de confirmação, rollback por timeout e um supervisor systemd/OpenRC (corpo do PR; ADR; `NFT:15-17,320`). Docker, FORWARD e NAT ficam fora do escopo, e Docker não é tratado como dono de DOCKER-USER (ADR:105-110).

### Conformidade com AGENTS.md/SECURITY.md

- ✅ **Não usa flush nem toca em chains alheias.** O script só faz `delete table inet manyfw` e recria a própria tabela (`NFT:315-320`, `NFT:609`). O restore após reboot rejeita `flush ruleset`, `jump` para fora e tabelas estrangeiras (testes em `NFT:1525-1557`).
- ✅ **Atomicidade.** Delete e add vão num único `nft -f` (`NFT:1323`), ou seja, numa transação netlink em lote (ver §2.9).
- ✅ **Sem identidade por IP de container e sem DOCKER-USER presumido.** Isso está declarado no ADR:105-110, e há golden `planner/docker-iptables-without-docker-user.json`.
- ✅ **`accept` local, não final.** Está documentado corretamente no ADR:93-107 e no SPEC24:34-36, e bate com o man nft (§2.4).
- ✅ **Checkpoint e rollback antes do apply**, com evidência de KVM para systemd e OpenRC citada no PR e em `docs/TEST-MATRIX.md`.

### Riscos, lacunas e discrepâncias

1. **`graphify-out/` versionado no PR.** São 69 arquivos e ~2,5 MB de cache de AST, e `.gitignore` não o exclui. É ruído e pode vazar estrutura local. Recomendo remover e ignorar.
2. **Discrepância entre docs e código sobre o hook input "limpo".**
   - O ADR:100-104 e o achado bloqueante nº 1 (ADR:196-199) dizem que o Apply deve "reject any pre-existing input base chain… supports only a clean input hook".
   - O código **aceita** base chains estrangeiras `filter` em `ip`/`ip6`/`inet` com policy accept ou drop (`compatible_input_hook`, `NFT:971-998`, chamada em `validate_plan` `NFT:177`).
   - A SPECIFICATION.md:318-321 diz que o hook "need not otherwise be empty".
   - O ADR está desatualizado em relação à spec e ao código. A disposição do achado bloqueante foi alterada sem um novo registro de review explícito.
3. **Default `deny` sem exceções.** `default_rule` gera `meta nfproto ipv4|ipv6 drop` incondicional no fim da chain (`NFT:410-435`).
   - Não há `ct state established,related accept`, exceção de `lo` nem exceção de ICMPv6 ND/RA.
   - Num host real isso derruba as respostas de conexões de saída (DNS, apt, SSH já estabelecido), o loopback e o IPv6 (sem NDP).
   - O SPEC24:36 diz "Defaults apply only to managed scope", mas a regra cobre todo o input da família.
   - Isso é aceitável num guest de laboratório, mas precisa ser explicitado ou corrigido (decisão D3).
4. **iptables-legacy invisível.** A checagem de composição lê só `nft --json list ruleset` (`NFT:121`). Regras xtables-legacy (`ip_tables`) não aparecem ali, mas atuam no mesmo hook (§2.6). A discovery lê `iptables-save` (`crates/manyfw-linux/src/firewall.rs:80`), mas o Apply não recusa um host com regras legacy ativas.
5. **Primeira criação com `add table`.** Quando a tabela não existe, o script usa `add table` (`NFT:317`), que é idempotente e faz merge, em vez de `create table`, que falha se a tabela existir. O restore após reboot já usa `create` (`NFT:1290`). Há uma janela TOCTOU pequena, mitigada pela verificação posterior.
6. **Prioridade −300 (`raw`) no hook input.** É válida: o man nft lista `raw` para inet/ip/ip6 em todos os hooks. No input, o conntrack já rodou em prerouting, então `ct state` funcionaria. Como a ManyFW roda **antes** de UFW/firewalld (prioridade 0), um `drop` da ManyFW vence os accepts deles. Já um `accept` da ManyFW não vence os drops deles, e isso está corretamente documentado.
7. **Evidência e gates.**
   - A suíte de pacotes (104/104) é de um candidato anterior, e o run atual de systemd marca `release_eligible: false` (corpo do PR).
   - Os jobs de recuperação/integração no CI estão SKIPPED.
   - Não houve review humano. O "review" de arquitetura/segurança foi feito pelo agente Goal, como autoriza o AGENTS.md, e não é independente.
   - O merge cria uma release candidata v0.4.0 com Apply, embora o README/AGENTS ainda falem em "v0.3.0 read-only". Confirme a coerência da narrativa de versão.
8. **Restore após reboot tolera chains alheias** (`NFT:1010`), o que é coerente com a spec atual, mas não com o ADR (ver item 2).

## 2. Verificação das afirmações das conversas de IA

| # | Afirmação | Veredito | Fonte / observação |
|---|---|---|---|
| 2.1 | Netfilter é o framework; iptables e nftables são frontends; iptables-nft traduz para nftables | **Correta** com nuance: iptables-legacy usa o backend xtables do kernel, e iptables-nft programa o nf_tables | https://wiki.nftables.org/wiki-nftables/index.php/Legacy_xtables_tools |
| 2.2 | Há 5 hooks IP (prerouting, input, forward, output, postrouting) | **Correta** para ip/ip6/inet. O inet também tem `ingress` (kernel ≥ 5.10) | man nft, seção ADDRESS FAMILIES |
| 2.3 | O DNAT da porta publicada leva o pacote para FORWARD, não para INPUT, e por isso o UFW não bloqueia | **Correta** | Docker docs: "Docker routes container traffic in the nat table… diverted before it reaches the INPUT and OUTPUT chains that ufw uses" — https://docs.docker.com/engine/network/packet-filtering-firewalls/ |
| 2.3b | DOCKER-USER é avaliada antes das regras do Docker | **Correta só no backend iptables.** A cadeia DOCKER-USER fica no filter/FORWARD, antes de DOCKER-FORWARD/DOCKER | https://docs.docker.com/engine/network/firewall-iptables/ |
| 2.4 | Só base chain tem hook e policy; regular chain é chamada por jump/goto | **Correta** | man nft, OVERALL EVALUATION; https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains |
| 2.5 | Prioridades: raw −300, mangle −150, dstnat −100, filter 0, security 50, srcnat 100 | **Correta.** A versão do Gemini ("mangle −50 a 0") está **incorreta**: mangle é −150 (NF_IP_PRI_MANGLE). Também existem conntrack −200 e defrag −400 | https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks (tabela de prioridades) |
| 2.5b | No nftables, tabelas são containers definidos pelo usuário | **Correta** | man nft: "Tables are merely a concept… not relevant to the evaluation of the ruleset" |
| **2.6 CRÍTICA** | "Tabela própria com prioridade anterior à do Docker e policy drop garante que Docker/UFW nunca sobrescrevem minha regra" | **Incorreta/enganosa.** `accept` encerra só a base chain atual, e o pacote segue para a próxima base chain do mesmo hook ou de um hook posterior. `drop` é final e não pode ser revertido. Um pacote só é aceito se **nenhuma** chain der drop. Consequências: (a) um allowlist com `accept` não anula o drop de UFW/firewalld/Docker; (b) uma `policy drop` própria derruba também o tráfego que o Docker aceita, como portas publicadas e retorno de containers em forward; (c) "precedência" só existe para **drop**, e a ordem importa apenas se houver mutação de pacote ou metadados | man nft (VERDICT STATEMENT; OVERALL EVALUATION OF THE RULESET); Docker docs, que mostram uma FORWARD DROP em iptables quebrando o que o Docker aceitou no nftables (https://docs.docker.com/engine/network/firewall-nftables/) |
| 2.7 | "iptables legacy e nftables são subsistemas paralelos" | **Imprecisa.** As regras de ambos ficam em estruturas separadas e não aparecem uma na listagem da outra, mas os dois registram hooks no **mesmo** pipeline Netfilter, e o pacote passa por ambos. Um drop em qualquer um vence | Docker docs (firewall-nftables): "will drop packets that have been accepted by Docker's nftables rules, because the packet will be processed by the iptables chains as well as Docker's nftables chains" |
| 2.8a | Script com `flush ruleset` | **Perigoso.** Apaga as tabelas de Docker, UFW e firewalld e viola o AGENTS.md ("Never write into or flush foreign firewall chains") e o ADR:90 | — |
| 2.8b | `type filter hook forward; policy drop;` sem `priority` | **Sintaxe inválida** no nft 1.1.6: `nft -c` retorna "syntax error, unexpected semicolon, expecting priority" (testado localmente, só parse) | execução local `nft -c -f` |
| 2.8c | `iifname "lo" accept` seguido de regra para 5432 em lo | É redundante: a regra de 5432 em lo nunca casa após o accept de lo na mesma chain | Semântica de `accept` (man nft) |
| 2.8d | forward com `policy drop` sem ICMPv6 e sem regras para Docker | Quebra o PMTU/ND do IPv6 e todo o forward de containers, porque o accept do Docker não salva o pacote do drop próprio | §2.6 |
| 2.9 | nft fala com o kernel via netlink (NETLINK_NETFILTER, subsistema NFNL_SUBSYS_NFTABLES), e `nft -f` é atômico | **Correta.** Um arquivo é enviado como um lote transacional que é aplicado inteiro ou nada | https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement; `man nft` (`--debug netlink`) |
| 2.9b | Opções em Rust: `nft -f` / `nft -j` (JSON), libnftables via FFI, crates `nftables` (wrapper JSON sobre `nft`), `rustables` (netlink nativo), `mnl` | **Correta** como inventário. O PR usa CLI e JSON (`NFT:121,1323`), o que é coerente com o atomismo e a auditabilidade | crates.io (nftables, rustables, mnl) |
| 2.10 | Estados NEW, ESTABLISHED, RELATED e INVALID; SYN+FIN é INVALID; existe `/proc/net/nf_conntrack` | **Correta.** SYN\|FIN não está em `tcp_valid_flags`, e `tcp_error` marca o pacote como inválido. Isso **não** o descarta por si só: precisa de uma regra `ct state invalid drop`. `/proc/net/nf_conntrack` depende de configuração do kernel; o preferível é `conntrack -L` | https://github.com/torvalds/linux/blob/master/net/netfilter/nf_conntrack_proto_tcp.c (`tcp_valid_flags`) |
| 2.11 | Docker com backend nftables | **Correta**, com flag `firewall-backend: nftables` (experimental). O Docker cria tabelas `ip docker-bridges`/`ip6 docker-bridges`, **não há DOCKER-USER**, e o usuário deve criar a própria tabela/base chain. O Docker exige ser dono exclusivo das suas tabelas. Impacto: a ManyFW deve detectar o backend e nunca presumir DOCKER-USER (o golden `docker-native-nftables.json` já cobre isso) | https://docs.docker.com/engine/network/firewall-nftables/ |
| 2.12 | MikroTik, FastTrack, speedtest, OSI | **Fora de escopo.** O RouterOS usa kernel Linux, mas expõe o próprio firewall (estilo iptables, não nft). A tabela de camadas do Gemini confundiu as numerações TCP/IP e OSI. Isso não tem impacto no ManyFW | — |

**Impacto no design:** a ManyFW não pode prometer "precedência" nem "minha regra prevalece". O modelo correto, já adotado no ADR, é:

- um **deny** da ManyFW (em prioridade baixa) é autoritativo;
- um **allow** é necessário, mas não suficiente;
- uma policy/default **drop** própria afeta o tráfego que outros gerenciadores permitem.

O `explain`/`audit` deve modelar o veredito como a "AND" de todas as base chains do hook, mais as regras xtables-legacy.

## 3. Decisões para o usuário

| ID | Decisão | Opções | Recomendação |
|---|---|---|---|
| D1 | O hook input precisa estar limpo? | (a) Voltar ao ADR, recusando qualquer base chain alheia; (b) manter o código e a spec, admitindo chains filter alheias, e atualizar o ADR com um novo review | **(b)**, mas com re-review registrado e ADR:100-104/196-199 corrigidos. Assim a ferramenta funciona com UFW/firewalld; é preciso ainda provar em KVM o deny contra um accept externo e o allow contra um drop externo (SPEC24:66). Se não houver tempo, use **(a)**, que é mais seguro |
| D2 | O que fazer com regras iptables-legacy? | (a) Recusar o Apply se `iptables-legacy-save` não estiver vazio; (b) modelar o legacy; (c) ignorar | **(a)**: é fail-closed, barato e coerente com a §2.7 |
| D3 | Como deve ser o default deny? | (a) Manter o drop incondicional e documentar que derruba conexões estabelecidas, lo e ND; (b) prefixar `ct state established,related accept`, `iifname lo accept` e ICMPv6 ND/RA; (c) proibir default deny no experimental | **(b)** ou **(c)**. A forma atual é um "footgun" que contradiz o SPEC24:36 |
| D4 | `graphify-out/` no PR | Remover e adicionar ao `.gitignore`, ou manter | **Remover** |
| D5 | O merge deve exigir evidência de pacotes do candidato atual? | (a) Rerodar a suíte 104/104 no HEAD; (b) aceitar a evidência anterior | **(a)**: o run atual marca `release_eligible: false` |
| D6 | Review independente antes do merge | Review humano ou externo, ou só o agente Goal | Um review humano de pelo menos `nft_apply.rs` e `transaction.rs` (~4.800 linhas) antes do merge, mesmo que o AGENTS.md permita o agente para o escopo KVM |
| D7 | `add table` vs `create table` na primeira aplicação | Trocar para `create` | **Trocar**: é trivial e elimina o merge silencioso |
| D8 | Narrativa de versão | Atualizar o README/AGENTS ("v0.3.0 read-only") para v0.4.0 experimental, ou adiar | Atualizar no próprio PR, deixando claro que não é proteção de produção |
| D9 | Escopo futuro para Docker/FORWARD | (a) Só explicar, sem enforce; (b) criar uma base chain forward própria só com drops, nunca `policy drop` | **(a)** agora. Se partir para (b), só com drops (§2.6) e com detecção do backend do Docker (§2.11) |

## 4. Impacto da decisão "nftables-by-default"

Orientação nova do dono do projeto (2026-11-20): **nftables é o backend padrão de escrita do ManyFW.**

O que ela **não** muda:
- A observação continua lendo tudo, incluindo iptables-legacy e iptables-nft (SECURITY.md:14-15).
- Nenhuma garantia de produção passa a valer. O Apply continua restrito a guests KVM descartáveis (AGENTS.md; SPECIFICATION.md:449-452).

### 4.1 O que já está alinhado

| Onde | Situação | Fonte |
|---|---|---|
| PR #43 | O único adaptador de escrita já é nftables: tabela `inet manyfw`, marcador `manyfw-owner-v1`, input com prioridade −300 e lote `nft -f` | `NFT:15-17,315-320,1323` |
| ADR-0005 | Já define a posse exclusiva da tabela, proíbe `flush ruleset` e alterar tabelas alheias, e trata `accept` como local e `drop` como final | ADR:82-110 |
| ARCHITECTURE.md | Distingue Docker em modo iptables (DOCKER-USER) do modo nativo nftables (sem DOCKER-USER) | ARCHITECTURE.md:32 |
| core | Já tem `BackendKind::{Nftables, Iptables, …}` e `BackendMode::{Unknown, NativeNftables, IptablesDocker, …}`. Sem um modo verificado, o planner não recorre implicitamente a outro gerenciador | `crates/manyfw-core/src/backend.rs:18-35,1014-1022` |
| SECURITY.md | Já pede "Never flush or rewrite foreign rules" e atomicidade "within backend guarantees" | SECURITY.md:23,96 |

### 4.2 O que precisa mudar ou ser escrito

1. **Novo ADR (por exemplo, ADR-0006 "nftables como backend padrão").**
   - Registrar a decisão e o que "padrão" significa: único alvo de escrita, ou preferido com um adaptador iptables futuro?
   - Registrar os critérios de recusa da §4.4 e o que fazer com o roadmap.
   - O texto de SPECIFICATION.md:446-448 ("no iptables adapter is implemented") vira política, não só um estado atual.
2. **ARCHITECTURE.md:17** descreve "nftables and iptables feasibility checks" sem ordem de preferência. É preciso dizer que a escrita vai para nftables e que iptables passa a ser só observado, ou que um adaptador iptables está fora de escopo.
3. **ROADMAP.md:33-36**:
   - remover ou adiar qualquer marco de adaptador de escrita iptables;
   - adicionar um marco para a detecção de capacidade da §4.4;
   - adicionar um marco para composição com firewalld e UFW em KVM.
4. **SPECIFICATION.md**:
   - documentar como a CLI reporta o backend escolhido e os motivos de recusa;
   - corrigir a contradição do default deny (§1, item 3);
   - corrigir a contradição do ADR sobre o hook limpo (§1, item 2).
5. **SECURITY.md:98** já exige testes "Docker legacy and native nftables". Faltam:
   - matriz com firewalld no backend nftables;
   - UFW sobre iptables-nft;
   - host com regras iptables-legacy, onde o resultado esperado é recusa.
6. **Código do PR (`nft_apply.rs`)**:
   - recusar o Apply quando houver regras xtables-legacy (§1, item 4);
   - trocar `add table` por `create table` na criação inicial (§1, item 5);
   - não depender só de `nft list ruleset` para concluir que o hook é seguro.

### 4.3 Requisitos de coexistência segura

| Requisito | Por quê / fonte | Estado no PR |
|---|---|---|
| Uma tabela própria e marcada; nunca adotar tabela sem marcador | ADR:83-87 | ✅ |
| Nunca usar `flush ruleset` nem `delete`/`flush` em tabela ou chain alheia, nem mudar a prioridade de terceiros | AGENTS.md; Docker: "Docker expects to have full ownership of its tables" (https://docs.docker.com/engine/network/firewall-nftables/) | ✅ (o restore rejeita `flush ruleset`, `NFT:1530`) |
| Modelar o veredito como o "E" de todas as base chains do hook: **o allow da ManyFW não é garantia, o drop da ManyFW é**. Nunca usar `policy drop` própria em input ou forward sem aceitar que ela bloqueia o que os outros liberam | man nft, OVERALL EVALUATION / VERDICT STATEMENT | ✅ policy accept; ⚠️ o default deny se comporta como uma policy drop por família (§1, item 3) |
| Prioridade fixa e revisada; recusar composição desconhecida, como chains `nat`/`route` no input com efeitos laterais, ou flowtables | man nft, prioridades; SPEC24:41-43 | ✅ flowtable é recusada; chains alheias do tipo filter são aceitas (ver D1) |
| **iptables-legacy**: as regras não aparecem no `nft`, mas atuam no mesmo hook | Docker nftables docs (o pacote passa "by the iptables chains as well as Docker's nftables chains") | ❌ falta recusa ou modelagem |
| **iptables-nft**: as regras aparecem como tabelas `ip filter`/`ip6 filter` com chains INPUT/FORWARD de prioridade 0. A ManyFW deve tratá-las como alheias e nunca editá-las com `nft` (o iptables-nft espera um formato próprio) | https://wiki.nftables.org/wiki-nftables/index.php/Legacy_xtables_tools | ✅ (são tratadas como alheias) |
| **Docker em modo iptables**: DOCKER-USER é de posse do Docker; a ManyFW só observa e não escreve | ARCHITECTURE.md:32; backend.rs:1025-1028 | ✅ |
| **Docker em modo nftables** (experimental): tabelas `ip docker-bridges`/`ip6 docker-bridges` e nenhuma DOCKER-USER. Controle de forward exige uma base chain própria em forward, só com drops. Uma FORWARD DROP de iptables quebra o Docker | https://docs.docker.com/engine/network/firewall-nftables/ | ✅ fora de escopo (só input) |
| **firewalld**: no backend nftables, usa a própria tabela `inet firewalld`, que fica alheia. Com `--reload`, o firewalld só deve recriar a tabela dele; isso precisa ser verificado em KVM. Sempre que houver uma regra de drop, ela também vence | https://firewalld.org/2018/07/nftables-backend | ⚠️ não testado |
| **UFW**: gera regras iptables (legacy ou nft, conforme o `update-alternatives` da distro) no INPUT com prioridade 0. Um drop do UFW vence um allow da ManyFW, e um drop da ManyFW (−300) vence um allow do UFW | man ufw-framework; Legacy_xtables_tools | ⚠️ não testado em KVM |

### 4.4 Detecção de capacidade e fallback

O Apply só é **elegível** se todas as condições abaixo forem verificadas. Qualquer falha ou ambiguidade resulta em `unknown`/`blocked`, nunca em "safe", e não há fallback automático para iptables.

1. O binário `nft` existe, tem versão mínima e `nft -j list ruleset` funciona (`NFT:121`).
2. O kernel tem nf_tables. Um `nft -c` com um lote mínimo da tabela própria serve como prova de parse, sem mutação.
3. A família `inet` é suportada no hook input.
4. Não há regras xtables-legacy com conteúdo. A forma de checar (`iptables-legacy-save`, `ip6tables-legacy-save`, ou existência de `/proc/net/ip_tables_names`) é decisão pendente P4.
5. A posse da tabela `inet manyfw` está consistente (`NFT:1040-1075`).
6. Não há flowtables nem chains de input com tipo, hook ou policy desconhecidos (`NFT:971-998`).
7. O modo do Docker foi identificado. Para Apply de forward, `BackendMode::Unknown` bloqueia.
8. O supervisor de recuperação está ativo.

Os relatórios de `audit`/`explain` devem mostrar o backend e os motivos.

### 4.5 Interface Rust

| Opção | Prós | Contras |
|---|---|---|
| **`nft -f` (texto) e `nft -j list` (JSON)**, usado hoje | Um arquivo é aplicado como um único lote transacional, inteiro ou nada (https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement). Auditável, fácil de reproduzir em testes e checkpoints, sem `unsafe` | Depende do binário e da versão. Exige parse do JSON e cuidado com escaping (o PR valida nomes de interface em `NFT:1000-1007`) |
| `nft -j -f` (entrada JSON) | Mesma atomicidade, entrada estruturada sem escaping de texto | O schema JSON varia entre versões do nft; o texto de checkpoint é menos legível |
| libnftables (FFI) | Mesmo motor do CLI, sem fork | Exige `unsafe` e dependência de linkagem; o ganho é pequeno |
| Netlink direto (`rustables`, `mnl`) | Sem binário externo; controle fino de lote e genid | Reimplementa a semântica de expressões do nft, com alto risco de divergência e mais superfície privilegiada. Fica a cargo do projeto testar compatibilidade com versões do kernel |

**Recomendação:** manter `nft -f`/`-j` como interface padrão, fixar e verificar a versão mínima, e considerar `nft -j -f` para eliminar o escaping. Netlink só se surgir necessidade concreta, como desempenho ou ambientes sem o binário, e com um ADR próprio.

### 4.6 Decisões pendentes (não resolvidas pela orientação)

| ID | Pendência | Opções | Recomendação |
|---|---|---|---|
| P1 | O que "padrão" significa | (a) nftables é o único backend de escrita e iptables nunca é escrito; (b) nftables é o preferido e um adaptador iptables pode vir depois | **(a)** agora, registrado em ADR. Uma eventual opção (b) só com ADR novo |
| P2 | Host sem nf_tables ou sem `nft` | Recusar, ou fazer fallback para iptables | **Recusar** (unknown/blocked) |
| P3 | Host com iptables-legacy ativo | Recusar, modelar ou ignorar | **Recusar** (= D2) |
| P4 | Como detectar o legacy | `*-legacy-save`, `/proc/net/ip_tables_names`, ou os módulos carregados | Combinar `/proc` (somente leitura) com `*-legacy-save` quando o binário existir; se for inconclusivo, tratar como unknown |
| P5 | Versão mínima de nft e kernel | Escolher após a matriz de CI/KVM | Definir no ADR-0006 (as evidências locais usam o nft 1.1.6) |
| P6 | Prioridade do input: −300 ou `filter − N` | Manter −300 (o drop vem antes de tudo) ou alinhar com `filter` | Manter −300, documentar que fica antes de UFW/firewalld e testar com o `--reload` deles |
| P7 | Política de default deny | (= D3) | Exceções para established/related, `lo` e ICMPv6 ND, ou proibir |
| P8 | Escopo de forward com Docker nftables e Docker iptables | Só explicar, ou ter chain forward própria só com drops | Só explicar até haver um ADR e evidência em KVM (= D9) |
| P9 | `nft -f` texto ou `nft -j -f` JSON | Manter o texto ou migrar | Manter agora; avaliar o JSON junto com P5 |
| P10 | Testes de composição com firewalld e UFW em KVM | Bloqueiam o merge, ou entram no próximo marco | Próximo marco, mas sem anunciar suporte antes |
