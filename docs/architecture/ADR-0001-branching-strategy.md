# ADR-0001 - Estrategia de branches e Pull Requests

## Status

Aceita para planejamento inicial.

## Contexto

O LumaBridge Display tera componentes de alto risco: driver Windows, host Windows com NVENC, cliente Linux com VA-API, protocolo, transporte e ferramentas. Misturar esses trabalhos em uma unica branch ou permitir commits diretos em `main` aumentaria o risco de regressao e dificultaria revisao.

Na etapa atual, a pasta local ainda nao esta inicializada como repositorio Git. Portanto, esta ADR documenta a estrategia futura, sem criar branch, commit, push, issue ou PR.

## Decisao

O projeto usara:

- `main` apenas para release final funcional ou releases estabilizadas.
- `dev` como branch de integracao durante o desenvolvimento.
- Branches por issue.
- Pull Request obrigatorio para integrar em `dev`.
- Conventional Commits.
- Nenhuma implementacao direta em `main`.
- Nenhum push necessario durante a fase de planejamento.

Padroes de branch:

- `docs/*` para documentacao.
- `infra/*` para governanca, CI e estrutura de repositorio.
- `spike/*` para validacoes tecnicas isoladas.
- `feature/*` para funcionalidades.
- `fix/*` para correcoes.
- `release/*` para estabilizacao antes de `main`.

## Consequencias

Beneficios:

- Reduz risco de misturar driver, host, cliente, protocolo e UI em um mesmo PR.
- Mantem `main` protegida ate existir release funcional.
- Facilita revisao pequena e vinculada a issue.
- Permite descartar spikes quando forem apenas prova tecnica.

Custos:

- Exige disciplina de branch e PR mesmo em projeto inicial.
- Pode parecer mais lento no comeco.
- Depende de templates e labels bem mantidas.

## Regras operacionais

- Todo PR futuro deve ter issue relacionada.
- Todo PR futuro deve declarar escopo, fora do escopo, testes e riscos.
- PRs de desenvolvimento devem ter base `dev`.
- Merge em `main` deve ocorrer apenas em release estabilizada.
- Commits devem seguir Conventional Commits.
- Nenhuma automacao deve criar issues, PRs, pushes ou merges sem revisao humana explicita.
