# Guia de Contribuição — LumaBridge Display

Obrigado pelo interesse em contribuir com o **LumaBridge Display**. Este documento define o escopo do projeto, o fluxo de branches e Pull Requests, os padrões de qualidade, segurança e privacidade, a política de dependências de terceiros e a política prospectiva de **Developer Certificate of Origin (DCO 1.1)**.

---

## 1. Escopo e Arquitetura do Projeto

O LumaBridge Display é uma plataforma open source para espelhamento, extensão real de área de trabalho na sessão gráfica ativa e interação remota entre dispositivos:

- **Emissor Windows (`M0`, integrado em `dev` via PR #37 / merge `23a28046`):**
  - [`windows/driver/`](windows/driver/README.md): driver virtual UMDF/IddCx (`LumaBridgeIddDriver`), máquina de estados determinística, monitor virtual opt-in (`EnableVirtualMonitor = 0` por padrão), modos CTA-861, pipeline Direct3D 11, pool limitado de texturas compartilhadas (`IDXGIKeyedMutex` + NT handle) e transporte IPC local autenticado (`LBIF` v1.0/v1.1 via Named Pipe).
  - [`windows/host/`](windows/host/README.md): consumidor local (`lumabridge-host.exe`), codificador GPU NVIDIA NVENC H.264 (carregamento dinâmico de `nvEncodeAPI64.dll` em runtime), validador estrutural/MFT H.264 e estímulo diagnóstico controlado.
  - **Fronteira permanente:** `LumaBridgeIddDriver` permanece isolado de rede, transporte remoto e SDKs proprietários de encoder; `LBIF` permanece privado ao enlace local Windows.
- **Arquitetura Universal (`M1–M6`, `M1` ainda não iniciada):**
  - Documentada em [`docs/architecture/universal-platform-architecture.md`](docs/architecture/universal-platform-architecture.md), [`docs/planning/UNIVERSAL_ROADMAP.md`](docs/planning/UNIVERSAL_ROADMAP.md) e [`docs/protocol/wire-protocol-v1.md`](docs/protocol/wire-protocol-v1.md).
  - Planeja núcleo multiplataforma compartilhado (`core/`), receptores/emissores Linux (`platforms/linux/`) e Android (`platforms/android/`), sem reescrever o driver C++/WDK Windows.

Consulte [`REQUISITOS_LUMABRIDGE.md`](REQUISITOS_LUMABRIDGE.md) e os ADRs em [`docs/architecture/`](docs/architecture/ADR-0001-branching-strategy.md) antes de propor mudanças arquiteturais.

---

## 2. Fluxo de Branches e Pull Requests

O repositório segue a estratégia definida em [`docs/architecture/ADR-0001-branching-strategy.md`](docs/architecture/ADR-0001-branching-strategy.md):

- **`main`:** reservada exclusivamente para releases estabilizadas e validadas. Nunca faça commits ou merges diretos em `main`.
- **`dev`:** branch de integração contínua de desenvolvimento. Toda alteração em `dev` deve entrar via **Pull Request revisado**.
- **Estratégia de integração recomendada:** **Merge commit** (`--no-ff`), preservando a ancestralidade exata dos commits validados e as assinaturas `Signed-off-by`. Não reescreva histórico publicado em branches compartilhadas (`force-push`, `rebase` ou `squash` que destruam rastreabilidade de validação).
- **Branches por issue / escopo:**
  - `docs/*` — documentação e planejamento
  - `chore/*` / `infra/*` — governança, licenciamento, templates e infraestrutura de CI
  - `spike/*` — validações técnicas exploratórias isoladas
  - `feature/*` — novas funcionalidades vinculadas a issue
  - `fix/*` — correções de defeitos
  - `release/*` — estabilização de release candidate antes de `main`

Todo Pull Request deve utilizar [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md), vincular a issue relacionada (`Related to #...`), explicitar o que está fora do escopo, listar comandos e evidências reais de teste e declarar limitações conhecidas.

---

## 3. Convenções de Commits e Identidade Git

1. **Conventional Commits:** utilize mensagens no formato `<tipo>(<escopo opcional>): <resumo imperativo>` (ex.: `feat(driver): ...`, `fix(host): ...`, `docs(m0): ...`, `ci(m0): ...`, `chore(m0): ...`, `test(protocol): ...`).
2. **Identidade noreply recomendada:** para evitar exposição inadvertida de endereço pessoal em histórico público, configure a identidade local do repositório com seu usuário e endereço `noreply` do GitHub (ex.: `<id>+<usuario>@users.noreply.github.com`).
3. **Assinatura DCO obrigatória (`git commit -s`):** todo novo commit de contribuição deve conter a linha `Signed-off-by: Nome <email>` gerada por `git commit -s` (ver Seção 11).

---

## 4. Separação entre Validação Convencional (CI) e Validação Administrativa

O LumaBridge Display distingue rigorosamente duas trilhas de verificação:

1. **Trilha Convencional (não administrativa, executável em CI hospedado):**
   - Validação de sintaxe de scripts PowerShell, compilação MSVC de suítes C++ independentes de hardware/WDK, testes unitários/componentes deterministicos ou com D3D11 WARP, checagens de higiene documental/licenciamento/segredos e verificação prospectiva de DCO.
   - **Nunca** instala drivers, certificados raiz/confiáveis, serviços, alterações de registro do SO, `bcdedit`, `TestSigning` ou `Secure Boot`.
2. **Trilha Especializada / Administrativa (local ou infraestrutura dedicada Windows 11 x64):**
   - Build WDK completo do pacote `LumaBridgeIddDriver` (`Debug|x64` e `Release|x64`), `InfVerif`, `Inf2Cat`, `DriverPackageValidationTests`, `NvencEncoderTests` (GPU NVIDIA física + `nvEncodeAPI64.dll`), `FrameEndToEndIntegrationTests` (`9/9` E2E multiprocesso), assinatura de teste em staging isolado fora do repositório, instalação PnP em `WUDFHost.exe`, execução do estímulo `D3d11DxgiVSync` em sessão interativa e ensaios prolongados (`Benchmark30s` / `ProlongedStability`).

Contribuições não devem misturar efeitos administrativos em testes unitários, nem afirmar que uma aprovação no CI convencional comprova o comportamento real em `WUDFHost.exe`, GPU física ou distribuição em produção.

---

## 5. Requisitos de Testes

- Utilize exatamente os contratos e comandos documentados em [`windows/driver/tests/README.md`](windows/driver/tests/README.md) e [`windows/host/README.md`](windows/host/README.md).
- Testes novos não devem introduzir flags genéricas para silenciar falhas, enfraquecer asserções existentes ou mascarar erros de hardware/ambiente como `PASS`.
- Scripts operacionais PowerShell devem suportar `-DryRun` sem mutar estado e passar na validação de sintaxe e nos mocks isolados de [`windows/driver/tests/LumaBridgeFunctionalToolingTests.ps1`](windows/driver/tests/LumaBridgeFunctionalToolingTests.ps1).
- Ao informar resultados em PRs, diferencie explicitamente **testes reais**, **testes com D3D11 WARP/mocks**, **execuções `-DryRun`** e **itens não executados por dependência ambiental**.

---

## 6. Requisitos de Documentação

Atualize a documentação correspondente sempre que houver mudança em arquitetura, contratos IPC/FFI/protocolo, matriz de testes, pré-requisitos ou procedimentos de validação:

- Mudanças de arquitetura ou decisões tecnológicas: ADRs em `docs/architecture/` e [`docs/architecture/compatibility-matrix.md`](docs/architecture/compatibility-matrix.md).
- Mudanças em builds, testes ou operação Windows: [`windows/driver/README.md`](windows/driver/README.md), [`windows/host/README.md`](windows/host/README.md), [`windows/driver/tests/README.md`](windows/driver/tests/README.md) e [`docs/setup/windows-idd-functional-validation.md`](docs/setup/windows-idd-functional-validation.md).
- Mudanças de escopo ou riscos: [`docs/planning/UNIVERSAL_ROADMAP.md`](docs/planning/UNIVERSAL_ROADMAP.md) e [`docs/planning/RISK_REGISTER.md`](docs/planning/RISK_REGISTER.md).
- Links Markdown relativos entre documentos devem ser mantidos válidos.

---

## 7. Revisão de Alterações de Segurança

Alterações nas fronteiras abaixo exigem revisão específica explícita no PR:

- Autenticação, DACL/SACL, nível de integridade, `TokenSessionId`, `AuthorizedHostUserSid` ou duplicação de handles (`DuplicateHandle`) no Named Pipe `LBIF` (`FrameTransport.cpp` / `FrameConsumer.cpp`).
- Futuros fluxos criptográficos de pareamento (SPAKE2/QR, mTLS, gerenciamento de chaves/certificados, revogação) e injeção de entrada remota (`M1+`).
- Scripts que manipulam Driver Store (`pnputil`), certificados de teste (`certutil` / `signtool`), registro de dispositivo (`PLUGPLAY_REGKEY_DEVICE`) ou rollback (`finally`).
- Nunca introduza criptografia caseira nem enfraqueça políticas *deny-by-default*.

---

## 8. Tratamento de Informações Sensíveis

É **estritamente proibido** versionar, imprimir em logs de CI ou publicar em issues/PRs:

- Chaves privadas (`.key`, `.pem`, `.pfx`, `.p12`), tokens de acesso, senhas ou credenciais.
- Caminhos pessoais específicos da estação de trabalho (ex.: diretórios de usuário locais), endereços de e-mail pessoais não públicos ou identificadores reais de máquina/certificado.
- SIDs reais de usuários ou thumbprints de certificados pessoais instalados na máquina do mantenedor.
- Capturas de tela, dumps de pixels reais da área de trabalho ou dados pessoais capturados durante sessões de teste.

*Nota:* Identificadores normativos do Windows (como SIDs bem conhecidos `S-1-16-4096`), fixtures sintéticos determinísticos e thumbprints fictícios explicitamente criados em tempo de teste (ex.: `00112233...` ou certificados efêmeros em diretório temporário fora do repositório) são permitidos quando claramente restritos a testes isolados.

---

## 9. Política de Dependências de Terceiros e Licenciamento

O código original do LumaBridge Display é licenciado sob a [**Apache License, Version 2.0**](LICENSE). Toda inclusão ou atualização de dependência de terceiros deve seguir [`docs/planning/LICENSE_COMPLIANCE_REVIEW.md`](docs/planning/LICENSE_COMPLIANCE_REVIEW.md):

- **Faixa Verde (permitida por padrão):** `Apache-2.0`, `MIT`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `Zlib`, `CC0-1.0` / `Unlicense`.
- **Faixa Amarela (revisão obrigatória e vínculo dinâmico quando aplicável):** `MPL-2.0`, `LGPL-2.1+` / `LGPL-3.0` (restrita a desktop via linkagem ou carregamento dinâmico documentado).
- **Faixa Vermelha (proibida nos artefatos distribuídos oficiais):** `GPLv2-only`, `GPLv3` vinculada ao mesmo executável, `AGPL`, binários/DLLs proprietários de terceiros sem autorização expressa de redistribuição e implementações de codecs sujeitas a patentes não licenciadas (ex.: encoders HEVC por software).
- **Obrigações ao incorporar código ou headers de terceiros:**
  1. Preserve integralmente o cabeçalho de copyright e o texto da licença original no arquivo incorporado (Apache-2.0 nunca substitui a licença de um componente de terceiros).
  2. Registre origem verificável, versão, titularidade, obrigações de atribuição e texto exigido em [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) e, quando aplicável, em [`NOTICE`](NOTICE).
  3. Nunca versione `.dll`, `.lib` ou executáveis binários de terceiros nem copie trechos de exemplos externos sem compatibilidade e atribuição comprovadas.

---

## 10. Processo de Reporte de Defeitos

Para reportar bugs ou propor melhorias:

1. Verifique se já existe issue aberta em [GitHub Issues](https://github.com/Altaeir-13/LumaBridge-Display/issues).
2. Abra uma issue utilizando o template adequado em [`.github/ISSUE_TEMPLATE/`](.github/ISSUE_TEMPLATE/bug.yml).
3. Informe ambiente (SO/build Windows ou distro/compositor Linux), commit SHA, passos mínimos para reprodução e logs sanitizados (nunca inclua pixels da tela, segredos, SIDs reais ou caminhos pessoais).

---

## 11. Política de Contribuição DCO (Developer Certificate of Origin — Versão 1.1)

O projeto LumaBridge Display adota o **Developer Certificate of Origin (DCO), Version 1.1**, como política **prospectiva** de certificação de contribuições.

### Texto Oficial do DCO 1.1

Fonte canônica: <https://developercertificate.org/>

```text
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

### Como assinar seus commits (`Signed-off-by`)

Para certificar que suas alterações atendem aos termos do DCO 1.1, inclua a flag `-s` / `--signoff` ao criar commits:

```bash
git commit -s -m "feat(escopo): descricao clara da mudanca"
```

Isso adiciona automaticamente uma linha no final da mensagem do commit:

```text
Signed-off-by: Seu Nome <seu-email-ou-noreply@users.noreply.github.com>
```

Use seu nome real ou identificador público consistente e o endereço de e-mail configurado no Git (recomenda-se o endereço `noreply` do GitHub). Não utilize nomes genéricos anônimos ou pseudônimos incompatíveis com o registro público exigido pela cláusula (d).

### Vigência Prospectiva, Verificação Automatizada e Não Retroatividade

- Esta política aplica-se **exclusivamente aos novos commits de contribuição** produzidos a partir da adoção da governança M0.6 (após o merge commit `23a2804606b02a85d915a55b75663b67bd5af58b` em `dev`).
- **Commits históricos anteriores** à adoção da política permanecem preservados integralmente sem reescrita de histórico e **não** devem ser tratados como falha retroativa por verificações manuais ou automatizadas de DCO.
- Em eventos `pull_request` no CI, [`scripts/ci/check_repo_hygiene.py`](scripts/ci/check_repo_hygiene.py) valida exclusivamente **trailers Git reconhecidos (`Signed-off-by`)** nos commits não mergeados posteriores ao cutoff `23a2804606b02a85d915a55b75663b67bd5af58b` (rejeitando referências inválidas ou faixas incompletas) e verifica a correspondência entre autoria (`name` e `email`) e pelo menos um trailer `Signed-off-by` bem-formado (aceitando múltiplos trailers legítimos). Eventos `push` e `workflow_dispatch` sem faixa DCO fornecida registram verificação de DCO como `SKIPPED` por contrato.

### O que o DCO NÃO é (Distinções Importantes)

- **DCO é uma declaração de conformidade, não autenticação criptográfica ou prova jurídica de identidade:** o trailer `Signed-off-by` atesta o compromisso do contribuidor sob o DCO 1.1 com base nos metadados Git declarados e **não** comprova criptograficamente nem juridicamente a identidade civil do autor.
- **DCO ≠ assinatura criptográfica de commit (GPG/SSH):** `Signed-off-by` é uma declaração formal de autoria e direito de contribuição sob o DCO 1.1; assinatura criptográfica GPG/SSH prova a posse da chave no Git e pode ser usada em conjunto, mas não substitui o trailer `Signed-off-by`.
- **DCO ≠ certificado de assinatura de driver Windows:** nada tem relação com certificados Authenticode, `TestSigning`, EV ou WHQL usados para assinar `LumaBridgeIddDriver.dll` e `.cat`.
- **DCO ≠ Contributor License Agreement (CLA):** o DCO não transfere nem atribui direitos autorais (copyright assignment) a uma entidade terceira; você mantém seus direitos autorais e certifica que o código é contribuído sob a licença aplicável do projeto (`Apache-2.0`).
