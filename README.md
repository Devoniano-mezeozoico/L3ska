# Nocturne v2.0

Firewall, IDS e monitor de rede com interface gráfica em Python/Tkinter.

Desenvolvido por **Matheus Luçolli Schollemberg** para uso exclusivo em ambientes autorizados.

## Sobre

O Nocturne v2.0 é uma ferramenta desktop para Linux que reúne controles básicos de firewall, criação e remoção de regras do Snort, execução de Snort em modo console, captura com TCPDump e diagnóstico com traceroute.

O objetivo do projeto é facilitar tarefas comuns de administração e monitoramento de rede em laboratórios, redes próprias ou infraestruturas nas quais o operador possua autorização.

## Recursos

- Interface gráfica escura feita com Tkinter.
- Verificação automática de ferramentas instaladas.
- Visualização das regras `iptables` da cadeia `OUTPUT`.
- Bloqueio de saída por IP, domínio e porta.
- Permissão de saída por destino, protocolo e porta.
- Remoção de regras `iptables` por número de linha.
- Política padrão `DROP` ou `ACCEPT` para tráfego de saída.
- Persistência de regras com `netfilter-persistent`.
- Visualização, criação e remoção de regras Snort.
- Execução do Snort em tempo real.
- Captura de pacotes com TCPDump.
- Diagnóstico com traceroute.
- Logs locais em `logs/`.

## Requisitos

- Linux
- Python 3.10+
- Permissão de superusuário
- Tkinter
- `iptables`
- `netfilter-persistent`
- `snort`
- `tcpdump`
- `traceroute`

Em Debian/Ubuntu:

```bash
sudo apt update
sudo apt install python3 python3-tk iptables netfilter-persistent snort tcpdump traceroute
Como Executar
sudo python3 nocturne.py
O uso de sudo é necessário porque o programa manipula regras de firewall, executa capturas de rede e acessa arquivos do Snort.

Snort
O projeto espera encontrar regras customizadas em:

/etc/snort/rules/alerta_geral.rules
Caso o arquivo não exista:

sudo touch /etc/snort/rules/alerta_geral.rules
sudo chmod 644 /etc/snort/rules/alerta_geral.rules
O arquivo de configuração usado pelo programa é:

/etc/snort/snort.lua
Se sua instalação usa outro caminho, ajuste o comando no método _iniciar_snort.

Logs
A cada execução, o Nocturne cria um arquivo de log em:

logs/
Formato do arquivo:

nocturne_AAAAMMDD_HHMMSS.log
Aviso Legal
Este projeto executa comandos que alteram regras de firewall e podem interromper a conectividade de rede.

Use somente em máquinas próprias, laboratórios, redes sob sua administração ou ambientes com autorização explícita.

O autor não se responsabiliza por uso indevido, perda de conectividade, bloqueios acidentais ou execução em ambientes não autorizados.

Limitações
Suporte focado em Linux.
Regras Snort criadas pela interface são simples e baseadas em content.
Caminhos do Snort podem variar conforme a distribuição.
A validação de IP/domínio é básica.
A persistência depende do netfilter-persistent.
Melhorias Futuras
Seleção automática de interfaces de rede.
Editor avançado de regras Snort.
Exportação de relatórios.
Perfis de firewall.
Histórico visual de alertas.
Tela de configuração para caminhos do Snort.
Autor
Matheus Luçolli Schollemberg

Projeto Nocturne v2.0 — Firewall, IDS e Monitor de Rede.
