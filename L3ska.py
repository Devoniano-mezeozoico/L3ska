#!/usr/bin/env python3
"""
Nocturne v2.0 — Firewall, IDS e Monitor de Rede
Desenvolvido por Matheus Luçolli Schollemberg
Uso exclusivo em ambientes autorizados.
"""

import tkinter as tk
from tkinter import messagebox, scrolledtext, simpledialog, ttk
import subprocess
import threading
import os
import queue
import signal
import shutil
import logging
import re
from datetime import datetime
from pathlib import Path

# ─── Paleta de cores ──────────────────────────────────────────────────────────
C = {
    "bg":        "#0d0f14",
    "bg2":       "#161922",
    "bg3":       "#1e2330",
    "border":    "#2a2f3d",
    "accent":    "#4fa3e0",
    "accent2":   "#7ec8a0",
    "warn":      "#e0a84f",
    "danger":    "#e05f5f",
    "text":      "#c9d1e0",
    "text2":     "#7a8399",
    "btn":       "#1e2330",
    "btn_hover": "#8e44ad",
    "success":   "#2ecc71",
}

FONTE_MONO  = ("Consolas", 10)
FONTE_TITLE = ("Helvetica", 11, "bold")
FONTE_LABEL = ("Helvetica", 10)
FONTE_SMALL = ("Helvetica", 9)

LOG_DIR = Path(__file__).resolve().parent / "logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / f"nocturne_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("nocturne")


# ─── Verificação de ferramentas ───────────────────────────────────────────────

REQUIRED_TOOLS = ["iptables", "netfilter-persistent", "snort", "tcpdump", "traceroute"]

def verificar_ferramentas() -> dict[str, bool]:
    """Retorna dicionário {ferramenta: disponível}."""
    return {t: shutil.which(t) is not None for t in REQUIRED_TOOLS}


# ─── Utilitários de shell ─────────────────────────────────────────────────────

def executar_comando_shell(cmd: list) -> str:
    """Executa comando, retorna stdout/stderr como string."""
    cmd = [str(a) for a in cmd]
    log.info("CMD: %s", " ".join(cmd))
    try:
        r = subprocess.run(cmd, text=True, capture_output=True, check=False, timeout=30)
        out = (r.stdout + r.stderr).strip()
        if r.returncode != 0:
            log.warning("Código de saída %d: %s", r.returncode, out)
            return f"[Erro {r.returncode}]\n{out}"
        return out or "Executado com sucesso (sem saída)."
    except FileNotFoundError:
        msg = f"Comando '{cmd[0]}' não encontrado."
        log.error(msg)
        return msg
    except subprocess.TimeoutExpired:
        msg = f"Timeout ao executar: {' '.join(cmd)}"
        log.error(msg)
        return msg
    except Exception as e:
        log.exception("Exceção inesperada")
        return f"Exceção: {e}"

def persistir_iptables() -> list[str]:
    """Salva e recarrega regras com netfilter-persistent."""
    resultados = []
    for sub in ["save", "reload"]:
        r = executar_comando_shell(["netfilter-persistent", sub])
        resultados.append(f"netfilter-persistent {sub}:\n{r}")
    return resultados

def validar_ip(ip: str) -> bool:
    padrao = r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$|^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$"
    return bool(re.match(padrao, ip))

def validar_porta(porta: str) -> bool:
    if not porta:
        return True
    return porta.isdigit() and 1 <= int(porta) <= 65535


# ─── Widgets reutilizáveis ────────────────────────────────────────────────────

def botao(parent, texto, comando, cor_fundo=None, bold=False, **kwargs):
    fonte = ("Helvetica", 10, "bold") if bold else FONTE_LABEL
    b = tk.Button(
        parent, text=texto, command=comando,
        bg=cor_fundo or C["btn"], fg=C["text"],
        activebackground=C["btn_hover"], activeforeground=C["text"],
        font=fonte, relief="flat", borderwidth=0,
        cursor="hand2", pady=8, **kwargs,
    )
    b.bind("<Enter>", lambda e: b.config(bg=C["btn_hover"]))
    b.bind("<Leave>", lambda e: b.config(bg=cor_fundo or C["btn"]))
    return b

def label(parent, texto, small=False, cor=None, **kwargs):
    return tk.Label(
        parent, text=texto,
        fg=cor or C["text2"], bg=C["bg"],
        font=FONTE_SMALL if small else FONTE_LABEL, **kwargs,
    )

def entrada(parent, **kwargs):
    return tk.Entry(
        parent, bg=C["bg3"], fg=C["text"],
        insertbackground=C["accent"], relief="flat",
        font=FONTE_MONO, bd=4, **kwargs,
    )

def janela_saida(titulo: str, conteudo: str, parent_win):
    """Abre janela scrollable com conteúdo de texto."""
    win = tk.Toplevel(parent_win)
    win.title(titulo)
    win.configure(bg=C["bg"])
    win.geometry("720x480")
    win.transient(parent_win)
    win.grab_set()

    _barra_titulo(win, titulo)

    st = scrolledtext.ScrolledText(
        win, wrap=tk.WORD, bg=C["bg2"], fg=C["text"],
        font=FONTE_MONO, relief="flat", padx=12, pady=8,
        insertbackground=C["accent"],
    )
    st.pack(padx=12, pady=(0, 12), fill=tk.BOTH, expand=True)
    st.insert(tk.INSERT, conteudo)
    st.configure(state="disabled")

    botao(win, "Fechar", win.destroy).pack(pady=(0, 10))

def _barra_titulo(win, texto):
    bar = tk.Frame(win, bg=C["bg2"], pady=10)
    bar.pack(fill=tk.X)
    tk.Label(bar, text=texto, fg=C["accent"], bg=C["bg2"],
             font=("Helvetica", 11, "bold"), padx=16).pack(side=tk.LEFT)

def separador(parent):
    tk.Frame(parent, height=1, bg=C["border"]).pack(fill=tk.X, padx=8, pady=4)


# ─── Janelas de formulário genéricas ─────────────────────────────────────────

def janela_form(titulo: str, campos: list[dict], callback, parent_win, btn_texto="Aplicar"):
    """
    campos: lista de dicts com 'label', 'default' (opcional), 'var' (nome retornado).
    callback(valores: dict) → None
    """
    win = tk.Toplevel(parent_win)
    win.title(titulo)
    win.configure(bg=C["bg"])
    win.resizable(False, False)
    win.transient(parent_win)
    win.grab_set()

    _barra_titulo(win, titulo)

    frame = tk.Frame(win, bg=C["bg"], padx=20, pady=10)
    frame.pack(fill=tk.BOTH)

    entradas = {}
    for campo in campos:
        label(frame, campo["label"]).pack(anchor="w", pady=(8, 2))
        e = entrada(frame, width=40)
        e.pack(fill=tk.X)
        if "default" in campo:
            e.insert(0, campo["default"])
        entradas[campo["var"]] = e

    def _aplicar():
        valores = {k: v.get().strip() for k, v in entradas.items()}
        callback(valores, win)

    botao(frame, btn_texto, _aplicar, bold=True).pack(fill=tk.X, pady=(16, 8))


# ─── Classe principal da aplicação ───────────────────────────────────────────

class NocturneApp:

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Nocturne v2.0 — Firewall & IDS")
        self.root.configure(bg=C["bg"])
        self.root.geometry("520x920")
        self.root.resizable(False, True)

        # Estado de processos contínuos
        self._proc: dict[str, subprocess.Popen | None] = {
            "snort": None, "tcpdump": None
        }
        self._queues: dict[str, queue.Queue] = {
            "snort": queue.Queue(), "tcpdump": queue.Queue()
        }
        self._output_wins: dict[str, tk.Toplevel | None] = {
            "snort": None, "tcpdump": None
        }
        self._output_texts: dict[str, scrolledtext.ScrolledText | None] = {
            "snort": None, "tcpdump": None
        }
        self._btn_refs: dict[str, tk.Button | None] = {
            "snort": None, "tcpdump": None
        }

        self._status_var = tk.StringVar(value="Pronto.")
        self._tools = verificar_ferramentas()

        self._verificar_root()
        self._construir_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._ao_fechar)
        log.info("Nocturne iniciado. Ferramentas: %s", self._tools)

    # ── Verificações ──────────────────────────────────────────────────────────

    def _verificar_root(self):
        if os.geteuid() != 0:
            messagebox.showerror(
                "Permissão Negada",
                "Execute com sudo para acessar iptables, Snort e TCPDump.",
            )
            self.root.destroy()
            raise SystemExit(1)

    def _ferramenta_ok(self, nome: str) -> bool:
        ok = self._tools.get(nome, False)
        if not ok:
            messagebox.showwarning(
                "Ferramenta ausente",
                f"'{nome}' não encontrado no PATH.\nInstale-o e reinicie o Nocturne.",
                parent=self.root,
            )
            log.warning("Ferramenta ausente: %s", nome)
        return ok

    # ── Construção da UI ──────────────────────────────────────────────────────

    def _construir_ui(self):
        self._cabecalho()
        self._status_bar_topo()
        self._painel_ferramentas()

        nb = ttk.Notebook(self.root)
        nb.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 8))
        self._estilizar_notebook(nb)

        self._aba_iptables(nb)
        self._aba_snort(nb)
        self._aba_rede(nb)

        self._rodape()

    def _cabecalho(self):
        frame = tk.Frame(self.root, bg=C["bg2"], pady=14)
        frame.pack(fill=tk.X)

        # Logo ASCII em miniatura
        ascii_art = (
            "  ⬡  NOCTURNE\n"
            "  Firewall & IDS v2.0"
        )
        tk.Label(frame, text=ascii_art, fg=C["accent"], bg=C["bg2"],
                 font=("Consolas", 13, "bold"), justify=tk.LEFT, padx=16).pack(side=tk.LEFT)

        ts = datetime.now().strftime("%d/%m/%Y %H:%M")
        tk.Label(frame, text=ts, fg=C["text2"], bg=C["bg2"],
                 font=FONTE_SMALL, padx=16).pack(side=tk.RIGHT)

    def _status_bar_topo(self):
        bar = tk.Frame(self.root, bg=C["bg3"], pady=5)
        bar.pack(fill=tk.X, padx=12, pady=(6, 0))
        tk.Label(bar, textvariable=self._status_var, fg=C["accent2"], bg=C["bg3"],
                 font=FONTE_SMALL, padx=8).pack(side=tk.LEFT)

    def _painel_ferramentas(self):
        """Mostra indicadores de disponibilidade de cada ferramenta."""
        frame = tk.Frame(self.root, bg=C["bg"], pady=6)
        frame.pack(fill=tk.X, padx=12)

        tk.Label(frame, text="Ferramentas:", fg=C["text2"], bg=C["bg"],
                 font=FONTE_SMALL).pack(side=tk.LEFT, padx=(0, 8))

        for tool, ok in self._tools.items():
            cor = C["accent2"] if ok else C["danger"]
            ic = "●" if ok else "✕"
            tk.Label(frame, text=f"{ic} {tool}", fg=cor, bg=C["bg"],
                     font=FONTE_SMALL).pack(side=tk.LEFT, padx=6)

    def _estilizar_notebook(self, nb):
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook", background=C["bg"], borderwidth=0)
        style.configure("TNotebook.Tab",
                        background=C["bg3"], foreground=C["text2"],
                        padding=[14, 6], font=FONTE_SMALL)
        style.map("TNotebook.Tab",
                  background=[("selected", C["bg2"])],
                  foreground=[("selected", C["accent"])])

    # ── Aba iptables ──────────────────────────────────────────────────────────

    def _aba_iptables(self, nb):
        frame = tk.Frame(nb, bg=C["bg"], pady=8)
        nb.add(frame, text="  iptables  ")

        secoes = [
            ("Visualização", [
                ("Verificar Regras OUTPUT", self.verificar_regras_iptables),
            ]),
            ("Regras de Saída", [
                ("Bloquear Destino", self.bloquear_saida),
                ("Permitir Destino", self.permitir_saida),
                ("Remover Regra", self.remover_regra_iptables),
            ]),
            ("Política Padrão OUTPUT", [
                ("⛔  Bloquear Tudo (DROP)", self.firewall_bloquear_padrao),
                ("✔  Permitir Tudo (ACCEPT)", self.firewall_permitir_padrao),
            ]),
        ]
        self._renderizar_secoes(frame, secoes)

    # ── Aba Snort ─────────────────────────────────────────────────────────────

    def _aba_snort(self, nb):
        frame = tk.Frame(nb, bg=C["bg"], pady=8)
        nb.add(frame, text="  Snort / IDS  ")

        secoes = [
            ("Regras Snort", [
                ("Verificar Regras", self.verificar_regras_snort),
                ("Criar Regra", self.criar_regra_snort),
                ("Remover Regra", self.remover_regra_snort),
            ]),
        ]
        self._renderizar_secoes(frame, secoes)

        separador(frame)

        self._btn_refs["snort"] = botao(
            frame, "▶  Iniciar Snort", self._toggle_snort,
            cor_fundo=C["bg3"], bold=True,
        )
        self._btn_refs["snort"].pack(fill=tk.X, padx=12, pady=4)

    # ── Aba Rede ─────────────────────────────────────────────────────────────

    def _aba_rede(self, nb):
        frame = tk.Frame(nb, bg=C["bg"], pady=8)
        nb.add(frame, text="  Rede  ")

        secoes = [
            ("Captura e Diagnóstico", [
                ("Traceroute", self.executar_traceroute),
            ]),
        ]
        self._renderizar_secoes(frame, secoes)

        separador(frame)

        self._btn_refs["tcpdump"] = botao(
            frame, "▶  Iniciar TCPDump", self._toggle_tcpdump,
            cor_fundo=C["bg3"], bold=True,
        )
        self._btn_refs["tcpdump"].pack(fill=tk.X, padx=12, pady=4)

    # ── Renderizador de seções de botões ─────────────────────────────────────

    def _renderizar_secoes(self, parent, secoes: list):
        for titulo_sec, botoes in secoes:
            tk.Label(parent, text=titulo_sec.upper(), fg=C["accent2"], bg=C["bg"],
                     font=("Helvetica", 9, "bold")).pack(anchor="w", padx=16, pady=(12, 4))
            for texto, cmd in botoes:
                b = botao(parent, texto, cmd)
                b.pack(fill=tk.X, padx=12, pady=2)

    def _rodape(self):
        tk.Frame(self.root, bg=C["border"], height=1).pack(fill=tk.X)
        frame = tk.Frame(self.root, bg=C["bg"], pady=8)
        frame.pack(fill=tk.X)
        tk.Label(frame, text=f"Log: {LOG_FILE}", fg=C["text2"],
                 bg=C["bg"], font=FONTE_SMALL).pack(side=tk.LEFT, padx=12)
        tk.Label(frame, text="Matheus Luçolli Schollemberg",
                 fg=C["text2"], bg=C["bg"], font=FONTE_SMALL).pack(side=tk.RIGHT, padx=12)

    # ── Utilitários de status ─────────────────────────────────────────────────

    def _set_status(self, msg: str, cor: str = None):
        self._status_var.set(msg)
        log.info("STATUS: %s", msg)

    # ── iptables — Ações ─────────────────────────────────────────────────────

    def verificar_regras_iptables(self):
        self._set_status("Consultando regras iptables OUTPUT...")
        saida = executar_comando_shell(["iptables", "-L", "OUTPUT", "-n", "--line-numbers", "-v"])
        janela_saida("Regras iptables — OUTPUT", saida, self.root)
        self._set_status("Pronto.")

    def bloquear_saida(self):
        def _aplicar(v, win):
            ip = v.get("ip", "")
            dns = v.get("dns", "")
            porta = v.get("porta", "")

            if not ip and not dns:
                messagebox.showerror("Erro", "Preencha ao menos IP ou Domínio.", parent=win)
                return
            if porta and not validar_porta(porta):
                messagebox.showerror("Erro", "Porta inválida (1-65535).", parent=win)
                return
            if ip and not validar_ip(ip):
                messagebox.showerror("Erro", "IP inválido.", parent=win)
                return

            cmds = []
            destinos = [d for d in [ip, dns] if d]
            portas = [porta] if porta else ["80", "443", "53"]

            for dest in destinos:
                for proto in ["tcp", "udp"]:
                    for p in portas:
                        cmds.append(["iptables", "-A", "OUTPUT", "-p", proto,
                                      "-d", dest, "--dport", p, "-j", "DROP"])

            self._set_status(f"Aplicando {len(cmds)} regra(s) de bloqueio...")
            resultados = [executar_comando_shell(c) for c in cmds]
            resultados += persistir_iptables()

            janela_saida("Resultado — Bloqueio", "\n\n".join(
                f"{'  '.join(c)}:\n{r}" for c, r in zip(cmds, resultados)
            ), self.root)
            win.destroy()
            self._set_status("Bloqueio aplicado.")

        janela_form(
            "Bloquear Saída Específica",
            [
                {"label": "IP a bloquear (ou deixe em branco):", "var": "ip"},
                {"label": "Domínio a bloquear (ou deixe em branco):", "var": "dns"},
                {"label": "Porta específica (em branco = bloqueia 80,443,53):", "var": "porta"},
            ],
            _aplicar, self.root, btn_texto="Aplicar Bloqueio",
        )

    def permitir_saida(self):
        def _aplicar(v, win):
            destino = v.get("destino", "")
            protocolo = v.get("protocolo", "all").lower()
            porta = v.get("porta", "")

            if not destino:
                messagebox.showerror("Erro", "Destino obrigatório.", parent=win)
                return
            if protocolo not in ["tcp", "udp", "icmp", "all"]:
                messagebox.showerror("Erro", "Protocolo inválido. Use: tcp, udp, icmp, all.", parent=win)
                return
            if porta and not validar_porta(porta):
                messagebox.showerror("Erro", "Porta inválida.", parent=win)
                return

            cmd = ["iptables", "-A", "OUTPUT"]
            if protocolo != "all":
                cmd.extend(["-p", protocolo])
            cmd.extend(["-d", destino])
            if porta and protocolo in ["tcp", "udp"]:
                cmd.extend(["--dport", porta])
            cmd.extend(["-j", "ACCEPT"])

            self._set_status(f"Permitindo saída para {destino}...")
            r = executar_comando_shell(cmd)
            resultados = [f"{' '.join(cmd)}:\n{r}"] + persistir_iptables()
            janela_saida("Resultado — Permissão", "\n\n".join(resultados), self.root)
            win.destroy()
            self._set_status("Permissão aplicada.")

        janela_form(
            "Permitir Saída Específica",
            [
                {"label": "IP ou Domínio de destino:", "var": "destino"},
                {"label": "Protocolo (tcp, udp, icmp, all):", "var": "protocolo", "default": "all"},
                {"label": "Porta de destino (em branco = qualquer):", "var": "porta"},
            ],
            _aplicar, self.root, btn_texto="Aplicar Permissão",
        )

    def remover_regra_iptables(self):
        saida_atual = executar_comando_shell(["iptables", "-L", "OUTPUT", "-n", "--line-numbers"])

        def _aplicar(v, win):
            numero = v.get("numero", "")
            if not numero.isdigit() or int(numero) <= 0:
                messagebox.showerror("Erro", "Número de linha inválido.", parent=win)
                return
            self._set_status(f"Removendo regra #{numero}...")
            r = executar_comando_shell(["iptables", "-D", "OUTPUT", numero])
            resultados = [f"iptables -D OUTPUT {numero}:\n{r}"] + persistir_iptables()
            janela_saida("Resultado — Remoção", "\n\n".join(resultados), self.root)
            win.destroy()
            self._set_status(f"Regra #{numero} removida.")

        win = tk.Toplevel(self.root)
        win.title("Remover Regra iptables OUTPUT")
        win.configure(bg=C["bg"])
        win.transient(self.root)
        win.grab_set()
        _barra_titulo(win, "Remover Regra iptables OUTPUT")

        frame = tk.Frame(win, bg=C["bg"], padx=16, pady=8)
        frame.pack(fill=tk.BOTH)

        label(frame, "Regras atuais (OUTPUT):").pack(anchor="w", pady=(4, 2))
        st = scrolledtext.ScrolledText(frame, height=14, width=72,
                                        bg=C["bg2"], fg=C["text"], font=FONTE_MONO, relief="flat")
        st.insert(tk.END, saida_atual)
        st.configure(state="disabled")
        st.pack(pady=(0, 8))

        label(frame, "Número da regra a remover:").pack(anchor="w", pady=(4, 2))
        e_num = entrada(frame, width=10)
        e_num.pack(anchor="w")

        def _ok():
            _aplicar({"numero": e_num.get().strip()}, win)

        botao(frame, "Remover", _ok, bold=True).pack(fill=tk.X, pady=(14, 8))

    def firewall_bloquear_padrao(self):
        if not messagebox.askyesno(
            "Confirmar — Bloquear Tudo (OUTPUT)",
            "Isso vai:\n"
            "1. Limpar todas as regras OUTPUT.\n"
            "2. Permitir loopback e conexões estabelecidas.\n"
            "3. Adicionar DROP no final (bloquear todo o restante).\n\n"
            "Você precisará adicionar regras de ACCEPT manualmente.\n\nContinuar?",
            icon="warning", parent=self.root,
        ):
            return

        cmds = [
            ["iptables", "-F", "OUTPUT"],
            ["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
            ["iptables", "-A", "OUTPUT", "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
            ["iptables", "-A", "OUTPUT", "-j", "DROP"],
        ]
        self._set_status("Aplicando política DROP no OUTPUT...")
        resultados = [executar_comando_shell(c) for c in cmds]
        resultados += persistir_iptables()
        janela_saida("Resultado — Bloqueio Padrão OUTPUT",
                     "\n\n".join(f"{' '.join(c)}:\n{r}" for c, r in zip(cmds, resultados)),
                     self.root)
        self._set_status("Política DROP aplicada.")

    def firewall_permitir_padrao(self):
        if not messagebox.askyesno(
            "Confirmar — Permitir Tudo (OUTPUT)",
            "Isso vai:\n"
            "1. Limpar todas as regras OUTPUT.\n"
            "2. Definir política OUTPUT como ACCEPT.\n\n"
            "Qualquer bloqueio anterior será removido.\n\nContinuar?",
            parent=self.root,
        ):
            return

        cmds = [
            ["iptables", "-F", "OUTPUT"],
            ["iptables", "-P", "OUTPUT", "ACCEPT"],
        ]
        self._set_status("Aplicando política ACCEPT no OUTPUT...")
        resultados = [executar_comando_shell(c) for c in cmds]
        resultados += persistir_iptables()
        janela_saida("Resultado — Permissão Padrão OUTPUT",
                     "\n\n".join(f"{' '.join(c)}:\n{r}" for c, r in zip(cmds, resultados)),
                     self.root)
        self._set_status("Política ACCEPT aplicada.")

    # ── Snort — Regras ────────────────────────────────────────────────────────

    SNORT_RULES_FILE = Path("/etc/snort/rules/alerta_geral.rules")

    def _ler_regras_snort(self) -> list[str]:
        try:
            return self.SNORT_RULES_FILE.read_text().splitlines(keepends=True)
        except FileNotFoundError:
            messagebox.showerror("Erro", f"Arquivo não encontrado:\n{self.SNORT_RULES_FILE}", parent=self.root)
            return []

    def verificar_regras_snort(self):
        linhas = self._ler_regras_snort()
        conteudo = "".join(linhas) if linhas else "Nenhuma regra encontrada."
        janela_saida("Regras Snort — alerta_geral.rules", conteudo, self.root)

    def criar_regra_snort(self):
        # Calcular próximo SID
        linhas = self._ler_regras_snort()
        sids = []
        for l in linhas:
            m = re.search(r"sid:(\d+)", l)
            if m:
                sids.append(int(m.group(1)))
        prox_sid = max(sids) + 1 if sids else 1000001

        def _aplicar(v, win):
            padrao = v.get("padrao", "")
            msg = v.get("msg", "")
            if not padrao or not msg:
                messagebox.showerror("Erro", "Preencha todos os campos.", parent=win)
                return

            padrao_esc = padrao.replace('"', '\\"').replace(";", "\\;")
            msg_esc = msg.replace('"', '\\"')
            regra = (
                f'alert tcp any any -> any any '
                f'(content:"{padrao_esc}"; msg:"{msg_esc}"; '
                f'sid:{prox_sid}; rev:1;)\n'
            )
            try:
                with self.SNORT_RULES_FILE.open("a") as f:
                    f.write(regra)
                log.info("Regra Snort criada: SID=%d", prox_sid)
                messagebox.showinfo("Sucesso",
                    f"Regra adicionada (SID {prox_sid}).\nReinicie o Snort para aplicar.",
                    parent=win)
                win.destroy()
                self._set_status(f"Regra Snort SID {prox_sid} criada.")
            except Exception as e:
                messagebox.showerror("Erro", f"Falha ao salvar: {e}", parent=win)

        janela_form(
            "Criar Regra Snort",
            [
                {"label": f"Palavra-chave a detectar (próximo SID: {prox_sid}):", "var": "padrao"},
                {"label": "Mensagem do alerta:", "var": "msg",
                 "default": "[ALERTA] Palavra-chave detectada"},
            ],
            _aplicar, self.root, btn_texto="Criar Regra",
        )

    def remover_regra_snort(self):
        linhas = self._ler_regras_snort()
        if not linhas:
            return

        win = tk.Toplevel(self.root)
        win.title("Remover Regra Snort")
        win.configure(bg=C["bg"])
        win.transient(self.root)
        win.grab_set()
        _barra_titulo(win, "Remover Regra — alerta_geral.rules")

        frame = tk.Frame(win, bg=C["bg"], padx=16, pady=8)
        frame.pack(fill=tk.BOTH, expand=True)

        label(frame, "Regras disponíveis:").pack(anchor="w")
        st = scrolledtext.ScrolledText(frame, height=14, width=80,
                                        bg=C["bg2"], fg=C["text"], font=FONTE_MONO, relief="flat")
        for i, l in enumerate(linhas):
            st.insert(tk.END, f"{i+1:>3}: {l}")
        st.configure(state="disabled")
        st.pack(pady=(4, 8))

        label(frame, "Número da regra a remover:").pack(anchor="w")
        e = entrada(frame, width=8)
        e.pack(anchor="w")

        def _remover():
            val = e.get().strip()
            if not val.isdigit():
                messagebox.showerror("Erro", "Digite um número válido.", parent=win)
                return
            n = int(val)
            if not (1 <= n <= len(linhas)):
                messagebox.showerror("Erro", f"Fora do intervalo (1-{len(linhas)}).", parent=win)
                return
            removida = linhas.pop(n - 1)
            try:
                self.SNORT_RULES_FILE.write_text("".join(linhas))
                log.info("Regra Snort removida: %s", removida.strip())
                messagebox.showinfo("Sucesso",
                    f"Regra {n} removida.\nReinicie o Snort para aplicar.", parent=win)
                win.destroy()
                self._set_status(f"Regra Snort #{n} removida.")
            except Exception as ex:
                messagebox.showerror("Erro", f"Falha ao salvar: {ex}", parent=win)

        botao(frame, "Remover Selecionada", _remover, bold=True).pack(fill=tk.X, pady=(12, 8))

    # ── Processos contínuos (Snort / TCPDump) ─────────────────────────────────

    def _toggle_snort(self):
        if self._proc["snort"] and self._proc["snort"].poll() is None:
            self._parar_processo("snort")
        else:
            self._iniciar_snort()

    def _toggle_tcpdump(self):
        if self._proc["tcpdump"] and self._proc["tcpdump"].poll() is None:
            self._parar_processo("tcpdump")
        else:
            self._iniciar_tcpdump()

    def _iniciar_snort(self):
        if not self._ferramenta_ok("snort"):
            return
        iface = simpledialog.askstring("Interface", "Interface para Snort (ex: eth0):", parent=self.root)
        if not iface:
            return
        cmd = ["snort", "-c", "/etc/snort/snort.lua", "-i", iface, "-A", "console"]
        self._iniciar_processo("snort", cmd, f"Snort — {iface}", "▶  Iniciar Snort", "■  Parar Snort")

    def _iniciar_tcpdump(self):
        if not self._ferramenta_ok("tcpdump"):
            return
        iface = simpledialog.askstring("Interface", "Interface para TCPDump (ex: eth0, any):", parent=self.root)
        if not iface:
            return
        ip_filtro = simpledialog.askstring("Filtro IP", "IP para filtrar (em branco = todos):", parent=self.root)

        cmd = ["tcpdump", "-i", iface, "-n", "-l", "--immediate-mode"]
        if ip_filtro:
            cmd.extend(["host", ip_filtro])
        titulo = f"TCPDump — {iface}" + (f" | {ip_filtro}" if ip_filtro else "")
        self._iniciar_processo("tcpdump", cmd, titulo, "▶  Iniciar TCPDump", "■  Parar TCPDump")

    def _iniciar_processo(self, nome: str, cmd: list, titulo: str, txt_iniciar: str, txt_parar: str):
        """Genérico para Snort e TCPDump."""
        self._set_status(f"Iniciando {nome}...")

        # Criar ou reutilizar janela de saída
        win = self._output_wins.get(nome)
        if win is None or not win.winfo_exists():
            win = tk.Toplevel(self.root)
            win.title(titulo)
            win.geometry("760x520")
            win.configure(bg=C["bg"])

            st = scrolledtext.ScrolledText(win, wrap=tk.WORD, bg=C["bg2"], fg=C["accent2"],
                                            font=FONTE_MONO, relief="flat", padx=10, pady=8)
            st.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            def _fechar():
                self._parar_processo(nome, interno=True)
                w = self._output_wins.get(nome)
                if w and w.winfo_exists():
                    w.destroy()
                self._output_wins[nome] = None
                self._output_texts[nome] = None

            win.protocol("WM_DELETE_WINDOW", _fechar)
            self._output_wins[nome] = win
            self._output_texts[nome] = st
        else:
            st = self._output_texts[nome]
            st.config(state=tk.NORMAL)
            st.delete(1.0, tk.END)
            st.config(state=tk.DISABLED)
            win.title(titulo)

        st.config(state=tk.NORMAL)
        st.insert(tk.END, f"[{datetime.now():%H:%M:%S}] Iniciando: {' '.join(cmd)}\n\n")
        st.config(state=tk.DISABLED)

        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, universal_newlines=True,
            )
        except FileNotFoundError:
            messagebox.showerror("Erro", f"'{cmd[0]}' não encontrado.", parent=self.root)
            self._set_status("Erro ao iniciar.")
            return
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao iniciar {nome}: {e}", parent=self.root)
            self._set_status("Erro ao iniciar.")
            return

        self._proc[nome] = proc
        q = self._queues[nome]

        threading.Thread(
            target=self._ler_saida_processo,
            args=(proc, q, nome), daemon=True,
        ).start()

        btn = self._btn_refs.get(nome)
        if btn:
            btn.config(text=txt_parar, command=lambda: self._parar_processo(nome))

        self._atualizar_widget_texto(nome, txt_iniciar, txt_parar)
        self._set_status(f"{nome.capitalize()} em execução.")

    def _ler_saida_processo(self, proc, q: queue.Queue, nome: str):
        try:
            for line in iter(proc.stdout.readline, ""):
                q.put(line)
            proc.stdout.close()
            proc.wait()
        except Exception as e:
            q.put(f"[Erro de leitura: {e}]\n")
        finally:
            q.put(None)

    def _atualizar_widget_texto(self, nome: str, txt_iniciar: str, txt_parar: str):
        st = self._output_texts.get(nome)
        q = self._queues[nome]
        proc = self._proc.get(nome)
        win = self._output_wins.get(nome)

        if st is None or (win and not win.winfo_exists()):
            return

        try:
            line = q.get_nowait()
        except queue.Empty:
            line = "EMPTY"

        if line is None:
            st.config(state=tk.NORMAL)
            st.insert(tk.END, f"\n[{datetime.now():%H:%M:%S}] — Processo encerrado.\n")
            st.see(tk.END)
            st.config(state=tk.DISABLED)
            self._parar_processo(nome, interno=True)
            return
        elif line != "EMPTY":
            st.config(state=tk.NORMAL)
            st.insert(tk.END, line)
            st.see(tk.END)
            st.config(state=tk.DISABLED)

        if proc and proc.poll() is None and win and win.winfo_exists():
            win.after(80, lambda: self._atualizar_widget_texto(nome, txt_iniciar, txt_parar))
        elif not q.empty():
            win.after(10, lambda: self._atualizar_widget_texto(nome, txt_iniciar, txt_parar))

    def _parar_processo(self, nome: str, interno: bool = False):
        proc = self._proc.get(nome)
        if proc and proc.poll() is None:
            try:
                if nome == "tcpdump":
                    os.kill(proc.pid, signal.SIGINT)
                    proc.wait(timeout=5)
                else:
                    proc.terminate()
                    proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            except Exception:
                proc.kill()
            finally:
                self._proc[nome] = None

        q = self._queues[nome]
        if q.empty():
            q.put(None)

        btn = self._btn_refs.get(nome)
        if btn:
            txt_iniciar = "▶  Iniciar Snort" if nome == "snort" else "▶  Iniciar TCPDump"
            cmd_fn = self._toggle_snort if nome == "snort" else self._toggle_tcpdump
            btn.config(text=txt_iniciar, command=cmd_fn, state=tk.NORMAL)

        if not interno:
            self._set_status(f"{nome.capitalize()} parado.")
            log.info("%s parado pelo usuário.", nome.capitalize())

    # ── Traceroute ────────────────────────────────────────────────────────────

    def executar_traceroute(self):
        destino = simpledialog.askstring("Traceroute", "IP ou hostname de destino:", parent=self.root)
        if not destino:
            return

        self._set_status(f"Executando traceroute para {destino}...")
        saida = executar_comando_shell(["traceroute", destino])
        if "não encontrado" in saida or "not found" in saida:
            self._set_status("traceroute ausente — tentando tracepath...")
            saida = executar_comando_shell(["tracepath", destino])
        janela_saida(f"Traceroute → {destino}", saida, self.root)
        self._set_status("Traceroute concluído.")

    # ── Encerramento ──────────────────────────────────────────────────────────

    def _ao_fechar(self):
        for nome in ["snort", "tcpdump"]:
            self._parar_processo(nome, interno=True)
        if messagebox.askokcancel("Sair", "Encerrar o Nocturne?", parent=self.root):
            log.info("Nocturne encerrado pelo usuário.")
            self.root.destroy()

    def run(self):
        self.root.mainloop()


# ─── Ponto de entrada ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = NocturneApp()
    app.run()