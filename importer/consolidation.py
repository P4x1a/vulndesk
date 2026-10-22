"""Consolidação de relatórios Greenbone/OpenVAS (GMP) em ações de correção.

Porta para Python a lógica da ferramenta de triagem (hoje em JavaScript):
agrupa achados repetidos em ações, atribui a equipe responsável por regras e
calcula prioridade, prazo e situação de SLA. É a mesma lógica validada contra o
scan de Canoas, para que o backend produza exatamente as mesmas ações que a
ferramenta manual produzia — mas de forma automática.
"""
from __future__ import annotations
import re
import datetime as dt
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from typing import Any

SEV = ["Critical", "High", "Medium", "Low"]
SEV_PT = {"Critical": "Crítica", "High": "Alta", "Medium": "Média", "Low": "Baixa"}
PRI = {"Critical": "P1", "High": "P2", "Medium": "P3", "Low": "P4"}

PRODUCT_NAMES = {
    "php:php": "PHP", "apache:http_server": "Apache HTTP Server", "openssl:openssl": "OpenSSL",
    "lighttpd:lighttpd": "lighttpd", "microsoft:internet_information_services": "Microsoft IIS",
    "nginx:nginx": "nginx", "f5:nginx": "nginx", "oracle:mysql": "MySQL", "mysql:mysql": "MySQL",
    "openbsd:openssh": "OpenSSH", "jquery:jquery": "jQuery", "apache:tomcat": "Apache Tomcat",
    "oracle:jre": "Java (JRE)", "samba:samba": "Samba", "isc:bind": "BIND",
    "postgresql:postgresql": "PostgreSQL", "microsoft:sql_server": "Microsoft SQL Server",
    "wordpress:wordpress": "WordPress", "vmware:esxi": "VMware ESXi", "mariadb:mariadb": "MariaDB",
    "proftpd:proftpd": "ProFTPD", "exim:exim": "Exim", "zabbix:zabbix": "Zabbix", "grafana:grafana": "Grafana",
}

# Produtos reconhecidos pelo nome da vulnerabilidade quando o scanner não traz CPE.
NAME_PRODUCTS = [
    (re.compile(r"^PHP\b", re.I), "php:php", "PHP"),
    (re.compile(r"^HP Integrated Lights-Out|\biLO\b"), "hp:ilo", "firmware do HP iLO"),
    (re.compile(r"^Intel Active Management Technology|Intel AMT", re.I), "intel:amt", "firmware Intel AMT / ME"),
    (re.compile(r"^jQuery\b", re.I), "jquery:jquery", "jQuery"),
    (re.compile(r"^Lighttpd\b", re.I), "lighttpd:lighttpd", "lighttpd"),
    (re.compile(r"^Apache HTTP Server|^Apache httpd", re.I), "apache:http_server", "Apache HTTP Server"),
    (re.compile(r"^OpenSSL\b", re.I), "openssl:openssl", "OpenSSL"),
    (re.compile(r"^OpenSSH\b", re.I), "openbsd:openssh", "OpenSSH"),
    (re.compile(r"^phpMyAdmin\b", re.I), "phpmyadmin:phpmyadmin", "phpMyAdmin"),
    (re.compile(r"^Apache Tomcat\b", re.I), "apache:tomcat", "Apache Tomcat"),
    (re.compile(r"^nginx\b", re.I), "nginx:nginx", "nginx"),
    (re.compile(r"^Dell (EMC )?iDRAC", re.I), "dell:idrac", "firmware do Dell iDRAC"),
    (re.compile(r"^Samba\b", re.I), "samba:samba", "Samba"),
    (re.compile(r"^WordPress\b", re.I), "wordpress:wordpress", "WordPress"),
    (re.compile(r"^Microsoft IIS", re.I), "microsoft:internet_information_services", "Microsoft IIS"),
]

# Base de conhecimento: texto de ação em português para os achados mais comuns.
KB = [
    (re.compile(r"End of Life|\bEOL\b", re.I), lambda a: f"Migrar {a.produto_nome or 'o software/sistema'} para uma versão ainda suportada pelo fabricante. A versão instalada não recebe mais correções de segurança."),
    (re.compile(r"ICMP Timestamp", re.I), lambda a: "Bloquear ICMP Timestamp Request (tipo 13) e Timestamp Reply (tipo 14) no firewall do host ou na borda do segmento."),
    (re.compile(r"TCP Timestamps", re.I), lambda a: "Desabilitar TCP timestamps. Linux: sysctl net.ipv4.tcp_timestamps=0. Windows: netsh int tcp set global timestamps=disabled."),
    (re.compile(r"Telnet", re.I), lambda a: "Desativar o serviço Telnet e usar SSH (v2) para administração remota. Sem suporte a SSH, restringir o acesso por ACL à rede de gerência."),
    (re.compile(r"SSLv2 and SSLv3", re.I), lambda a: "Desabilitar SSLv2 e SSLv3 no serviço, mantendo apenas TLS 1.2 e TLS 1.3."),
    (re.compile(r"TLSv1\.0 and TLSv1\.1", re.I), lambda a: "Desabilitar TLS 1.0 e TLS 1.1, mantendo apenas TLS 1.2 e TLS 1.3."),
    (re.compile(r"Certificate Expired", re.I), lambda a: "Renovar o certificado expirado e instalá-lo no serviço. Incluir no controle de vencimentos."),
    (re.compile(r"RSA keys less than 2048", re.I), lambda a: "Reemitir o certificado (e a cadeia) com chave RSA de 2048 bits ou mais."),
    (re.compile(r"Weak Signature Algorithm", re.I), lambda a: "Reemitir o certificado assinado com SHA-256 ou superior (substituir SHA-1/MD5)."),
    (re.compile(r"Diffie-Hellman|DH Group", re.I), lambda a: "Configurar grupos Diffie-Hellman de 2048 bits ou mais, ou priorizar ECDHE."),
    (re.compile(r"Vulnerable Cipher Suites|Weak Cipher Suites|Cipher Suites", re.I), lambda a: "Remover cipher suites fracas ou vulneráveis (RC4, 3DES, DES, NULL, EXPORT, anon) e priorizar AES-GCM/ChaCha20 com ECDHE."),
    (re.compile(r"Weak MAC Algorithm.*SSH", re.I), lambda a: "Remover MACs fracos do SSH (hmac-md5, hmac-sha1-96, umac-64) e manter hmac-sha2-256/512."),
    (re.compile(r"Weak Key Exchange.*SSH", re.I), lambda a: "Remover algoritmos de troca de chaves fracos do SSH (group1-sha1, group-exchange-sha1, group14-sha1)."),
    (re.compile(r"Weak Encryption Algorithm.*SSH", re.I), lambda a: "Remover cifras fracas do SSH (arcfour, 3des-cbc, blowfish-cbc, *-cbc) e manter aes*-ctr/gcm e chacha20-poly1305."),
    (re.compile(r"Weak Host Key Algorithm.*SSH", re.I), lambda a: "Desabilitar chaves de host ssh-dss/ssh-rsa (SHA-1) e usar ed25519 ou rsa-sha2-256/512."),
    (re.compile(r"Cleartext Transmission|Cleartext Login", re.I), lambda a: "Publicar o login apenas em HTTPS e redirecionar todo HTTP para HTTPS (com HSTS quando possível)."),
    (re.compile(r"TRACE/TRACK|Debugging Methods", re.I), lambda a: "Desabilitar os métodos HTTP TRACE e TRACK no servidor web."),
    (re.compile(r"Source Control Management|SCM\)? Files", re.I), lambda a: "Remover diretórios de versionamento (.git, .svn, .hg) do diretório publicado ou bloquear o acesso. Avaliar exposição de código/credenciais."),
    (re.compile(r"HttpOnly", re.I), lambda a: "Definir o atributo HttpOnly (e Secure) nos cookies de sessão da aplicação."),
    (re.compile(r"Secure' Cookie|Secure Cookie", re.I), lambda a: "Definir o atributo Secure nos cookies servidos via HTTPS."),
    (re.compile(r"DCE/RPC and MSRPC Services Enumeration", re.I), lambda a: "Restringir o acesso às portas RPC (135 e faixa dinâmica) por firewall, liberando só para gerência e servidores que precisam."),
    (re.compile(r"Dahua|Multiple Devices Information Disclosure|Amcrest|Hikvision", re.I), lambda a: "Atualizar o firmware dos dispositivos, trocar senhas de administrador (podem ter sido expostas) e isolar os equipamentos em VLAN própria."),
    (re.compile(r"phpinfo\(\)", re.I), lambda a: "Remover do servidor os arquivos que chamam phpinfo() (info.php, test.php). Eles expõem configuração, caminhos e versões."),
    (re.compile(r"ICMP Netmask", re.I), lambda a: "Bloquear ICMP Address Mask Request/Reply (tipos 17 e 18) no host ou no firewall."),
    (re.compile(r"Renegotiation DoS", re.I), lambda a: "Desabilitar a renegociação TLS iniciada pelo cliente no serviço."),
    (re.compile(r"Untrusted|Dangerous Certificate Authority", re.I), lambda a: "Substituir o certificado por um de CA confiável e remover a CA não confiável da cadeia."),
    (re.compile(r"POODLE|SSLv3 Protocol CBC", re.I), lambda a: "Desabilitar SSLv3 no serviço (resolve o POODLE), mantendo apenas TLS 1.2 e 1.3."),
]


def _txt(el, *path):
    for p in path:
        if el is None:
            return ""
        el = el.find(p)
    return (el.text or "").strip() if el is not None else ""


def _own_text(el):
    return (el.text or "").strip() if el is not None else ""


def parse_tags(s: str) -> dict:
    out, marks = {}, []
    for m in re.finditer(r"(?:^|\|)([a-z_]+)=", s):
        marks.append((m.group(1), m.start(), m.end()))
    for i, (k, _start, vstart) in enumerate(marks):
        end = marks[i + 1][1] if i + 1 < len(marks) else len(s)
        out[k] = re.sub(r"\s+", " ", s[vstart:end]).strip()
    return out


def product_info(cpe: str | None):
    if not cpe:
        return None
    body = re.sub(r"^cpe:/[aoh]:", "", cpe).split(":")
    key = ":".join(body[:2])
    nome = PRODUCT_NAMES.get(key) or re.sub(r"_", " ", (body[1] if len(body) > 1 else body[0])).title()
    tipo_m = re.match(r"^cpe:/([aoh])", cpe)
    return {"cpe": cpe, "key": key, "nome": nome, "versao": body[2] if len(body) > 2 else "",
            "tipo": tipo_m.group(1) if tipo_m else ""}


@dataclass
class Finding:
    nome: str = ""
    oid: str = ""
    familia: str = ""
    threat: str = ""
    sev: float = 0.0
    qod: int = 0
    ip: str = ""
    porta: str = ""
    solucao: str = ""
    sol_tipo: str = ""
    resumo: str = ""
    impacto: str = ""
    cves: list = field(default_factory=list)
    urls: list = field(default_factory=list)
    produto: str | None = None
    evidencia: str = ""


def parse_report_file(path: str) -> dict:
    return _parse_root(ET.parse(path).getroot())


def parse_report_string(xml_text: str) -> dict:
    return _parse_root(ET.fromstring(xml_text))


def _parse_root(root) -> dict:
    if root.tag != "report":
        raise ValueError("Raiz não é <report>: não parece um relatório GMP/OpenVAS em XML.")
    inner = root.find("report")
    if inner is None:
        inner = root
    results_el = inner.find("results")
    if results_el is None:
        raise ValueError("Relatório sem a seção <results>.")
    task_el = inner.find("task") if inner.find("task") is not None else root.find("task")
    meta = {
        "tarefa": _txt(task_el, "name") or _txt(root, "name"),
        "alvo": _txt(task_el, "target", "name"),
        "scan_start": _txt(inner, "scan_start"),
        "scan_end": _txt(inner, "scan_end"),
        "hosts_scan": int(_txt(inner, "hosts", "count") or 0),
        "filtro": _txt(inner, "filters", "term"),
        "gmp": _txt(inner, "gmp", "version"),
    }
    hosts = {}
    for h in inner.findall("host"):
        ip = _txt(h, "ip")
        if not ip:
            continue
        d = {}
        for det in h.findall("detail"):
            n = _txt(det, "name")
            if n in ("hostname", "best_os_txt", "best_os_cpe") and n not in d:
                d[n] = _txt(det, "value")
        hosts[ip] = {"ip": ip, "hostname": d.get("hostname", ""), "so": d.get("best_os_txt", "")}
    findings = []
    for r in results_el.findall("result"):
        threat = _txt(r, "threat")
        if threat not in SEV:
            continue
        nvt = r.find("nvt")
        tags = parse_tags(_txt(nvt, "tags"))
        sol_el = nvt.find("solution") if nvt is not None else None
        refs = nvt.findall("refs/ref") if nvt is not None else []
        host_el = r.find("host")
        produto = None
        det_res = r.find("detection/result")
        if det_res is not None:
            for det in det_res.findall("details/detail"):
                if _txt(det, "name") == "product":
                    produto = _txt(det, "value")
        f = Finding(
            nome=_txt(r, "name") or _txt(nvt, "name"),
            oid=nvt.get("oid") if nvt is not None else "",
            familia=_txt(nvt, "family"),
            threat=threat,
            sev=float(_txt(r, "severity") or 0),
            qod=int(_txt(r, "qod", "value") or 0),
            ip=_own_text(host_el),
            porta=_txt(r, "port"),
            solucao=re.sub(r"\s+", " ", (sol_el.text if sol_el is not None and sol_el.text else tags.get("solution", ""))).strip(),
            sol_tipo=(sol_el.get("type") if sol_el is not None else tags.get("solution_type", "")) or "",
            resumo=tags.get("summary", ""),
            impacto=tags.get("impact", ""),
            cves=sorted({x.get("id") for x in refs if x.get("type") == "cve"}),
            urls=[x.get("id") for x in refs if x.get("type") == "url"][:4],
            produto=produto,
            evidencia=(_txt(r, "description") or "")[:1500],
        )
        findings.append(f)
        if f.ip and f.ip not in hosts:
            hosts[f.ip] = {"ip": f.ip, "hostname": "", "so": ""}
    return {"meta": meta, "hosts": hosts, "findings": findings}


def _ip_key(ip: str) -> str:
    return ".".join(p.zfill(3) for p in ip.split("."))


def _acao_generica(a, top: Finding) -> str:
    prod = f" para {a.produto_nome}" if a.produto_nome else ""
    base = {
        "VendorFix": f"Aplicar a atualização ou correção do fabricante{prod}.",
        "Mitigation": "Aplicar a mitigação recomendada (ajuste de configuração ou restrição de acesso).",
        "Workaround": "Aplicar o contorno recomendado até haver correção definitiva.",
        "WillNotFix": "O fabricante não vai corrigir: substituir o componente ou isolar o host e registrar o risco aceito.",
        "NoneAvailable": "Não há correção disponível: restringir o acesso ao serviço e monitorar.",
    }.get(top.sol_tipo, "Avaliar a vulnerabilidade e aplicar a correção recomendada.")
    orig = (top.solucao or "").strip()
    if orig:
        orig = orig[:257] + "…" if len(orig) > 260 else orig
        return f"{base} Orientação do scanner: {orig}"
    return base


@dataclass
class Action:
    key: str
    id: str = ""
    titulo: str = ""
    acao: str = ""
    threat: str = ""
    sev: float = 0.0
    prioridade: str = ""
    familia: str = ""
    produto_nome: str = ""
    produto_key: str = ""
    hosts: list = field(default_factory=list)
    portas: dict = field(default_factory=dict)
    cves: list = field(default_factory=list)
    nvts: list = field(default_factory=list)
    resumo: str = ""
    solucao: str = ""
    sol_tipo: str = ""
    team: str = ""
    team_auto: str = ""


def consolidate(parsed: dict) -> list[Action]:
    findings = parsed["findings"]
    groups: dict[str, dict] = {}
    for f in findings:
        pi = product_info(f.produto)
        key = None
        gpi = None
        nome_low = f.nome.lower()
        eol = bool(re.search(r"end of life|\beol\b", f.nome, re.I)) and not re.search(r"operating system", f.nome, re.I)
        fixavel = f.sol_tipo == "VendorFix" or eol
        if fixavel and pi and pi["tipo"] != "o" and ":ietf:" not in pi["cpe"] and pi["nome"].split(" ")[0].lower() in nome_low:
            key, gpi = "prod:" + pi["key"], pi
        elif fixavel:
            for rx, k, nm in NAME_PRODUCTS:
                if rx.search(f.nome):
                    key = "prod:" + k
                    gpi = {"cpe": k, "key": k, "nome": nm, "versao": pi["versao"] if pi else "", "tipo": "a"}
                    break
        if not key:
            key = "nvt:" + (f.oid or f.nome)
            gpi = pi if pi and pi["tipo"] == "a" else None
        g = groups.setdefault(key, {"key": key, "fs": [], "pi": gpi})
        g["fs"].append(f)
        if key.startswith("prod:") and g["pi"] and PRODUCT_NAMES.get(g["pi"]["key"]) and g["pi"]["nome"] != PRODUCT_NAMES[g["pi"]["key"]]:
            g["pi"] = {**g["pi"], "nome": PRODUCT_NAMES[g["pi"]["key"]]}

    actions: list[Action] = []
    for g in groups.values():
        fs = g["fs"]
        top = max(fs, key=lambda x: x.sev)
        threat = next(s for s in SEV if any(f.threat == s for f in fs))
        portas: dict[str, set] = {}
        for f in fs:
            portas.setdefault(f.ip, set()).add(f.porta)
        nvts = list(dict.fromkeys(f.nome for f in fs))
        is_prod = g["key"].startswith("prod:")
        versoes = list(dict.fromkeys(pi["versao"] for pi in (product_info(f.produto) for f in fs) if pi and pi["versao"]))
        a = Action(
            key=g["key"], threat=threat, sev=top.sev, prioridade=PRI[threat],
            hosts=sorted(portas.keys(), key=_ip_key),
            portas={ip: sorted(ps) for ip, ps in portas.items()},
            cves=sorted({c for f in fs for c in f.cves}),
            nvts=nvts, familia=top.familia,
            produto_nome=(g["pi"]["nome"] + (" " + ", ".join(versoes) if versoes else "")) if g["pi"] else "",
            produto_key=g["pi"]["cpe"] if g["pi"] else "",
            resumo=top.resumo, solucao=top.solucao, sol_tipo=top.sol_tipo,
        )
        if is_prod:
            tem_eol = any(re.search(r"end of life|\beol\b", n, re.I) for n in nvts)
            a.titulo = f"Atualizar {g['pi']['nome']}" + (f" (versão instalada {', '.join(versoes)})" if versoes else "")
            if len(nvts) > 1:
                a.acao = (f"Atualizar {g['pi']['nome']} para a versão suportada mais recente do fabricante."
                          + (" A versão instalada está fora de suporte (EOL)." if tem_eol else "")
                          + f" Uma única atualização corrige as {len(nvts)} vulnerabilidades agrupadas"
                          + (f" ({len(a.cves)} CVEs)." if a.cves else "."))
            else:
                a.acao = (f"Atualizar {g['pi']['nome']} para a versão suportada mais recente do fabricante."
                          + (" A versão instalada está fora de suporte (EOL)." if tem_eol else "")
                          + f" Orientação do scanner: {top.solucao}")
        else:
            a.titulo = top.nome
            kb = next((fn for rx, fn in KB if rx.search(top.nome)), None)
            a.acao = kb(a) if kb else _acao_generica(a, top)
        actions.append(a)

    actions.sort(key=lambda a: (SEV.index(a.threat), -a.sev, -len(a.hosts), a.titulo))
    for i, a in enumerate(actions):
        a.id = f"A-{i + 1:03d}"
    return actions


def compile_rules(rules):
    out = []
    for r in rules:
        try:
            out.append({**r, "rx": re.compile(r["padrao"], re.I)})
        except re.error:
            out.append({**r, "rx": None})
    return out


def assign_teams(actions, parsed, config):
    rules = compile_rules(config["rules"])
    team_ids = {t["id"] for t in config["teams"]}
    default = config.get("default_team") or (config["teams"][0]["id"] if config["teams"] else "")
    for a in actions:
        so = " ".join((parsed["hosts"].get(ip, {}).get("so", "")) for ip in a.hosts)
        campos = {
            "nome": " | ".join(a.nvts) + " | " + a.titulo,
            "familia": a.familia,
            "produto": a.produto_key + " " + a.produto_nome,
            "so": so,
            "ip": " ".join(a.hosts),
        }
        campos["qualquer"] = " | ".join(campos.values())
        team = None
        for r in rules:
            if r["rx"] and r["team"] in team_ids and r["rx"].search(campos.get(r["campo"], "") or ""):
                team = r["team"]
                break
        a.team_auto = team or default
        a.team = a.team_auto
    return actions


def sla_fields(action, config, base_date: dt.date):
    dias = config["sla"].get(action.threat, 90)
    prazo = base_date + dt.timedelta(days=dias)
    return {"sla_dias": dias, "prazo": prazo.isoformat()}
