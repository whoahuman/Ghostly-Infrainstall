#!/usr/bin/env bash
# ==============================================================================
#   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗██╗  ██╗   ██╗   ██╗
#  ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██║  ██║   ╚██╗ ██╔╝
#  ██║  ███╗███████║██║   ██║███████╗   ██║   ███████║    ╚████╔╝
#  ██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██╔══██║     ╚██╔╝
#  ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ██║  ██║      ██║
#   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝      ╚═╝
#
#  Ghostly Infra-installer — установка и защита Remnawave Node
#  Версия: 1.2.2
#
#  Что делает:
#    1. Тюнинг ядра (BBR + fq, безопасные sysctl, без слепой правки conntrack)
#    2. Firewall (nftables): NODE_PORT только для панели, анти-флуд,
#       анти-скан, опционально строгий режим (policy DROP)
#    3. Docker + ротация логов Docker
#    4. Let's Encrypt (acme.sh): HTTP-01 standalone или DNS-01 Cloudflare
#    5. Remnawave Node (docker compose) с доступом к сертификатам и логам
#    6. Ротация логов ноды, journald
#    7. Опционально: fail2ban (SSH), CrowdSec (анти-скан/ботнеты),
#       харденинг SSH, сниппет анти-торрент для Config Profile
#
#  Запуск:  sudo bash ghostly-infra-installer.sh
#  Справка: sudo bash ghostly-infra-installer.sh --help
#
#  Повторный запуск безопасен: берёт параметры из /etc/ghostly/config.env
# ==============================================================================
set -Eeuo pipefail

readonly VERSION="1.2.2"
readonly APP="Ghostly Infra-installer"

CONFIG_DIR="/etc/ghostly"
CONFIG_FILE="${CONFIG_DIR}/config.env"
NFT_FILE="${CONFIG_DIR}/firewall.nft"
NODE_DIR="/opt/remnanode"
NODE_LOG_DIR="/var/log/remnanode"
CERT_DIR="${NODE_DIR}/certs"
LOG_FILE="/var/log/ghostly-installer.log"
CLI_PATH="/usr/local/bin/ghostly"
SUMMARY_FILE="/root/ghostly-summary.txt"

# acme.sh всегда у root, независимо от того, откуда запущен sudo
export HOME=/root
readonly ACME_SH="/root/.acme.sh/acme.sh"

# ---------------------------------------------------------------- defaults ---
DOMAIN=""
LE_EMAIL=""
ACME_METHOD=""      # standalone | dns_cf
CF_TOKEN=""
NODE_PORT=""
SECRET_KEY="${GHOSTLY_SECRET_KEY:-}"
PANEL_IPS=""
BRIDGE_PORT=""
BRIDGE_IPS=""
SELFSTEAL=""
SELFSTEAL_PORT=""
TCP_PORTS=""
UDP_PORTS=""
SSH_PORT=""
ENABLE_FAIL2BAN=""
ENABLE_CROWDSEC=""
STRICT=""
HARDEN_SSH=""
FLOOD_RATE=40
FLOOD_BURST=80
FLOOD_ENABLE=""

RECONFIGURE=0
ASSUME_YES=0
DO_TUNING=1
DO_FIREWALL=1
DO_DOCKER=1
DO_CERTS=1
DO_NODE=1
DO_LOGS=1
DO_SELFSTEAL=1

declare -A ARGS=()   # значения, переданные флагами (имеют приоритет над конфигом)

# ------------------------------------------------------------------- output ---
if [[ -t 2 ]]; then
  C_RESET=$'\033[0m'; C_DIM=$'\033[2m'; C_RED=$'\033[31m'
  C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_CYN=$'\033[36m'; C_BLD=$'\033[1m'
else
  C_RESET=""; C_DIM=""; C_RED=""; C_GRN=""; C_YEL=""; C_CYN=""; C_BLD=""
fi

_log_raw() { printf '%s\n' "$*" >>"$LOG_FILE" 2>/dev/null || true; }
log()  { printf '%s[•]%s %s\n' "$C_CYN" "$C_RESET" "$*"; _log_raw "[$(date '+%F %T')] [*] $*"; }
ok()   { printf '%s[✓]%s %s\n' "$C_GRN" "$C_RESET" "$*"; _log_raw "[$(date '+%F %T')] [ok] $*"; }
warn() { printf '%s[!]%s %s\n' "$C_YEL" "$C_RESET" "$*" >&2; _log_raw "[$(date '+%F %T')] [warn] $*"; }
err()  { printf '%s[x]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; _log_raw "[$(date '+%F %T')] [err] $*"; }
step() { printf '\n%s%s══ %s%s\n' "$C_BLD" "$C_CYN" "$*" "$C_RESET"; }
die()  { err "$*"; exit 1; }
trap 'err "Прерывание на строке $LINENO (команда: $BASH_COMMAND)"' ERR

# -------------------------------------------------------------------- utils ---
have() { command -v "$1" >/dev/null 2>&1; }
is_tty() { [[ -t 0 && -t 1 ]]; }

usage() {
  cat <<EOF
$APP v$VERSION

Использование:
  sudo bash $(basename "$0") [опции]

Основные опции:
  --domain <fqdn>        домен для сертификата (напр. node.example.com)
  --email <addr>         email для Let's Encrypt
  --acme <mode>          standalone | dns_cf
  --cf-token <token>     Cloudflare API token (для --acme dns_cf)
  --node-port <port>     NODE_PORT из карточки ноды в панели (по умолчанию 2222)
  --secret-key <key>     SECRET_KEY из карточки ноды (лучше ввести в интерактиве)
  --panel-ip <list>      IP/домены панели через запятую: кому открыт NODE_PORT
  --bridge-port <port>   порт моста (вход для других нод), напр. 8443
  --bridge-ip <list>     IP нод, которым разрешён порт моста (обязательно вместе
                         с --bridge-port: иначе мост будет открыт всем)
  --selfsteal            поднять self-steal заглушку (Caddy на 127.0.0.1:9443),
  --no-selfsteal         чтобы REALITY отдавал свой сайт, а не чужой
  --tcp-ports <list>     TCP-порты для пользователей (по умолчанию 80,443 standalone / 443 dns)
  --udp-ports <list>     UDP-порты для пользователей (по умолчанию 443)
  --ssh-port <port>      порт SSH (определяется автоматически)
  --strict               строгий firewall: policy DROP (осторожно, спросит подтверждение)
  --harden-ssh           отключить вход по паролю и root-логин (нужен рабочий ключ!)
  --fail2ban / --no-fail2ban
  --flood / --no-flood   анти-флуд в nftables (лимит новых соединений на IP)
  --crowdsec / --no-crowdsec
  --skip-tuning --skip-firewall --skip-docker --skip-certs --skip-node --skip-logs --skip-selfsteal
  --reconfigure          перезапросить все параметры заново
  -y, --yes              не задавать подтверждающих вопросов
  -h, --help             эта справка

После установки: ghostly status | apply-firewall | allow-panel | logs | panic
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain)        ARGS[DOMAIN]="${2:-}"; shift 2 ;;
    --email)         ARGS[LE_EMAIL]="${2:-}"; shift 2 ;;
    --acme)          ARGS[ACME_METHOD]="${2:-}"; shift 2 ;;
    --cf-token)      ARGS[CF_TOKEN]="${2:-}"; shift 2 ;;
    --node-port)     ARGS[NODE_PORT]="${2:-}"; shift 2 ;;
    --secret-key)    ARGS[SECRET_KEY]="${2:-}"; shift 2 ;;
    --panel-ip)      ARGS[PANEL_IPS]="${2:-}"; shift 2 ;;
    --bridge-port)   ARGS[BRIDGE_PORT]="${2:-}"; shift 2 ;;
    --bridge-ip)     ARGS[BRIDGE_IPS]="${2:-}"; shift 2 ;;
    --selfsteal)     ARGS[SELFSTEAL]="1"; shift ;;
    --no-selfsteal)  ARGS[SELFSTEAL]="0"; shift ;;
    --tcp-ports)     ARGS[TCP_PORTS]="${2:-}"; shift 2 ;;
    --udp-ports)     ARGS[UDP_PORTS]="${2:-}"; shift 2 ;;
    --ssh-port)      ARGS[SSH_PORT]="${2:-}"; shift 2 ;;
    --strict)        ARGS[STRICT]="1"; shift ;;
    --harden-ssh)    ARGS[HARDEN_SSH]="1"; shift ;;
    --fail2ban)      ARGS[ENABLE_FAIL2BAN]="1"; shift ;;
    --no-fail2ban)   ARGS[ENABLE_FAIL2BAN]="0"; shift ;;
    --crowdsec)      ARGS[ENABLE_CROWDSEC]="1"; shift ;;
    --no-crowdsec)   ARGS[ENABLE_CROWDSEC]="0"; shift ;;
    --flood)         ARGS[FLOOD_ENABLE]="1"; shift ;;
    --no-flood)      ARGS[FLOOD_ENABLE]="0"; shift ;;
    --skip-tuning)   DO_TUNING=0; shift ;;
    --skip-firewall) DO_FIREWALL=0; shift ;;
    --skip-docker)   DO_DOCKER=0; shift ;;
    --skip-certs)    DO_CERTS=0; shift ;;
    --skip-node)     DO_NODE=0; shift ;;
    --skip-logs)     DO_LOGS=0; shift ;;
    --skip-selfsteal) DO_SELFSTEAL=0; shift ;;
    --reconfigure)   RECONFIGURE=1; shift ;;
    -y|--yes)        ASSUME_YES=1; shift ;;
    -h|--help)       usage; exit 0 ;;
    *) die "Неизвестная опция: $1 (см. --help)" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "Запусти от root: sudo bash $0"
mkdir -p "$CONFIG_DIR" "$NODE_DIR"
touch "$LOG_FILE"

ask() { # ask VAR "prompt" [default]
  local __var="$1" __prompt="$2" __default="${3:-}" __val=""
  [[ -n "${!__var:-}" ]] && return 0
  if ! is_tty; then
    if [[ -n "$__default" ]]; then printf -v "$__var" '%s' "$__default"; return 0; fi
    die "Параметр $__var не задан, а интерактив недоступен. Используй флаги (см. --help)."
  fi
  if [[ -n "$__default" ]]; then
    read -r -p "${C_BLD}${__prompt}${C_RESET} [${__default}]: " __val || true
    __val="${__val:-$__default}"
  else
    while [[ -z "$__val" ]]; do read -r -p "${C_BLD}${__prompt}${C_RESET}: " __val || true; done
  fi
  printf -v "$__var" '%s' "$__val"
}

ask_opt() { # ask_opt VAR "prompt" [default] — можно оставить пустым
  local __var="$1" __prompt="$2" __default="${3:-}" __val=""
  [[ -n "${!__var:-}" ]] && return 0
  if ! is_tty; then printf -v "$__var" '%s' "$__default"; return 0; fi
  if [[ -n "$__default" ]]; then
    read -r -p "${C_BLD}${__prompt}${C_RESET} [${__default}]: " __val || true
    __val="${__val:-$__default}"
  else
    read -r -p "${C_BLD}${__prompt}${C_RESET}: " __val || true
  fi
  printf -v "$__var" '%s' "$__val"
}

ask_secret() { # ask_secret VAR "prompt"
  local __var="$1" __prompt="$2" __val=""
  [[ -n "${!__var:-}" ]] && return 0
  is_tty || die "SECRET_KEY не передан. Используй --secret-key или переменную GHOSTLY_SECRET_KEY."
  printf '%s%s%s\n' "$C_BLD" "$__prompt" "$C_RESET" >&2
  printf '%s(ввод скрыт, в логи не пишется)%s\n' "$C_DIM" "$C_RESET" >&2
  while [[ -z "$__val" ]]; do read -rs -p "> " __val || true; echo >&2; done
  printf -v "$__var" '%s' "$__val"
}

yesno() { # yesno "вопрос" [default y|n] -> 0 если да
  local __q="$1" __def="${2:-n}" __ans=""
  (( ASSUME_YES )) && { [[ "$__def" == "y" ]]; return; }
  is_tty || { [[ "$__def" == "y" ]]; return; }
  local __hint="y/N"; [[ "$__def" == "y" ]] && __hint="Y/n"
  read -r -p "${C_BLD}${__q}${C_RESET} [${__hint}]: " __ans || true
  __ans="${__ans:-$__def}"
  [[ "$__ans" =~ ^([yYдД]|yes|да)$ ]]
}

ask_phrase() { # ask_phrase "вопрос" "ожидаемая фраза" -> 0 если совпало
  local __q="$1" __want="$2" __ans=""
  is_tty || return 1
  read -r -p "${C_BLD}${__q}${C_RESET} (напиши ${__want}): " __ans || true
  [[ "$__ans" == "$__want" ]]
}

save_config() {
  umask 077
  {
    echo "# Ghostly Infra-installer — конфигурация (обновлено $(date '+%F %T'))"
    echo "# Источник правды для 'ghostly apply-firewall'. Правь аккуратно, файл 0600."
    echo "DOMAIN=\"$DOMAIN\""
    echo "LE_EMAIL=\"$LE_EMAIL\""
    echo "ACME_METHOD=\"$ACME_METHOD\""
    echo "CF_TOKEN=\"$CF_TOKEN\""
    echo "NODE_PORT=\"$NODE_PORT\""
    echo "PANEL_IPS=\"$PANEL_IPS\""
    echo "BRIDGE_PORT=\"$BRIDGE_PORT\""
    echo "BRIDGE_IPS=\"$BRIDGE_IPS\""
    echo "SELFSTEAL=\"$SELFSTEAL\""
    echo "SELFSTEAL_PORT=\"$SELFSTEAL_PORT\""
    echo "TCP_PORTS=\"$TCP_PORTS\""
    echo "UDP_PORTS=\"$UDP_PORTS\""
    echo "SSH_PORT=\"$SSH_PORT\""
    echo "ENABLE_FAIL2BAN=\"$ENABLE_FAIL2BAN\""
    echo "ENABLE_CROWDSEC=\"$ENABLE_CROWDSEC\""
    echo "STRICT=\"$STRICT\""
    echo "HARDEN_SSH=\"$HARDEN_SSH\""
    echo "FLOOD_RATE=\"$FLOOD_RATE\""
    echo "FLOOD_BURST=\"$FLOOD_BURST\""
    echo "FLOOD_ENABLE=\"$FLOOD_ENABLE\""
  } >"$CONFIG_FILE"
  chmod 600 "$CONFIG_FILE"
}

# ==============================================================================
#  ШАГ 0. Сбор параметров: конфиг → флаги → интерактив
# ==============================================================================
collect_input() {
  if [[ -f "$CONFIG_FILE" && $RECONFIGURE -eq 0 ]]; then
    log "Читаю существующий конфиг: $CONFIG_FILE"
    # shellcheck disable=SC1090
    . "$CONFIG_FILE"
  fi

  # флаги командной строки имеют приоритет над конфигом
  local k
  for k in "${!ARGS[@]}"; do printf -v "$k" '%s' "${ARGS[$k]}"; done

  step "Параметры"

  if [[ -z "$SSH_PORT" ]]; then
    SSH_PORT="$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}' || true)"
    SSH_PORT="${SSH_PORT:-22}"
  fi

  ask DOMAIN "Домен ноды (A-запись уже настроена)"
  ask LE_EMAIL "Email для Let's Encrypt"
  ask_opt ACME_METHOD "Метод ACME: standalone (порт 80) или dns_cf" "standalone"
  if [[ "$ACME_METHOD" == "dns_cf" ]]; then
    ask_opt CF_TOKEN "Cloudflare API Token (DNS-01; можно оставить пусто и задать позже)"
  fi
  # если нода уже развёрнута — берём порт и секрет из её .env (секрет в /etc/ghostly не хранится)
  if [[ -f "${NODE_DIR}/.env" ]]; then
    local env_port env_secret
    env_port="$(sed -n 's/^NODE_PORT=//p' "${NODE_DIR}/.env" | head -1 | tr -d '"'"'"' ')"
    env_secret="$(sed -n 's/^SECRET_KEY=//p' "${NODE_DIR}/.env" | head -1 | tr -d '"'"'"' ')"
    if [[ -n "$env_port" || -n "$env_secret" ]]; then
      log "Найден существующий ${NODE_DIR}/.env — использую NODE_PORT и SECRET_KEY оттуда"
      [[ -z "$NODE_PORT"  && -n "$env_port"   ]] && NODE_PORT="$env_port"
      [[ -z "$SECRET_KEY" && -n "$env_secret" ]] && SECRET_KEY="$env_secret"
    fi
  fi

  if (( DO_NODE )); then
    ask NODE_PORT "NODE_PORT из карточки ноды" "2222"
    ask_secret SECRET_KEY "SECRET_KEY из карточки ноды (Nodes → Management)"
  else
    [[ -z "$NODE_PORT" ]] && NODE_PORT="2222"
  fi
  ask_opt PANEL_IPS "IP или домены панели через запятую (только им будет открыт NODE_PORT; пусто = открыт всем)"
  ask_opt BRIDGE_PORT "Порт моста для приёма трафика с других нод (пусто — мост не нужен)" ""
  if [[ -n "$BRIDGE_PORT" ]]; then
    ask_opt BRIDGE_IPS "IP нод, которым разрешён порт моста (через запятую; обязательно)"
  fi
  if [[ -z "$SELFSTEAL" ]]; then
    if yesno "Поднять self-steal заглушку (REALITY отдаёт свой сайт на ${DOMAIN:-домене})?" y; then
      SELFSTEAL=1
    else
      SELFSTEAL=0
    fi
  fi
  if [[ "$SELFSTEAL" == "1" ]]; then
    ask_opt SELFSTEAL_PORT "Порт Caddy-заглушки на loopback (REALITY будет форвардить сюда)" "9443"
  fi
  local tcp_default
  if [[ "$ACME_METHOD" == "standalone" ]]; then tcp_default="80,443"; else tcp_default="443"; fi
  ask_opt TCP_PORTS "Открытые TCP-порты для пользователей (80 нужен для продления сертификата)" "$tcp_default"
  ask_opt UDP_PORTS "Открытые UDP-порты для пользователей (Hysteria2: 443/udp)" "443"
  if is_tty; then ask_opt SSH_PORT "Порт SSH" "$SSH_PORT"; fi

  [[ -z "$STRICT" ]]     && STRICT=0
  [[ -z "$HARDEN_SSH" ]] && HARDEN_SSH=0
  if is_tty && (( ! ASSUME_YES )); then
    echo
    if ! [[ -v ARGS[ENABLE_FAIL2BAN] ]]; then
      if yesno "Включить fail2ban (бан брутфорса SSH)?" y; then ENABLE_FAIL2BAN=1; else ENABLE_FAIL2BAN=0; fi
    fi
    if ! [[ -v ARGS[ENABLE_CROWDSEC] ]]; then
      if yesno "Включить CrowdSec (community-блоклисты, анти-скан/ботнеты)?" n; then ENABLE_CROWDSEC=1; else ENABLE_CROWDSEC=0; fi
    fi
    if [[ "$STRICT" != "1" ]] && yesno "Строгий firewall (policy DROP: всё, кроме явно разрешённого)?" n; then
      warn "Строгий режим оставит открытыми только: SSH($SSH_PORT), TCP($TCP_PORTS), UDP($UDP_PORTS), NODE_PORT($NODE_PORT) для панели."
      if ask_phrase "Подтверди строгий режим" "STRICT"; then
        STRICT=1
      else
        warn "Не подтверждено — строгий режим выключен."
      fi
    fi
    if [[ "$HARDEN_SSH" != "1" ]] && yesno "Отключить вход по паролю и root-логин по SSH (нужен уже проверенный ключ!)?" n; then
      HARDEN_SSH=1
    fi
  fi
  [[ -z "$ENABLE_FAIL2BAN" ]] && ENABLE_FAIL2BAN=1
  [[ -z "$ENABLE_CROWDSEC" ]] && ENABLE_CROWDSEC=0
  [[ -z "$FLOOD_ENABLE" ]] && FLOOD_ENABLE=1

  save_config
  ok "Параметры сохранены в $CONFIG_FILE (0600)"
}

# ==============================================================================
#  ШАГ 1. Тюнинг ядра
# ==============================================================================
step_tuning() {
  step "1/8 Тюнинг ядра (BBR, очереди, лимиты)"
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ca-certificates curl dnsutils logrotate cron >/dev/null

  modprobe tcp_bbr 2>/dev/null || true
  modprobe sch_fq   2>/dev/null || true

  cat >/etc/modules-load.d/ghostly-bbr.conf <<'EOF'
tcp_bbr
sch_fq
EOF

  cat >/etc/sysctl.d/99-ghostly-tuning.conf <<'EOF'
# === Ghostly Infra-installer / тюнинг прокси-ноды ============================
# Увеличиваются только ВЕРХНИЕ границы буферов: память выделяется по факту,
# постоянного резерва нет. conntrack сознательно не трогаем.

# --- Congestion control ---
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# --- Буферы (верхние границы) ---
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# --- Задержки и переиспользование соединений ---
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.ip_local_port_range = 10240 65535

# --- Очереди входящих соединений / анти-SYN ---
net.core.somaxconn = 8192
net.core.netdev_max_backlog = 4096
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_syncookies = 1

# --- Гигиена стека ---
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
EOF

  sysctl --system >/dev/null
  if sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -q bbr; then
    ok "BBR: $(sysctl -n net.ipv4.tcp_congestion_control), qdisc: $(sysctl -n net.core.default_qdisc)"
  else
    warn "BBR не отображается в доступных — проверь: sysctl net.ipv4.tcp_available_congestion_control"
  fi

  if [[ -r /proc/sys/net/netfilter/nf_conntrack_max ]]; then
    log "conntrack: занято $(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo '?') из $(cat /proc/sys/net/netfilter/nf_conntrack_max) (менять не стали, сначала нужны данные о нагрузке)"
  fi
}

# ==============================================================================
#  ШАГ 2. Firewall (nftables) + CLI ghostly
# ==============================================================================
install_cli() {
  cat >"$CLI_PATH" <<'GHOSTLY_CLI_EOF'
#!/usr/bin/env bash
# ghostly — служебная команда ноды (установлена Ghostly Infra-installer).
# Источник правды по firewall: /etc/ghostly/config.env → ghostly apply-firewall
set -Eeuo pipefail

CONFIG_FILE="/etc/ghostly/config.env"
NFT_FILE="/etc/ghostly/firewall.nft"
NODE_DIR="/opt/remnanode"
NODE_LOG_DIR="/var/log/remnanode"
CERT_DIR="${NODE_DIR}/certs"

export HOME=/root
ACME_SH="/root/.acme.sh/acme.sh"

die() { printf 'ghostly: %s\n' "$*" >&2; exit 1; }

load_config() {
  [[ -r "$CONFIG_FILE" ]] || die "нет $CONFIG_FILE (запусти Ghostly Infra-installer)"
  # shellcheck disable=SC1090
  . "$CONFIG_FILE"
}

split_list() { tr ',' '\n' <<<"${1:-}" | tr -d ' \t' | sed '/^$/d'; }

resolve_ipv4() {
  local item out=""
  for item in $(split_list "${1:-}"); do
    [[ "$item" == *:* ]] && continue
    if [[ "$item" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$ ]]; then
      out+="$item"$'\n'
    else
      out+="$(getent ahostsv4 "$item" 2>/dev/null | awk '{print $1}' | sort -u)"$'\n'
    fi
  done
  printf '%s' "$out" | sed '/^$/d' | sort -u
}

resolve_ipv6() {
  local item out=""
  for item in $(split_list "${1:-}"); do
    [[ "$item" != *:* ]] && continue
    if [[ "$item" =~ ^[0-9a-fA-F:]+(/[0-9]{1,3})?$ ]]; then
      out+="$item"$'\n'
    else
      out+="$(getent ahostsv6 "$item" 2>/dev/null | awk '{print $1}' | sort -u)"$'\n'
    fi
  done
  printf '%s' "$out" | sed '/^$/d' | sort -u
}

emit_addr_set() { # name type "<addr lines>"
  local name="$1" type="$2" addrs="$3" list="" a=""
  while read -r a; do [[ -n "$a" ]] && list+="${list:+, }$a"; done <<<"$addrs"
  printf '    set %s {\n        type %s\n        flags interval\n' "$name" "$type"
  [[ -n "$list" ]] && printf '        elements = { %s }\n' "$list"
  printf '    }\n'
}

port_elements() {
  local p="" out=""
  while read -r p; do
    [[ -z "$p" ]] && continue
    [[ "$p" =~ ^[0-9]+(-[0-9]+)?$ ]] || die "некорректный порт: $p"
    out+="${out:+, }$p"
  done <<<"$(split_list "${1:-}")"
  printf '%s' "$out"
}

emit_svc_set() { # name "<ports>"
  local name="$1" list
  list="$(port_elements "${2:-}")"
  if [[ -n "$list" ]]; then
    printf '    set %s { type inet_service; flags interval; elements = { %s } }\n' "$name" "$list"
  else
    printf '    set %s { type inet_service; flags interval; }\n' "$name"
  fi
}

gen_firewall() {
  local ssh_port="${SSH_PORT:-22}"
  local tcp_ports="${TCP_PORTS:-443}" udp_ports="${UDP_PORTS:-443}"
  local node_port="${NODE_PORT:-2222}" policy="accept"
  local panel4 panel6 has_panel=0

  [[ -n "$node_port" && "$node_port" =~ ^[0-9]+$ ]] || die "NODE_PORT задан неверно: '${NODE_PORT}'"
  [[ "$node_port" == "$ssh_port" ]] && die "NODE_PORT совпадает с портом SSH — так делать нельзя"
  for p in $(split_list "$tcp_ports") $(split_list "$udp_ports"); do
    [[ "$p" == "$node_port" ]] && die "NODE_PORT ($node_port) указан в списке пользовательских портов — убери его"
  done

  [[ "${STRICT:-0}" == "1" ]] && policy="drop"

  panel4="$(resolve_ipv4 "${PANEL_IPS:-}")"
  panel6="$(resolve_ipv6 "${PANEL_IPS:-}")"
  if [[ -n "${PANEL_IPS:-}" ]]; then
    [[ -n "$panel4$panel6" ]] || die "не удалось разрешить адреса панели из PANEL_IPS='${PANEL_IPS}'. Укажи IP вручную."
    has_panel=1
  fi

  # мост: вход для других нод, открыт только их адресам
  local bridge_port="${BRIDGE_PORT:-}" bridge4="" bridge6="" has_bridge=0
  if [[ -n "$bridge_port" && "$bridge_port" != "off" ]]; then
    [[ "$bridge_port" =~ ^[0-9]+$ ]] || die "BRIDGE_PORT задан неверно: '${bridge_port}'"
    [[ "$bridge_port" == "$ssh_port" ]] && die "BRIDGE_PORT совпадает с портом SSH"
    [[ "$bridge_port" == "$node_port" ]] && die "BRIDGE_PORT совпадает с NODE_PORT"
    for p in $(split_list "$tcp_ports") $(split_list "$udp_ports"); do
      [[ "$p" == "$bridge_port" ]] && die "BRIDGE_PORT ($bridge_port) указан в списке пользовательских портов — убери его"
    done
    bridge4="$(resolve_ipv4 "${BRIDGE_IPS:-}")"
    bridge6="$(resolve_ipv6 "${BRIDGE_IPS:-}")"
    if [[ -z "$bridge4$bridge6" ]]; then
      die "BRIDGE_PORT=$bridge_port задан, а BRIDGE_IPS пуст или не резолвится. Так мост будет открыт всему интернету — укажи IP нод."
    fi
    has_bridge=1
  fi

  cat <<'NFT_HEAD'
#!/usr/sbin/nft -f
# Сгенерировано Ghostly Infra-installer. НЕ редактируй вручную:
# источник правды — /etc/ghostly/config.env, применение — `ghostly apply-firewall`
table inet ghostly
delete table inet ghostly
table inet ghostly {
NFT_HEAD

  emit_addr_set panel4 ipv4_addr "$panel4"
  emit_addr_set panel6 ipv6_addr "$panel6"
  emit_addr_set bridge4 ipv4_addr "$bridge4"
  emit_addr_set bridge6 ipv6_addr "$bridge6"
  emit_svc_set svc_tcp "$tcp_ports"
  emit_svc_set svc_udp "$udp_ports"

  cat <<EOF
    chain input {
        type filter hook input priority filter; policy ${policy};
        comment "ghostly input"

        ct state invalid drop comment "ghostly: битые пакеты"
        ct state established,related accept comment "ghostly: установленные соединения"
        iif lo accept comment "ghostly: loopback"
        ip protocol icmp accept comment "ghostly: ping v4"
        meta l4proto ipv6-icmp accept comment "ghostly: icmp v6"

        # --- Панель -> NODE_PORT (внутренний API ноды) ---
EOF

  if (( has_panel )); then
    cat <<EOF
        ip saddr @panel4 tcp dport ${node_port} accept comment "ghostly: NODE_PORT — панель v4"
        ip6 saddr @panel6 tcp dport ${node_port} accept comment "ghostly: NODE_PORT — панель v6"
        tcp dport ${node_port} drop comment "ghostly: NODE_PORT закрыт для остальных"
EOF
  else
    cat <<EOF
        tcp dport ${node_port} accept comment "ghostly: NODE_PORT открыт всем (панель не ограничена)"
EOF
  fi

  if (( has_bridge )); then
    cat <<EOF

        # --- Мост: приём трафика с других нод (только их адреса) ---
        ip saddr @bridge4 tcp dport ${bridge_port} accept comment "ghostly: мост — ноды v4"
        ip6 saddr @bridge6 tcp dport ${bridge_port} accept comment "ghostly: мост — ноды v6"
        tcp dport ${bridge_port} drop comment "ghostly: мост закрыт для остальных"
EOF
  fi

  cat <<EOF

        # --- Пользовательские порты ---
EOF
  if [[ "${FLOOD_ENABLE:-1}" == "1" ]]; then
    cat <<EOF
        # анти-флуд: лимит НОВЫХ соединений на один IP (отключается FLOOD_ENABLE=0)
        tcp dport @svc_tcp ct state new meter flood_tcp4 { ip saddr limit rate over ${FLOOD_RATE:-40}/second burst ${FLOOD_BURST:-80} packets } drop comment "ghostly: anti-flood v4"
        tcp dport @svc_tcp ct state new meter flood_tcp6 { ip6 saddr limit rate over ${FLOOD_RATE:-40}/second burst ${FLOOD_BURST:-80} packets } drop comment "ghostly: anti-flood v6"
        udp dport @svc_udp ct state new meter flood_udp4 { ip saddr limit rate over 200/second burst 400 packets } drop comment "ghostly: anti-flood udp v4"
        udp dport @svc_udp ct state new meter flood_udp6 { ip6 saddr limit rate over 200/second burst 400 packets } drop comment "ghostly: anti-flood udp v6"
EOF
  fi
  cat <<EOF
        tcp dport @svc_tcp accept comment "ghostly: пользовательский TCP"
        udp dport @svc_udp accept comment "ghostly: пользовательский UDP"

        # --- SSH ---
        tcp dport ${ssh_port} accept comment "ghostly: SSH"
EOF

  if [[ "$policy" == "drop" ]]; then
    cat <<'EOF'

        # --- Строгий режим: всё неразрешённое выше отбрасывается ---
        iifname "docker*" accept comment "ghostly: docker bridge"
        iifname "br-*" accept comment "ghostly: compose bridge"
        udp dport 67-68 accept comment "ghostly: DHCP"
EOF
  fi

  cat <<'EOF'
    }
}
EOF
}

apply_firewall() {
  command -v nft >/dev/null 2>&1 || die "nftables не установлен (apt install nftables)"
  load_config
  mkdir -p /etc/ghostly
  gen_firewall >"$NFT_FILE"
  nft -c -f "$NFT_FILE" || die "проверка правил не прошла, ядро не приняло таблицу. Файл: $NFT_FILE"
  nft -f "$NFT_FILE"
  printf 'ghostly: firewall применён (policy %s)\n' "$([[ "${STRICT:-0}" == "1" ]] && echo drop || echo accept)"
}

cmd_status() {
  load_config
  printf '== ghostly status ==\n'
  printf 'домен:      %s\n' "${DOMAIN:-—}"
  printf 'NODE_PORT:  %s\n' "${NODE_PORT:-—}"
  printf 'панель:     %s\n' "${PANEL_IPS:-все адреса}"
  printf 'TCP / UDP:  %s / %s\n' "${TCP_PORTS:-—}" "${UDP_PORTS:-—}"
  printf 'SSH:        %s   strict: %s\n' "${SSH_PORT:-22}" "${STRICT:-0}"
  if [[ -n "${BRIDGE_PORT:-}" ]]; then
    printf 'мост:       порт %s → %s\n' "$BRIDGE_PORT" "${BRIDGE_IPS:-НЕ ОГРАНИЧЕН (плохо!)}"
  else
    printf 'мост:       не настроен\n'
  fi
  printf 'self-steal: %s\n' "$([[ "${SELFSTEAL:-0}" == "1" ]] && echo "Caddy 127.0.0.1:${SELFSTEAL_PORT}" || echo "выключен")"
  printf 'fail2ban:   %s   crowdsec: %s\n' "${ENABLE_FAIL2BAN:-0}" "${ENABLE_CROWDSEC:-0}"
  echo
  printf -- '-- firewall --\n'
  if nft list table inet ghostly >/dev/null 2>&1; then
    nft list table inet ghostly | sed 's/^/  /'
  else
    printf '  таблица inet ghostly не загружена\n'
  fi
  echo
  printf -- '-- порты --\n'
  ss -lntu | sed 's/^/  /'
  echo
  printf -- '-- контейнер --\n'
  if command -v docker >/dev/null 2>&1; then
    docker ps --format '  {{.Names}}\t{{.Status}}\t{{.Image}}' 2>/dev/null || true
    docker compose -f "${NODE_DIR}/docker-compose.yml" ps 2>/dev/null | sed 's/^/  /' || true
  else
    printf '  docker не установлен\n'
  fi
  echo
  printf -- '-- сертификат --\n'
  if [[ -r "$CERT_DIR/fullchain.pem" ]]; then
    openssl x509 -in "$CERT_DIR/fullchain.pem" -noout -subject -enddate | sed 's/^/  /'
  else
    printf '  %s/fullchain.pem отсутствует\n' "$CERT_DIR"
  fi
  echo
  printf -- '-- self-steal --\n'
  if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' 2>/dev/null | grep -qx selfsteal; then
    printf '  контейнер selfsteal: работает\n'
  else
    printf '  контейнер selfsteal: не запущен\n'
  fi
  if [[ -n "${DOMAIN:-}" && -n "${SELFSTEAL_PORT:-}" ]]; then
    local sscode
    sscode="$(curl -sk --max-time 5 --resolve "${DOMAIN}:${SELFSTEAL_PORT}:127.0.0.1" "https://${DOMAIN}:${SELFSTEAL_PORT}/" -o /dev/null -w '%{http_code}' 2>/dev/null || true)"
    printf '  https://%s:%s/ → %s\n' "$DOMAIN" "$SELFSTEAL_PORT" "${sscode:-нет ответа}"
  fi
  echo
  printf -- '-- fail2ban --\n'
  if command -v fail2ban-client >/dev/null 2>&1; then
    fail2ban-client status sshd 2>/dev/null | sed 's/^/  /' || printf '  jail sshd не активен\n'
  else
    printf '  fail2ban не установлен\n'
  fi
}

cmd_allow_panel() {
  load_config
  local add="${1:-}"
  [[ -n "$add" ]] || die "использование: ghostly allow-panel <ip|домен>[,<ip>...]"
  local new="$add"
  [[ -n "${PANEL_IPS:-}" ]] && new="${PANEL_IPS},${add}"
  if grep -q '^PANEL_IPS=' "$CONFIG_FILE"; then
    sed -i "s|^PANEL_IPS=.*|PANEL_IPS=\"${new}\"|" "$CONFIG_FILE"
  else
    printf 'PANEL_IPS="%s"\n' "$new" >>"$CONFIG_FILE"
  fi
  PANEL_IPS="$new"
  apply_firewall
}

cmd_bridge() {
  load_config
  local port="${1:-}" ips="${2:-}"
  if [[ "$port" == "off" ]]; then
    sed -i 's|^BRIDGE_PORT=.*|BRIDGE_PORT=""|; s|^BRIDGE_IPS=.*|BRIDGE_IPS=""|' "$CONFIG_FILE"
    BRIDGE_PORT=""; BRIDGE_IPS=""
    apply_firewall
    printf 'ghostly: правила моста убраны (порт закрыт)\n'
    return 0
  fi
  [[ -n "$port" && -n "$ips" ]] || die "использование: ghostly bridge <порт> <ip|домен>[,<ip>...]   |   ghostly bridge off"
  if grep -q '^BRIDGE_PORT=' "$CONFIG_FILE"; then
    sed -i "s|^BRIDGE_PORT=.*|BRIDGE_PORT=\"${port}\"|" "$CONFIG_FILE"
  else
    printf 'BRIDGE_PORT="%s"\n' "$port" >>"$CONFIG_FILE"
  fi
  if grep -q '^BRIDGE_IPS=' "$CONFIG_FILE"; then
    sed -i "s|^BRIDGE_IPS=.*|BRIDGE_IPS=\"${ips}\"|" "$CONFIG_FILE"
  else
    printf 'BRIDGE_IPS="%s"\n' "$ips" >>"$CONFIG_FILE"
  fi
  BRIDGE_PORT="$port"; BRIDGE_IPS="$ips"
  apply_firewall
}

cmd_renew_cert() {
  load_config
  [[ -x "$ACME_SH" ]] || die "acme.sh не найден в /root/.acme.sh"
  [[ -n "${DOMAIN:-}" ]] || die "домен не задан в $CONFIG_FILE"
  "$ACME_SH" --renew -d "$DOMAIN" --ecc --force || die "не удалось обновить сертификат"
}

cmd_logs() {
  if command -v docker >/dev/null 2>&1; then
    docker logs -f --tail 200 remnanode
  else
    tail -n 200 -f "${NODE_LOG_DIR}/error.log" 2>/dev/null || die "логов сейчас нет"
  fi
}

cmd_panic() {
  nft delete table inet ghostly 2>/dev/null || true
  printf 'ghostly: правила сняты, активен режим по умолчанию.\n'
  printf 'Вернуть защиту: ghostly apply-firewall\n'
}

usage_cli() {
  cat <<'EOF'
ghostly — служебная команда ноды

  ghostly status                  правила, порты, контейнер, сертификат, fail2ban
  ghostly apply-firewall          применить правила из /etc/ghostly/config.env
  ghostly allow-panel <ip|домен>  открыть панели NODE_PORT (можно список через запятую)
  ghostly bridge <порт> <ip,ip>   открыть порт моста только указанным нодам
  ghostly bridge off              закрыть порт моста
  ghostly panic                   снять все правила ghostly (аварийный случай)
  ghostly logs                    живые логи ноды
  ghostly renew-cert              принудительно продлить сертификат
  ghostly edit                    открыть /etc/ghostly/config.env
EOF
}

case "${1:-}" in
  status)          cmd_status ;;
  apply-firewall)  apply_firewall ;;
  allow-panel)     shift; cmd_allow_panel "$@" ;;
  bridge)          shift; cmd_bridge "$@" ;;
  panic)           cmd_panic ;;
  logs)            cmd_logs ;;
  renew-cert)      cmd_renew_cert ;;
  edit)            "${EDITOR:-nano}" "$CONFIG_FILE" ;;
  ""|-h|--help|help) usage_cli ;;
  *) die "неизвестная команда: $1 (ghostly --help)" ;;
esac
GHOSTLY_CLI_EOF
  chmod 755 "$CLI_PATH"
  ok "Служебная команда установлена: ghostly (ghostly --help)"
}

step_firewall() {
  step "2/8 Firewall (nftables): NODE_PORT по IP панели, анти-флуд, анти-скан"
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables >/dev/null || die "не удалось установить nftables"
  install_cli

  if "$CLI_PATH" apply-firewall; then
    ok "Правила активны: NODE_PORT ${NODE_PORT} → ${PANEL_IPS:-все адреса}; пользовательские TCP ${TCP_PORTS} / UDP ${UDP_PORTS}"
  else
    warn "Firewall НЕ применён. Причина выше. Починить и применить: ghostly apply-firewall"
  fi

  # персистентность через собственный unit: не трогаем /etc/nftables.conf,
  # чтобы не задеть чужие таблицы (например, таблицы Remnawave Node)
  cat >/etc/systemd/system/ghostly-firewall.service <<'EOF'
[Unit]
Description=Ghostly nftables firewall
After=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/ghostly/firewall.nft
ExecReload=/usr/sbin/nft -f /etc/ghostly/firewall.nft

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable -q ghostly-firewall.service >/dev/null 2>&1 || true
  ok "Автозагрузка правил: systemd unit ghostly-firewall.service (чужие nft-таблицы не затрагиваются)"

  if have ufw && ufw status 2>/dev/null | grep -qi '^Status: active'; then
    warn "Активен ufw — дублирую разрешения, чтобы он не зарезал доступ"
    ufw allow "${SSH_PORT}/tcp" >/dev/null 2>&1 || true
    local p ip
    for p in ${TCP_PORTS//,/ }; do ufw allow "${p}/tcp" >/dev/null 2>&1 || true; done
    for p in ${UDP_PORTS//,/ }; do ufw allow "${p}/udp" >/dev/null 2>&1 || true; done
    if [[ -n "${PANEL_IPS:-}" ]]; then
      for ip in ${PANEL_IPS//,/ }; do
        ufw allow from "$ip" to any port "$NODE_PORT" proto tcp >/dev/null 2>&1 || true
      done
      ufw deny "${NODE_PORT}/tcp" >/dev/null 2>&1 || true
    fi
    ok "ufw: разрешения добавлены"
  fi
}

# ==============================================================================
#  ШАГ 3. Docker + ротация логов Docker
# ==============================================================================
step_docker() {
  step "3/8 Docker + ротация логов Docker"
  if have docker; then
    ok "Docker уже установлен: $(docker --version)"
  else
    log "Устанавливаю Docker (get.docker.com)…"
    curl -fsSL https://get.docker.com | sh
  fi
  systemctl enable -q --now docker >/dev/null 2>&1 || true

  mkdir -p /etc/docker
  if [[ -f /etc/docker/daemon.json ]] && ! grep -q 'max-size' /etc/docker/daemon.json; then
    cp /etc/docker/daemon.json "/etc/docker/daemon.json.bak.$(date +%s)"
    warn "Прежний /etc/docker/daemon.json сохранён как .bak и дополнен"
  fi
  cat >/etc/docker/daemon.json <<'EOF'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "50m",
    "max-file": "3"
  },
  "live-restore": true,
  "default-ulimits": {
    "nofile": { "Name": "nofile", "Hard": 1048576, "Soft": 1048576 }
  }
}
EOF
  systemctl restart docker
  ok "Docker: логи 50 МБ × 3, nofile=1048576, live-restore включён"
}

# ==============================================================================
#  ШАГ 4. Сертификаты Let's Encrypt (acme.sh)
# ==============================================================================
step_certs() {
  step "4/8 Сертификаты Let's Encrypt (acme.sh)"
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq socat openssl >/dev/null

  if [[ ! -x "$ACME_SH" ]]; then
    log "Устанавливаю acme.sh в /root/.acme.sh…"
    curl -fsS https://get.acme.sh | sh -s email="$LE_EMAIL"
  fi
  [[ -x "$ACME_SH" ]] || { warn "acme.sh не установился — выпусти сертификат позже"; return 0; }
  "$ACME_SH" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true

  local pubip resolved
  pubip="$(curl -fsS4 --max-time 10 https://api.ipify.org 2>/dev/null || true)"
  resolved="$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ')"
  if [[ -n "$pubip" ]]; then
    log "IP сервера: $pubip | A-запись $DOMAIN: ${resolved:-нет}"
    if [[ -n "$resolved" && "$resolved" != *"$pubip"* ]]; then
      warn "A-запись домена не совпадает с IP сервера: для HTTP-01 нужен прямой A-запись без Cloudflare-прокси"
    fi
  fi

  mkdir -p "$CERT_DIR"
  local reloadcmd
  reloadcmd="chmod 600 ${CERT_DIR}/privkey.key; chmod 644 ${CERT_DIR}/fullchain.pem; ln -sf privkey.key ${CERT_DIR}/privkey.pem; ln -sf fullchain.pem ${CERT_DIR}/cert.pem; docker restart remnanode >/dev/null 2>&1 || true; docker restart selfsteal >/dev/null 2>&1 || true"

  local rc_issue=0
  if [[ "$ACME_METHOD" == "dns_cf" ]]; then
    if [[ -z "${CF_TOKEN:-}" ]]; then
      warn "CF_TOKEN пуст — пропускаю выпуск. Позже: CF_Token=<token> $ACME_SH --issue --dns dns_cf -d $DOMAIN --keylength ec-256"
      return 0
    fi
    export CF_Token="$CF_TOKEN"
    "$ACME_SH" --issue --dns dns_cf -d "$DOMAIN" --keylength ec-256 || rc_issue=$?
  else
    if ss -lntH 2>/dev/null | awk '{print $4}' | grep -qE '(:80)$'; then
      warn "Порт 80 занят — HTTP-01 standalone не пройдёт (варианты: освободить 80 или --acme dns_cf)"
    fi
    "$ACME_SH" --issue --standalone -d "$DOMAIN" --keylength ec-256 || rc_issue=$?
  fi

  # acme.sh: 0 = выпущен сейчас, 2 = уже есть и не требует продления (это норма при повторном запуске)
  if (( rc_issue == 0 || rc_issue == 2 )); then
    "$ACME_SH" --install-cert -d "$DOMAIN" --ecc \
      --key-file       "${CERT_DIR}/privkey.key" \
      --fullchain-file "${CERT_DIR}/fullchain.pem" \
      --reloadcmd      "$reloadcmd"
    chmod 600 "${CERT_DIR}/privkey.key"; chmod 644 "${CERT_DIR}/fullchain.pem"
    # совместимость с Config Profile, где указан privkey.pem (или cert.pem)
    ln -sf privkey.key "${CERT_DIR}/privkey.pem"
    ln -sf fullchain.pem "${CERT_DIR}/cert.pem"
    if (( rc_issue == 2 )); then
      ok "Сертификат уже выпущен ранее — обновил файлы и reloadcmd (< 30 дней до продления acme.sh обновит сам)"
    else
      ok "Сертификат: $CERT_DIR/fullchain.pem + privkey.key (ECC, автопродление через cron acme.sh)"
    fi
  else
    warn "Сертификат не выпущен (код acme.sh: $rc_issue). Нода всё равно установится; выпусти позже (см. $SUMMARY_FILE)"
  fi
}

# ==============================================================================
#  ШАГ 5. Self-steal заглушка (Caddy на loopback)
# ==============================================================================
step_selfsteal() {
  step "5/8 Self-steal заглушка для REALITY (Caddy)"

  if [[ -z "${DOMAIN:-}" ]]; then
    warn "домен не задан — пропускаю self-steal"
    return 0
  fi
  if [[ ! -r "${CERT_DIR}/fullchain.pem" || ! -r "${CERT_DIR}/privkey.key" ]]; then
    warn "нет сертификата в ${CERT_DIR} — Caddy без него не стартует. Выпусти сертификат и повтори установку (или --skip-selfsteal)."
    return 0
  fi

  mkdir -p "${NODE_DIR}/selfsteal/www" /var/log/selfsteal
  chmod 755 /var/log/selfsteal

  # Caddy: loopback-only, PROXY protocol (Xray REALITY форвардит с xver=1)
  cat >"${NODE_DIR}/selfsteal/Caddyfile" <<EOF
{
	https_port ${SELFSTEAL_PORT}
	default_bind 127.0.0.1
	auto_https disable_redirects

	servers {
		listener_wrappers {
			proxy_protocol {
				allow 127.0.0.1/32
			}
			tls
		}
	}

	log {
		output file /var/log/caddy/access.log {
			roll_size 10MB
			roll_keep 5
		}
		level ERROR
		format json
	}
}

# Заглушка для активного пробинга. Домен = realitySettings.serverNames у ноды.
https://${DOMAIN} {
	tls /certs/fullchain.pem /certs/privkey.key
	encode gzip
	root * /srv
	try_files {path} /index.html
	file_server
	header {
		-Server
		Strict-Transport-Security "max-age=31536000"
	}
}
EOF

  # Стартовая страница-заглушка. Замени своими файлами в ${NODE_DIR}/selfsteal/www/
  cat >"${NODE_DIR}/selfsteal/www/index.html" <<'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Northwind Data Systems</title>
<style>
  body { margin:0; font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif; color:#12161c; background:#fbfcfe; }
  header { border-bottom:1px solid #e4e8ee; background:#fff; }
  .wrap { max-width:980px; margin:0 auto; padding:0 24px; }
  nav { display:flex; align-items:center; gap:10px; height:64px; font-weight:700; }
  .dot { width:10px; height:10px; border-radius:50%; background:#1f6feb; display:inline-block; }
  h1 { font-size:40px; line-height:1.15; letter-spacing:-.03em; margin:64px 0 16px; }
  p { color:#5b6673; max-width:640px; }
</style>
</head>
<body>
<header><div class="wrap"><nav><span class="dot"></span> Northwind Data Systems</nav></div></header>
<main class="wrap">
  <h1>Infrastructure that stays quiet.</h1>
  <p>Мы строим и эксплуатируем распределённые системы: наблюдаемость, автоматический failover
     и планирование мощностей для команд, которым важнее продукт, а не кластеры.</p>
  <p>hello@example.com</p>
</main>
</body>
</html>
HTML

  cat >"${NODE_DIR}/selfsteal/docker-compose.yml" <<'EOF'
services:
  selfsteal:
    image: caddy:2
    container_name: selfsteal
    hostname: selfsteal
    restart: always
    network_mode: host
    volumes:
      - '/opt/remnanode/selfsteal/Caddyfile:/etc/caddy/Caddyfile:ro'
      - '/opt/remnanode/selfsteal/www:/srv:ro'
      - '/opt/remnanode/certs:/certs:ro'
      - '/var/log/selfsteal:/var/log/caddy'
    logging:
      driver: json-file
      options:
        max-size: 10m
        max-file: 3
EOF

  if have docker; then
    ( cd "${NODE_DIR}/selfsteal" && docker compose up -d )
    sleep 2
    local code
    code="$(curl -sk --max-time 10 --resolve "${DOMAIN}:${SELFSTEAL_PORT}:127.0.0.1" "https://${DOMAIN}:${SELFSTEAL_PORT}/" -o /dev/null -w '%{http_code}' || true)"
    if [[ "$code" == "200" ]]; then
      ok "Self-steal отвечает: https://${DOMAIN}:${SELFSTEAL_PORT}/ → 200 (только с 127.0.0.1)"
    else
      warn "Заглушка не ответила (код: ${code:-таймаут}). Проверь: docker logs selfsteal; сертификат должен покрывать ${DOMAIN}"
    fi
  else
    warn "docker не установлен — Caddy не запущен"
  fi

  ok "В профиле RU-ноды: realitySettings.target = 127.0.0.1:${SELFSTEAL_PORT}, xver = 1, serverNames = [\"${DOMAIN}\"]"
}

# ==============================================================================
#  ШАГ 6. Remnawave Node
# ==============================================================================
step_node() {
  step "6/8 Remnawave Node (docker compose)"
  mkdir -p "$NODE_DIR" "$NODE_LOG_DIR" "$CERT_DIR"
  chmod 700 "$NODE_DIR"

  umask 077
  cat >"${NODE_DIR}/.env" <<EOF
# Секреты ноды. Не коммитить и не пересылать.
NODE_PORT=${NODE_PORT}
SECRET_KEY=${SECRET_KEY}
EOF
  chmod 600 "${NODE_DIR}/.env"

  if [[ -f "${NODE_DIR}/docker-compose.yml" ]]; then
    cp "${NODE_DIR}/docker-compose.yml" "${NODE_DIR}/docker-compose.yml.bak.$(date +%s)"
    log "Прежний docker-compose.yml сохранён как .bak"
  fi

  # при включённой заглушке монтируем её в ноду: landing для masquerade Hysteria2
  local www_mount=""
  if [[ "${SELFSTEAL:-0}" == "1" ]]; then
    www_mount="      # Заглушка для masquerade Hysteria2 (landing-страница)
      - '${NODE_DIR}/selfsteal/www:/var/www:ro'
"
  fi

  cat >"${NODE_DIR}/docker-compose.yml" <<EOF
services:
  remnanode:
    container_name: remnanode
    hostname: remnanode
    image: remnawave/node:latest
    restart: always
    network_mode: host
    env_file:
      - .env
    volumes:
${www_mount}      # Логи Xray: путь указывается в конфиге Xray как /var/log/remnanode/*.log
      - '/var/log/remnanode:/var/log/remnanode'
      # Сертификаты внутри контейнера: fullchain.pem + privkey.key
      - '${CERT_DIR}:/var/lib/remnawave/configs/xray/ssl'
      # Тот же каталог по короткому пути /ssl — для Config Profile,
      # где certificateFile: /ssl/fullchain.pem (частый шаблон)
      - '${CERT_DIR}:/ssl'
      # Доп. geo-файлы: монтируй ФАЙЛЫ, а не папку (иначе перекроешь штатные)
      # - './geo-custom.dat:/usr/local/share/xray/geo-custom.dat'
      # - './ip-custom.dat:/usr/local/share/xray/ip-custom.dat'
EOF
      # Логи Xray: путь указывается в конфиге Xray как /var/log/remnanode/*.log


  ( cd "$NODE_DIR" && docker compose up -d )
  sleep 3
  if docker ps --format '{{.Names}}' | grep -qx remnanode; then
    ok "Контейнер remnanode работает"
  else
    warn "Контейнер не поднялся. Проверь: cd $NODE_DIR && docker compose logs -t"
  fi
}

# ==============================================================================
#  ШАГ 6. Ротация логов
# ==============================================================================
step_logs() {
  step "7/8 Ротация логов (нода, journald, docker)"
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq logrotate >/dev/null
  mkdir -p "$NODE_LOG_DIR"

  cat >/etc/logrotate.d/remnanode <<'EOF'
/var/log/remnanode/*.log {
    size 50M
    rotate 5
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF

  cat >/etc/logrotate.d/ghostly <<'EOF'
/var/log/ghostly-installer.log {
    size 5M
    rotate 2
    compress
    missingok
    notifempty
    copytruncate
}
EOF

  mkdir -p /etc/systemd/journald.conf.d
  cat >/etc/systemd/journald.conf.d/99-ghostly.conf <<'EOF'
[Journal]
SystemMaxUse=200M
SystemMaxFileSize=50M
MaxRetentionSec=2week
EOF
  systemctl restart systemd-journald || true

  logrotate -f /etc/logrotate.d/remnanode >/dev/null 2>&1 || warn "logrotate: проверь конфиг (/etc/logrotate.d/remnanode)"
  ok "Ротация: /var/log/remnanode (50 МБ × 5), journald ≤ 200 МБ, Docker 50 МБ × 3"
}

# ==============================================================================
#  ШАГ 7. Дополнительная защита
# ==============================================================================
step_security() {
  step "8/8 Дополнительная защита"

  if [[ "${ENABLE_FAIL2BAN:-0}" == "1" ]]; then
    if DEBIAN_FRONTEND=noninteractive apt-get install -y -qq fail2ban >/dev/null 2>&1; then
      cat >/etc/fail2ban/jail.d/ghostly.local <<EOF
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
backend  = systemd

[sshd]
enabled = true
port    = ${SSH_PORT}
EOF
      systemctl enable -q --now fail2ban >/dev/null 2>&1 || true
      systemctl restart fail2ban >/dev/null 2>&1 || true
      if systemctl is-active --quiet fail2ban; then
        ok "fail2ban: SSH, 5 попыток → бан 1 час"
      else
        warn "fail2ban не запустился — journalctl -u fail2ban -n 50"
      fi
    else
      warn "fail2ban не установился — не критично"
    fi
  fi

  if [[ "${ENABLE_CROWDSEC:-0}" == "1" ]]; then
    log "Ставлю CrowdSec (локальные сценарии + community-блоклисты)…"
    if curl -fsS https://install.crowdsec.net | sh - >/dev/null 2>&1; then
      if ! DEBIAN_FRONTEND=noninteractive apt-get install -y -qq crowdsec crowdsec-firewall-bouncer-nftables >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq crowdsec crowdsec-firewall-bouncer-iptables >/dev/null 2>&1 || warn "пакеты bouncer не установились"
      fi
      systemctl enable -q --now crowdsec >/dev/null 2>&1 || true
      systemctl enable -q --now crowdsec-firewall-bouncer >/dev/null 2>&1 || true
      if systemctl is-active --quiet crowdsec; then
        ok "CrowdSec активен. Список блоклистов: cscli decisions list"
      else
        warn "CrowdSec не запустился — journalctl -u crowdsec -n 50"
      fi
    else
      warn "CrowdSec не установился (репозиторий недоступен) — не критично"
    fi
  fi

  if [[ "${HARDEN_SSH:-0}" == "1" ]]; then
    mkdir -p /etc/ssh/sshd_config.d
    cat >/etc/ssh/sshd_config.d/99-ghostly-hardening.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
MaxAuthTries 4
EOF
    if sshd -t 2>/dev/null; then
      systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
      ok "SSH: вход по паролю выключен, root — только по ключу"
    else
      rm -f /etc/ssh/sshd_config.d/99-ghostly-hardening.conf
      warn "Конфиг SSH не прошёл проверку — откатил, парольный вход оставлен"
    fi
  fi

  mkdir -p "$NODE_DIR"
  cat >"${NODE_DIR}/antitorrent-routing.snippet.json" <<'EOF'
{
  "type": "field",
  "protocol": ["bittorrent"],
  "outboundTag": "BLOCK"
}
EOF
  ok "Сниппет анти-торрент: ${NODE_DIR}/antitorrent-routing.snippet.json (вставить в Config Profile)"
}

# ==============================================================================
#  Отчёт
# ==============================================================================
write_summary() {
  {
    echo "Ghostly Infra-installer v$VERSION — отчёт $(date '+%F %T')"
    echo
    echo "Домен:      ${DOMAIN}"
    echo "NODE_PORT:  ${NODE_PORT}"
    echo "Панель:     ${PANEL_IPS:-не ограничена}"
    echo "TCP:        ${TCP_PORTS}    UDP: ${UDP_PORTS}    SSH: ${SSH_PORT}"
    if [[ -n "${BRIDGE_PORT:-}" ]]; then
      echo "Мост:       порт ${BRIDGE_PORT} открыт только: ${BRIDGE_IPS}"
    fi
    if [[ "${SELFSTEAL:-0}" == "1" ]]; then
      echo "Self-steal: Caddy на 127.0.0.1:${SELFSTEAL_PORT}, сайт: ${NODE_DIR}/selfsteal/www"
      echo "            target=127.0.0.1:${SELFSTEAL_PORT}, xver=1, serverNames=[\"${DOMAIN}\"]"
    else
      echo "Self-steal: выключен"
    fi
    echo "strict: ${STRICT}  fail2ban: ${ENABLE_FAIL2BAN}  crowdsec: ${ENABLE_CROWDSEC}  harden-ssh: ${HARDEN_SSH}"
    echo
    echo "Файлы:"
    echo "  конфиг:   $CONFIG_FILE (0600)"
    echo "  правила:  $NFT_FILE"
    echo "  compose:  $NODE_DIR/docker-compose.yml"
    echo "  серты:    $CERT_DIR/fullchain.pem + $CERT_DIR/privkey.key"
    echo "  логи:     $NODE_LOG_DIR (ротация 50 МБ × 5)"
    echo
    echo "Служебные команды: ghostly status | apply-firewall | allow-panel | logs | panic | renew-cert"
    echo
    echo "=== Дальше в панели ==="
    echo "1. Nodes → Management: нода должна стать online."
    echo "2. VLESS-Vision-TLS: сертификат нужен ПАНЕЛИ, она передаёт его ноде."
    echo "   Панель читает /var/lib/remnawave/configs/xray/ssl/ — на сервере панели:"
    echo "     mkdir -p /opt/remnawave/nginx"
    echo "     scp $CERT_DIR/fullchain.pem $CERT_DIR/privkey.key root@IP_ПАНЕЛИ:/opt/remnawave/nginx/"
    echo "   и добавить в docker-compose панели строку:"
    echo "     - '/opt/remnawave/nginx:/var/lib/remnawave/configs/xray/ssl'"
    echo "   Для Reality сертификат не нужен."
    echo "3. Анти-торрент: в Config Profile добавить правило из"
    echo "   $NODE_DIR/antitorrent-routing.snippet.json"
    echo "   (в inbound должен быть включён sniffing с destOverride http/tls/quic)."
    echo "   Максимальный эффект — плагин 'Torrent Blocker' в панели."
    echo "4. Обновление: cd $NODE_DIR && docker compose pull && docker compose up -d"
    echo "5. Если потерял доступ: ghostly panic (снимает правила ghostly)."
  } >"$SUMMARY_FILE"
  chmod 600 "$SUMMARY_FILE"
}

banner() {
  printf '%s%s' "$C_BLD" "$C_CYN"
  cat <<'EOF'
  ____ _   _  ___  ____ _____ _   _ __   __
 / ___| | | |/ _ \/ ___|_   _| | | |\ \ / /
| |  _| |_| | | | \___ \ | | | |_| | \ V /
| |_| |  _  | |_| |___) || | |  _  |  | |
 \____|_| |_|\___/|____/ |_| |_| |_|  |_|   Infra-installer
EOF
  printf '%s' "$C_RESET"
  printf ' %s v%s — Remnawave Node: установка, сертификаты, защита, логи%s\n' "$APP" "$VERSION" "$C_RESET"
  printf '%sЛог: %s%s\n' "$C_DIM" "$LOG_FILE" "$C_RESET"
}

banner
collect_input
(( DO_TUNING ))   && step_tuning
(( DO_FIREWALL )) && step_firewall
(( DO_DOCKER ))   && step_docker
(( DO_CERTS ))    && step_certs
if (( DO_SELFSTEAL )) && [[ "${SELFSTEAL:-0}" == "1" ]]; then step_selfsteal; fi
(( DO_NODE ))     && step_node
(( DO_LOGS ))     && step_logs
step_security

step "Готово"
write_summary
printf '%s%s%s\n' "$C_GRN" "Установка завершена. Отчёт: $SUMMARY_FILE" "$C_RESET"
printf '\n%sДальше:%s\n' "$C_BLD" "$C_RESET"
printf '  ghostly status            — состояние ноды, правил, портов, сертификата\n'
printf '  docker logs -f remnanode  — живые логи ноды\n'
printf '  cd %s && docker compose pull && docker compose up -d   — обновление ноды\n' "$NODE_DIR"
printf '  ghostly panic             — снять правила firewall, если потерял доступ\n\n'
