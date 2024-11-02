apt update > /dev/null

# パッケージリストを配列として定義
packages=(
    "software-properties-common"
    "wget"
    "redis-server"
    "libsnmp-dev"
    "libtonezone-dev"
    "libpq-dev"
    "liblua5.2-dev"
    "libpri-dev"
    "libbluetooth-dev"
    "libunbound-dev"
    "libsybdb5"
    "libspeexdsp-dev"
    "libiksemel-dev"
    "libresample1-dev"
    "libgmime-3.0-dev"
    "libc-client2007e-dev"
    "dpkg-dev"
    "ghostscript"
    "libtiff-tools"
    "iptables-persistent"
    "net-tools"
    "rsyslog"
    "nmap"
    "apache2"
    "zip"
    "incron"
    "vim"
    "openssh-server"
    "mariadb-server"
    "bison"
    "flex"
    "flite"
    "php8.2"
    "php8.2-curl"
    "php8.2-zip"
    "php8.2-redis"
    "php8.2-mysql"
    "php8.2-gd"
    "php8.2-mbstring"
    "php8.2-intl"
    "php8.2-xml"
    "php8.2-bz2"
    "php8.2-ldap"
    "php8.2-sqlite3"
    "php8.2-bcmath"
    "php8.2-soap"
    "php8.2-ssh2"
    "php-pear"
    "curl"
    "sox"
    "libncurses5-dev"
    "mpg123"
    "libxml2-dev"
    "libnewt-dev"
    "sqlite3"
    "libsqlite3-dev"
    "git"
    "unixodbc-dev"
    "uuid"
    "libasound2-dev"
    "libogg-dev"
    "libvorbis-dev"
    "libcurl4-openssl-dev"
    "odbc-mariadb"
    "libical-dev"
    "libneon27-dev"
    "libsrtp2-dev"
    "libspandsp-dev"
    "sudo"
    "subversion"
    "python-dev-is-python3"
    "unixodbc"
    "libjansson-dev"
    "nodejs"
    "npm"
    "ipset"
    "fail2ban"
    "htop"
    "liburiparser-dev"
    "postfix"
    "tcpdump"
    "sngrep"
    "libavdevice-dev"
    "tftpd-hpa"
    "xinetd"
    "lame"
    "haproxy"
    "screen"
    "easy-rsa"
    "openvpn"
    "sysstat"
    "apt-transport-https"
    "cron"
    "python3-mysqldb"
    "default-libmysqlclient-dev"
    "at"
    "avahi-daemon"
    "avahi-utils"
    "mailutils"
)

for pkg in "${packages[@]}"; do
    version=$(apt policy "$pkg" 2>/dev/null | grep "Candidate" | awk '{print $2}')
    echo "$pkg=${version}"
done

exit 0
for pkg in "${packages[@]}"; do
    version=$(apt install "$pkg" -y)
    echo "$pkg=${version}"
done

