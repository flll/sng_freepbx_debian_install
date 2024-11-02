#!/bin/bash
#####################################################################################
# * Copyright 2024 by Sangoma Technologies
# このプログラムはフリーソフトウェアです。あなたはこれを、フリーソフトウェア財団によって発行された
# GNU一般公衆利用許諾契約書(バージョン3か、それ以降のバージョンのうちどれか)が定める条件の下で
# 再頒布または改変することができます。
#
# このプログラムは有用であることを願って頒布されますが、*全くの無保証* です。
# 商業可能性の保証や特定の目的への適合性は、言外に示されたものも含め全く存在しません。
# 詳しくはGNU一般公衆利用許諾契約書をご覧ください。
#
# @author kgupta@sangoma.com
#
# このFreePBXインストールスクリプトとすべての概念はSangoma Technologiesの所有物です。
# このインストールスクリプトは、FreePBXと依存パッケージのインストールにのみ
# 自由に使用できますが、性能に関する保証はなく、自己責任で使用してください。
# このスクリプトには保証はありません。
## 追記:
# このスクリプトは
# https://github.com/FreePBX/sng_freepbx_debian_install/blob/25ee336fc38b3d3a4142a39a09824086158f71c6/sng_freepbx_debian_install.sh
# を日本語に翻訳したものです。(2024/10/28) (commit: 25ee336fc38b3d3a4142a39a09824086158f71c6)
## 変更点
# - Edited: で検索してください
#####################################################################################
#                                               FreePBX 17                          #
#####################################################################################

set -e
SCRIPTVER="1.14"
ASTVERSION=21
PHPVERSION="8.2"
LOG_FOLDER="/var/log/pbx"
LOG_FILE="${LOG_FOLDER}/freepbx17-install-$(date '+%Y.%m.%d-%H.%M.%S').log"
log=$LOG_FILE
SANE_PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
DEBIAN_MIRROR="http://ftp.debian.org/debian"
NPM_MIRROR=""

# root権限のチェック
if [[ $EUID -ne 0 ]]; then
   echo "このスクリプトはroot権限で実行する必要があります"
   exit 1
fi


# スクリプト実行のための適切なPATHを設定
export PATH=$SANE_PATH

while [[ $# -gt 0 ]]; do
	case $1 in
		--testing)
			testrepo=true
			shift
			;;
		--nofreepbx)
			nofpbx=true
			shift
			;;
		--noasterisk)
			noast=true
			shift
			;;
		--opensourceonly)
			opensourceonly=true
			shift
			;;
		--noaac)
			noaac=true
			shift
			;;
		--skipversion)
			skipversion=true
			shift
			;;
		--dahdi)
			dahdi=true
			shift
			;;
		--dahdi-only)
			nofpbx=true
			noast=true
			noaac=true
			dahdi=true
			shift
			;;
		--nochrony)
			nochrony=true
			shift
			;;
		--debianmirror)
			DEBIAN_MIRROR=$2
			shift; shift
			;;
    --npmmirror)
      NPM_MIRROR=$2
      shift; shift
      ;;
		-*)
			echo "不明なオプション $1"
			exit 1
			;;
		*)
			echo "不明な引数 \"$1\""
			exit 1
			;;
	esac
done

# ログファイルの作成
mkdir -p "${LOG_FOLDER}"
touch "${LOG_FILE}"

# 標準エラー出力をログファイルにリダイレクト
exec 2>>"${LOG_FILE}"

#バージョン比較
compare_version() {
        if dpkg --compare-versions "$1" "gt" "$2"; then
                result=0
        elif dpkg --compare-versions "$1" "lt" "$2"; then
                result=1
        else
                result=2
        fi
}

check_version() {
    # 最新バージョンとチェックサムの取得
    REPO_URL="https://github.com/FreePBX/sng_freepbx_debian_install/raw/master"
    wget -O /tmp/sng_freepbx_debian_install_latest_from_github.sh "$REPO_URL/sng_freepbx_debian_install.sh" >> "$log"

    latest_version=$(grep '^SCRIPTVER="' /tmp/sng_freepbx_debian_install_latest_from_github.sh | awk -F'"' '{print $2}')
    latest_checksum=$(sha256sum /tmp/sng_freepbx_debian_install_latest_from_github.sh | awk '{print $1}')

    # ダウンロードしたファイルの削除
    rm -f /tmp/sng_freepbx_debian_install_latest_from_github.sh

    compare_version $SCRIPTVER $latest_version

    case $result in
            0)
                echo "インストールスクリプトのバージョン($SCRIPTVER)がGitHubの最新バージョン($latest_version)より新しいです。GitHubにあるバージョンをダウンロードすることをお勧めします。"
                echo "バージョンチェックをスキップするには '$0 --skipversion' を使用してください"
                exit 1
            ;;

            1)
                echo "GitHubに新しいバージョン($latest_version)のインストールスクリプトがあります。更新するか、GitHubから最新のものを使用することをお勧めします。"
                echo "バージョンチェックをスキップするには '$0 --skipversion' を使用してください。"
                exit 0
            ;;

            2)
                local_checksum=$(sha256sum "$0" | awk '{print $1}')
                if [[ "$latest_checksum" != "$local_checksum" ]]; then
                        echo "ローカルのインストールスクリプトとGitHubの最新インストールスクリプトの間に変更が検出されました。GitHubにある最新のインストールスクリプトを使用することをお勧めします。"
                        echo "バージョンチェックをスキップするには '$0 --skipversion' を使用してください"
                        exit 0
                else
                        echo "完璧です！既に最新バージョンを実行しています。"
                fi
            ;;
        esac
}

# メッセージをログに記録する関数
log() {
	echo "$(date +"%Y-%m-%d %T") - $*" >> "$LOG_FILE"
}

message() {
	echo "$(date +"%Y-%m-%d %T") - $*"
	log "$*"
}

#現在のステップを記録し表示する関数
setCurrentStep () {
	currentStep="$1"
	message "${currentStep}"
}

# インストールをクリーンアップする関数
terminate() {
	# pidファイルの削除
	message "スクリプトを終了します"
	rm -f "$pidfile"
}

#エラーとその場所をログに記録する関数
errorHandler() {
	log "****** インストールに失敗しました *****"
	message "ステップ ${currentStep} でインストールに失敗しました。詳細は ${LOG_FILE} を確認してください。"
	message "エラー発生行: $1 終了コード $2 (最後のコマンド: $3)"
	exit "$2"
}

# パッケージがすでにインストールされているかどうかを確認する
isinstalled() {
	PKG_OK=$(dpkg-query -W --showformat='${Status}\n' "$@" 2>/dev/null|grep "install ok installed")
	if [ "" = "$PKG_OK" ]; then
		false
	else
		true
	fi
}

# パッケージをインストールする関数
pkg_install() {
	log "############################### "
	PKG=$@
	if isinstalled $PKG; then
		log "$PKG はすでに存在します ...."
	else
		message "$PKG をインストールしています ...."
		apt-get -y --ignore-missing -o DPkg::Options::="--force-confnew" -o Dpkg::Options::="--force-overwrite" install $PKG >> $log
		if isinstalled $PKG; then
			message "$PKG のインストールに成功しました ...."
		else
			message "$PKG のインストールに失敗しました ...."
			message "依存パッケージ $PKG のインストールに失敗したため、インストールプロセスを終了します ...."
			terminate
		fi
	fi
	log "############################### "
}

# Asteriskと依存パッケージをインストールする関数
install_asterisk() {
	astver=$1
	ASTPKGS=("addons"
		"addons-bluetooth"
		"addons-core"
		"addons-mysql"
		"addons-ooh323"
		"core"
		"curl"
		"dahdi"
		"doc"
		"odbc"
		"ogg"
		"flite"
		"g729"
		"resample"
		"snmp"
		"speex"
		"sqlite3"
		"res-digium-phone"
		"voicemail"
	)

	# ディレクトリの作成
	mkdir -p /var/lib/asterisk/moh
	pkg_install asterisk$astver

	for i in "${!ASTPKGS[@]}"; do
		pkg_install asterisk$astver-${ASTPKGS[$i]}
	done

	pkg_install asterisk$astver.0-freepbx-asterisk-modules
	pkg_install asterisk-version-switch
	# pkg_install asterisk-sounds-* # **Edited: コメントアウト**
}

setup_repositories() {
	apt-key del "9641 7C6E 0423 6E0A 986B  69EF DE82 7447 3C8D 0E52" >> "$log"

	wget -O - http://deb.freepbx.org/gpg/aptly-pubkey.asc | gpg --dearmor --yes -o /etc/apt/trusted.gpg.d/freepbx.gpg  >> "$log"

	# デフォルトのリポジトリサーバーの設定
	if [ $testrepo ] ; then
		add-apt-repository -y -S "deb [ arch=amd64 ] http://deb.freepbx.org/freepbx17-dev bookworm main" >> "$log"
		add-apt-repository -y -S "deb [ arch=amd64 ] http://deb.freepbx.org/freepbx17-dev bookworm main" >> "$log"
	else
		add-apt-repository -y -S "deb [ arch=amd64 ] http://deb.freepbx.org/freepbx17-prod bookworm main" >> "$log"
		add-apt-repository -y -S "deb [ arch=amd64 ] http://deb.freepbx.org/freepbx17-prod bookworm main" >> "$log"
	fi

	if [ ! $noaac ] ; then
		add-apt-repository -y -S "deb $DEBIAN_MIRROR stable main non-free non-free-firmware" >> "$log"
	fi

	setCurrentStep "Sangomaリポジトリの設定"
    local aptpref="/etc/apt/preferences.d/99sangoma-fpbx-repository"
    cat << EOF > $aptpref
Package: *
Pin: origin deb.freepbx.org
Pin-Priority: ${MIRROR_PRIO}
EOF
    if [ $noaac ]; then
    cat << EOF >> $aptpref

Package: ffmpeg
Pin: origin deb.freepbx.org
Pin-Priority: 1
EOF
    fi
}

#aptコマンド実行後に実行するスクリプトを作成
create_post_apt_script() {
    #post-apt-runスクリプトの確認
    if [ -e "/usr/bin/post-apt-run" ]; then
        rm -f /usr/bin/post-apt-run
    fi

    message "すべてのaptコマンド実行後に実行するスクリプトを作成しています"
    {
        echo "#!/bin/bash"
        echo ""
        echo "kernel_idx=\$(grep GRUB_DEFAULT /etc/default/grub | cut -d '=' -f 2)"
        echo "kernel_pres=\$(sed -n '/^menuentry/,/}/p' /boot/grub/grub.cfg  | grep -o -P 'vmlinuz-\S+')"
        echo ""
        echo "dahdi_pres=\$(dpkg -l | grep dahdi-linux | wc -l)"
        echo ""
        echo "if [[ \$dahdi_pres -gt 0 ]]; then"
        echo "    idx=0"
        echo "    for kernel in \$kernel_pres; do"
        echo "        if [[ \$idx -ne \$kernel_idx ]]; then"
        echo "            idx=\$((idx+1))"
        echo "            continue"
        echo "        fi"
        echo ""
        echo "        kernel_ver=\$(echo \$kernel | sed -n -e 's/vmlinuz-\([[:digit:].-]*\).*/\\1/' -e 's/-$//p')"
        echo "        logger \"カーネルイメージ \$kernel_ver のdahdiとwanpipeのカーネルモジュールを確認しています\""
        echo ""
        echo "        #対応するカーネルバージョンのdahdiがインストールされているかどうかを確認"
        echo "        dahdi_kmod_pres=\$(dpkg -l | grep dahdi-linux-kmod | grep \$kernel_ver | wc -l)"
        echo "        wanpipe_kmod_pres=\$(dpkg -l | grep kmod-wanpipe | grep \$kernel_ver | wc -l)"
        echo ""
        echo "        if [[ \$dahdi_kmod_pres -eq 0 ]] && [[ \$wanpipe_kmod_pres -eq 0 ]]; then"
        echo "            logger \"dahdi-linux-kmod-\$kernel_ver と kmod-wanpipe-\$kernel_ver をアップグレードしています\""
        echo "            echo \"aptコマンドの実行が完了してから約2分お待ちください。dahdi-linux-kmod-\$kernel_ver kmod-wanpipe-\$kernel_ver の更新が進行中です\""
        echo "            apt -y upgrade dahdi-linux-kmod-\$kernel_ver kmod-wanpipe-\$kernel_ver > /dev/null 2>&1 | at now +1 minute&"
        echo "        elif [[ \$dahdi_kmod_pres -eq 0 ]]; then"
        echo "            logger \"dahdi-linux-kmod-\$kernel_ver をアップグレードしています\""
        echo "            echo \"aptコマンドの実行が完了してから約2分お待ちください。dahdi-linux-kmod-\$kernel_ver の更新が進行中です\""
        echo "            apt -y upgrade dahdi-linux-kmod-\$kernel_ver > /dev/null 2>&1 | at now +1 minute&"
        echo "        elif [[ \$wanpipe_kmod_pres -eq 0 ]];then"
        echo "            logger \"kmod-wanpipe-\$kernel_ver をアップグレードしています\""
        echo "            echo \"aptコマンドの実行が完了してから約2分お待ちください。kmod-wanpipe-\$kernel_ver の更新が進行中です\""
        echo "            apt -y upgrade kmod-wanpipe-\$kernel_ver > /dev/null 2>&1 | at now +1 minute&"
        echo "        fi"
        echo ""
        echo "        break"
        echo "    done"
        echo "else"
        echo "    logger \"Dahdi / wanpipeが存在しないため、dahdi / wanpipe kmodのアップグレードを確認しません\""
        echo "fi"
        echo ""
        echo "if [ -e "/var/www/html/index.html" ]; then"
        echo "    rm -f /var/www/html/index.html"
        echo "fi"
    } >> /usr/bin/post-apt-run

    #スクリプト実行のためのファイル権限変更
    chmod 755 /usr/bin/post-apt-run

    #カーネルチェックを実行するためのPost Invokeの追加
    if [ -e "/etc/apt/apt.conf.d/80postaptcmd" ]; then
        rm -f /etc/apt/apt.conf.d/80postaptcmd
    fi

    echo "DPkg::Post-Invoke {\"/usr/bin/post-apt-run\";};" >> /etc/apt/apt.conf.d/80postaptcmd
    chmod 644 /etc/apt/apt.conf.d/80postaptcmd
}

check_kernel_compatibility() {
    local latest_dahdi_supported_version=$(apt-cache search dahdi | grep -E "^dahdi-linux-kmod-[0-9]" | awk '{print $1}' | awk -F'-' '{print $4"-"$5}' | sort -n | tail -1)
    local latest_wanpipe_supported_version=$(apt-cache search wanpipe | grep -E "^kmod-wanpipe-[0-9]" | awk '{print $1}' | awk -F'-' '{print $3"-"$4}' | sort -n | tail -1)
    local curr_kernel_version=$1

    if dpkg --compare-versions "$latest_dahdi_supported_version" "eq" "$latest_wanpipe_supported_version"; then
        local supported_kernel_version=$latest_dahdi_supported_version
    else
        local supported_kernel_version="6.1.0.22"
    fi

    if dpkg --compare-versions "$curr_kernel_version" "gt" "$supported_kernel_version"; then
        message "検出されたカーネルバージョン $curr_kernel_version は freepbx dahdi モジュール $supported_kernel_version でサポートされていないため、freepbx のインストールを中止します"
	exit
    fi

    if [ -e "/usr/bin/kernel-check" ]; then
        rm -f /usr/bin/kernel-check
    fi

    if [ $testrepo ]; then
        message "カーネルチェックをスキップします。テストリポジトリではカーネルチェックは不要です....."
        return
    fi

    message "適切なカーネルアップグレードを許可するためのカーネルチェックスクリプトを作成しています"
    {
        echo "#!/bin/bash"
        echo ""
        echo "curr_kernel_version=\"\""
        echo "supported_kernel_version=\"\""
        echo ""

        echo "set_supported_kernel_version() {"
        echo "    local latest_dahdi_supported_version=\$(apt-cache search dahdi | grep -E \"^dahdi-linux-kmod-[0-9]\" | awk '{print \$1}' | awk -F'-' '{print \$4,-\$5}' | sed 's/[[:space:]]//g' | sort -n | tail -1)"
        echo "    local latest_wanpipe_supported_version=\$(apt-cache search wanpipe | grep -E \"^kmod-wanpipe-[0-9]\" | awk '{print \$1}' | awk -F'-' '{print \$3,-\$4}' | sed 's/[[:space:]]//g' | sort -n | tail -1)"
        echo "    curr_kernel_version=\$(uname -r | cut -d'-' -f1-2)"
        echo ""
        echo "    if dpkg --compare-versions \"\$latest_dahdi_supported_version\" \"eq\" \"\$latest_wanpipe_supported_version\"; then"
        echo "        supported_kernel_version=\$latest_dahdi_supported_version"
        echo "    else"
        echo "        supported_kernel_version=\"6.1.0-21\""
        echo "    fi"
        echo "}"
        echo ""

        echo "check_and_unblock_kernel() {"
        echo "    local kernel_packages=\$(apt-mark showhold | grep -E ^linux-image-[0-9] | awk '{print \$1}')"
        echo ""
        echo "    if [[ \"w\$1\" != \"w\" ]]; then"
        echo "        # バージョンを現在サポートされているカーネルバージョンと比較"
        echo "        if dpkg --compare-versions \"\$1\" \"le\" \"\$supported_kernel_version\"; then"
        echo "            local is_on_hold=\$(apt-mark showhold | grep -E ^linux-image-[0-9] | awk '{print \$1}' | grep -w \"\$1\" | wc -l )"
        echo ""
        echo "            if [[ \$is_on_hold -gt 0 ]]; then"
        echo "                logger \"自動更新を許可するためにカーネルバージョン \$version のホールドを解除します。\""
        echo "                apt-mark unhold \"\$version\" >> /dev/null 2>&1"
        echo "            fi"
        echo "        fi"
        echo "        return"
        echo "    fi"
        echo ""
        echo "    for package in \$kernel_packages; do"
        echo "        # パッケージ名からバージョンを抽出"
        echo "        local version=\$(echo \"\$package\" | awk -F'-' '{print \$3,-\$4}' | sed 's/[[:space:]]//g' | sort -n)"
        echo ""
        echo "        # バージョンを現在サポートされているカーネルバージョンと比較"
        echo "        if dpkg --compare-versions \"\$version\" \"le\" \"\$supported_kernel_version\"; then"
        echo "            logger \"自動更新を許可するためにカーネルバージョン \$version のホールドを解除します。\""
        echo "            apt-mark unhold \"\$version\" >> /dev/null 2>&1"
        echo "        fi"
        echo "    done"
        echo "}"

        echo ""
        echo "check_and_block_kernel() {"
        echo "    if dpkg --compare-versions \"\$curr_kernel_version\" \"gt\" \"\$supported_kernel_version\"; then"
        echo "        logger \"検出されたカーネルバージョンは freepbx dahdi モジュールでサポートされていないため中止します\""
        echo "    fi"
        echo ""

        echo "    local kernel_packages=\$( apt-cache search linux-image | grep -E "^linux-image-[0-9]" | awk '{print \$1}')"
        echo "    for package in \$kernel_packages; do"
        echo "        # パッケージ名からバージョンを抽出"
        echo "        local version=\$(echo \"\$package\" | awk -F'-' '{print \$3,-\$4}' | sed 's/[[:space:]]//g' | sort -n)"
        echo ""

        echo "        # バージョンを現在サポートされているカーネルバージョンと比較"
        echo "        if dpkg --compare-versions \"\$version\" \"gt\" \"\$supported_kernel_version\"; then"
        echo "            logger \"自動更新を防ぐためにカーネルバージョン \$version をホールドします。\""
        echo "            apt-mark hold \"\$version\" >> /dev/null 2>&1"
        echo "        else"
        echo "            check_and_unblock_kernel \$version"
        echo "        fi"
        echo "    done"
        echo "}"

        echo ""
        echo "case \$1 in"
        echo "    --hold)"
        echo "        hold=true"
        echo "        ;;"
        echo ""
        echo "    --unhold)"
        echo "        unhold=true"
        echo "        ;;"
        echo ""
        echo "    *)"
        echo "        logger \"不明 / 無効なオプション \$1\""
        echo "        exit 1"
        echo "        ;;"
        echo "esac"
        echo ""
        echo "set_supported_kernel_version"
        echo ""
        echo "if [[ \$hold ]]; then"
        echo "    check_and_block_kernel"
        echo "elif [[ \$unhold ]]; then"
        echo "    check_and_unblock_kernel"
        echo "fi"
    } >> /usr/bin/kernel-check

    #スクリプトを実行するためにファイルのパーミッションを変更
    chmod 755 /usr/bin/kernel-check

    #カーネルチェックを実行するためにアップデート後の呼び出しを追加
    if [ -e "/etc/apt/apt.conf.d/05checkkernel" ]; then
        rm -f /etc/apt/apt.conf.d/05checkkernel
    fi
    echo "APT::Update::Post-Invoke {\"/usr/bin/kernel-check --hold\"}" >> /etc/apt/apt.conf.d/05checkkernel
    chmod 644 /etc/apt/apt.conf.d/05checkkernel
}

refresh_signatures() {
  fwconsole ma refreshsignatures >> "$log"
}

check_services() {
    services=("fail2ban" "iptables")
    for service in "${services[@]}"; do
        service_status=$(systemctl is-active "$service")
        if [[ "$service_status" != "active" ]]; then
            message "サービス $service がアクティブではありません。実行中であることを確認してください。"
        fi
    done

    apache2_status=$(systemctl is-active apache2)
    if [[ "$apache2_status" == "active" ]]; then
        apache_process=$(netstat -anp | awk '$4 ~ /:80$/ {sub(/.*\//,"",$7); print $7}')
        if [ "$apache_process" == "apache2" ]; then
            message "Apache2サービスがポート80で実行中です。"
        else
            message "Apache2がポート80で実行されていません。"
        fi
    else
        message "Apache2サービスがアクティブではありません。サービスを有効にしてください。"
    fi
}

check_php_version() {
    php_version=$(php -v | grep built: | awk '{print $2}')
    if [[ "${php_version:0:3}" == "8.2" ]]; then
        message "インストールされているPHPバージョン $php_version はFreePBXと互換性があります。"
    else
        message "インストールされているPHPバージョン $php_version はFreePBXと互換性がありません。PHPバージョン'8.2.x'をインストールしてください。"
    fi

    # 有効なPHPモジュールがPHP 8.2バージョンであるかチェック
    php_module_version=$(a2query -m | grep php | awk '{print $1}')

    if [[ "$php_module_version" == "php8.2" ]]; then
       log "PHPモジュールバージョン $php_module_version はFreePBXと互換性があります。スクリプトを続行します。"
    else
       log "インストールされているPHPモジュールバージョン $php_module_version はFreePBXと互換性がありません。PHPバージョン'8.2'をインストールしてください。"
       exit 1
    fi
}

verify_module_status() {
    modules_list=$(fwconsole ma list | grep -Ewv "Enabled|----|Module|No repos")
    if [ -z "$modules_list" ]; then
        message "すべてのモジュールが有効です。"
    else
        message "有効になっていないモジュールのリスト："
        message "$modules_list"
    fi
}

# サービスに割り当てられたポートをチェックする関数
inspect_network_ports() {
    # ポートとサービスのペアの配列
    local ports_services=(
        82 restapps
        83 restapi
        81 ucp
        80 acp
        84 hpro
        "" leport
        "" sslrestapps
        "" sslrestapi
        "" sslucp
        "" sslacp
        "" sslhpro
        "" sslsngphone
    )

    for (( i=0; i<${#ports_services[@]}; i+=2 )); do
        port="${ports_services[i]}"
        service="${ports_services[i+1]}"
        port_set=$(fwconsole sa ports | grep "$service" | cut -d'|' -f 2 | tr -d '[:space:]')

        if [ "$port_set" == "$port" ]; then
            message "$serviceモジュールはデフォルトのポートに割り当てられています。"
        else
            message "$serviceモジュールは$port_setの代わりにポート$portが割り当てられていることが期待されます。"
        fi
    done
}

inspect_running_processes() {
    processes=$(fwconsole pm2 --list |  grep -Ewv "online|----|Process")
    if [ -z "$processes" ]; then
        message "オフラインのプロセスは見つかりませんでした。"
    else
        message "オフラインのプロセスのリスト："
        message "$processes"
    fi
}

check_freepbx() {
     # FreePBXがインストールされているかチェック
    if ! dpkg -l | grep -q 'freepbx'; then
        message "FreePBXがインストールされていません。続行するにはFreePBXをインストールしてください。"
    else
        verify_module_status
	if [ ! $opensourceonly ] ; then
        	inspect_network_ports
	fi
        inspect_running_processes
        inspect_job_status=$(fwconsole job --list)
        message "ジョブリスト : $inspect_job_status"
    fi
}

check_digium_phones_version() {
    installed_version=$(asterisk -rx 'digium_phones show version' | awk '/Version/{print $NF}' 2>/dev/null)
    if [[ -n "$installed_version" ]]; then
        required_version="21.0_3.6.8"
        present_version=$(echo "$installed_version" | sed 's/_/./g')
        required_version=$(echo "$required_version" | sed 's/_/./g')
        if dpkg --compare-versions "$present_version" "lt" "$required_version"; then
            message "Digium Phonesモジュールの新しいバージョンが利用可能です。"
        else
            message "インストールされているDigium Phonesモジュールのバージョン: ($installed_version)"
        fi
    else
        message "Digium Phonesモジュールのバージョン確認に失敗しました。"
    fi
}

check_asterisk() {
    if ! dpkg -l | grep -q 'asterisk'; then
        message "Asteriskがインストールされていません。続行するにはAsteriskをインストールしてください。"
    else
        check_asterisk_version=$(asterisk -V)
        message "$check_asterisk_version"
	if asterisk -rx "module show" | grep -q "res_digium_phone.so"; then
            check_digium_phones_version
        else
            message "Digium Phonesモジュールがロードされていません。正しくインストールされ、ロードされていることを確認してください。"
        fi
    fi
}

hold_packages() {
    # ホールドするパッケージ名のリスト
    local packages=("sangoma-pbx17" "nodejs" "node-*")
    if [ ! $nofpbx ] ; then
        packages+=("freepbx17")
    fi

    # 各パッケージをループしてホールドする
    for pkg in "${packages[@]}"; do
        apt-mark hold "$pkg" >> "$log"
    done
}

################################################################################################################
MIRROR_PRIO=600
kernel=$(uname -a)
host=$(hostname)
fqdn="$(hostname -f)" || true

# wgetをインストール（バージョンチェックに必要）
pkg_install wget

# スクリプトのバージョンチェック
if [[ $skipversion ]]; then
    message "バージョンチェックをスキップしています..."
else
    # --skipversionが提供されていない場合、バージョンチェックを実行
    message "バージョンチェックを実行しています..."
    check_version
fi

# コンテナ内で実行されているかチェック
if systemd-detect-virt --container &> /dev/null; then
	message "コンテナ内で実行されています。Chronyのインストールをスキップします。"
	nochrony=true
fi

# 64ビットシステムで実行されているかチェック
ARCH=$(dpkg --print-architecture)
if [ "$ARCH" != "amd64" ]; then
    message "FreePBX 17のインストールは64ビット（amd64）システムでのみ可能です！"
    message "現在のシステムのアーキテクチャ: $ARCH"
    exit 1
fi

# hostnameコマンドが成功し、FQDNが空でないことを確認
if [ -z "$fqdn" ]; then
    echo "完全修飾ドメイン名（FQDN）が正しく設定されていません。"
    echo "このシステムのFQDNを設定し、スクリプトを再実行してください。"
    echo "FQDNを設定するには、/etc/hostnameと/etc/hostsファイルを更新してください。"
    exit 1
fi

#スクリプトが実行中でないことを確認
pid="$$"
pidfile='/var/run/freepbx17_installer.pid'

if [ -f "$pidfile" ]; then
	log "以前のPIDファイルが見つかりました。"
	if ps -p "${pid}" > /dev/null
	then
		message "FreePBX 17のインストールプロセスが既に進行中です（PID=${pid}）。新しいプロセスは開始しません。"
		exit 1;
	fi
	log "古いPIDファイルを削除しています"
	rm -f "${pidfile}"
fi

setCurrentStep "インストールを開始しています。"
trap 'errorHandler "$LINENO" "$?" "$BASH_COMMAND"' ERR
trap "terminate" EXIT
echo "${pid}" > $pidfile

start=$(date +%s)
message "  $host $kernelのFreePBX 17インストールプロセスを開始しています"
message "  プロセスの詳細は$logを参照してください..."
log "  スクリプトv$SCRIPTVERを実行しています..."

setCurrentStep "インストールが正常であることを確認しています"
# 壊れたインストールを修正
apt-get -y --fix-broken install >> $log
apt-get autoremove -y >> "$log"

# CD-ROMリポジトリがsources.listファイルに存在するかチェック
if grep -q "^deb cdrom" /etc/apt/sources.list; then
  # sources.listファイルのCD-ROMリポジトリ行をコメントアウト
  sed -i '/^deb cdrom/s/^/#/' /etc/apt/sources.list
  message "sources.listのCD-ROMリポジトリをコメントアウトしました"
fi

apt-get update >> $log

# "iptables-persistent"とpostfixが入力を求めないようにiptablesとpostfixの入力を追加
setCurrentStep "デフォルト設定をセットアップしています"
debconf-set-selections <<EOF
iptables-persistent iptables-persistent/autosave_v4 boolean true
iptables-persistent iptables-persistent/autosave_v6 boolean true
EOF
echo "postfix postfix/mailname string ${fqdn}" | debconf-set-selections
echo "postfix postfix/main_mailer_type string 'Internet Site'" | debconf-set-selections

# リポジトリのセットアップに必要な以下のパッケージをインストール
pkg_install software-properties-common
pkg_install gnupg

setCurrentStep "リポジトリをセットアップしています"
setup_repositories

lat_dahdi_supp_ver=$(apt-cache search dahdi | grep -E "^dahdi-linux-kmod-[0-9]" | awk '{print $1}' | awk -F'-' '{print $4"-"$5}' | sort -n | tail -1)
kernel_version=$(uname -r | cut -d'-' -f1-2)

message " カーネル$kernel_version に FreePBX 17 をインストールしています。"
message " DAHDIを使用する予定がある場合は以下の点に注意してください："
message " DAHDIオプションを選択してスクリプトがDAHDIを設定するようにするか、"
message "                                  または"
message " DAHDI がサポートするカーネルを実行していることを確認してください。現在の最新サポートカーネルバージョンは $lat_dahdi_supp_ver です。"

if [ $dahdi ]; then
    setCurrentStep "適切なカーネルアップグレードとバージョンのインストールのみを許可していることを確認しています"
    check_kernel_compatibility "$kernel_version"
fi

setCurrentStep "リポジトリを更新しています"
apt-get update >> $log

# apt-cache policyをログに記録
apt-cache policy  >> $log

# tftpとchronyデーモンを自動的に起動しないようにする（設定変更が必要なため）
mv /etc/init.d/tftpd-hpa /etc/init.d/tftpd-hpa.disabled # **Edited: systemctl mask tftpd-hpa.service**
if [ "$nochrony" != true ]; then
	mv /etc/init.d/chrony /etc/init.d/chrony.disabled # **Edited: systemctl mask chrony.service**
fi

# 依存パッケージをインストール
setCurrentStep "必要なパッケージをインストールしています"
DEPPKGS=("redis-server"
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
	"libavahi-client3"
	"nmap"
	"apache2"
	"zip"
	"incron"
	"wget"
	"vim"
	"build-essential"
	"openssh-server"
	"mariadb-server"
	"mariadb-client"
	"bison"
	"flex"
	"flite"
	"php${PHPVERSION}"
	"php${PHPVERSION}-curl"
	"php${PHPVERSION}-zip"
	"php${PHPVERSION}-redis"
	"php${PHPVERSION}-curl"
	"php${PHPVERSION}-cli"
	"php${PHPVERSION}-common"
	"php${PHPVERSION}-mysql"
	"php${PHPVERSION}-gd"
	"php${PHPVERSION}-mbstring"
	"php${PHPVERSION}-intl"
	"php${PHPVERSION}-xml"
	"php${PHPVERSION}-bz2"
	"php${PHPVERSION}-ldap"
	"php${PHPVERSION}-sqlite3"
	"php${PHPVERSION}-bcmath"
	"php${PHPVERSION}-soap"
	"php${PHPVERSION}-ssh2"
	"php-pear"
	"curl"
	"sox"
	#"libncurses5-dev"
	"libssl-dev"
	"mpg123"
	"libxml2-dev"
	"libnewt-dev"
	"sqlite3"
	"libsqlite3-dev"
	"pkg-config"
	"automake"
	"libtool"
	"autoconf"
	"git"
	"unixodbc-dev"
	"uuid"
	"uuid-dev"
	"libasound2-dev"
	"libogg-dev"
	"libvorbis-dev"
	"libicu-dev"
	"libcurl4-openssl-dev"
	"odbc-mariadb"
	"libical-dev"
	"libneon27-dev"
	"libsrtp2-dev"
	"libspandsp-dev"
	"sudo"
	"subversion"
	"libtool-bin"
	"python-dev-is-python3"
	"unixodbc"
	"libjansson-dev"
	"nodejs"
	"npm"
	"ipset"
	"iptables"
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
	"lsb-release"
	"ca-certificates"
 	"cron"
 	"python3-mysqldb"
 	"default-libmysqlclient-dev"
 	"at"
 	"avahi-daemon"
 	"avahi-utils"
	"libnss-mdns"
	"mailutils"
)
if [ "$nochrony" != true ]; then
	DEPPKGS+=("chrony")
fi
for i in "${!DEPPKGS[@]}"; do
	pkg_install ${DEPPKGS[$i]}
done

if  dpkg -l | grep -q 'postfix'; then
    warning_message="# 警告: inet_interfacesを127.0.0.1以外のIPに変更すると、Postfixが外部ネットワーク接続に露出する可能性があります。\n# この設定は、影響を理解し、特定のネットワーク要件がある場合にのみ変更してください。"

    if ! grep -q "警告: inet_interfacesの変更" /etc/postfix/main.cf; then
        # inet_interfaces設定の上に警告メッセージを追加
        sed -i "/^inet_interfaces\s*=/i $warning_message" /etc/postfix/main.cf
    fi

    sed -i "s/^inet_interfaces\s*=.*/inet_interfaces = 127.0.0.1/" /etc/postfix/main.cf

    /etc/init.d/postfix restart # **Edited: systemctl restart postfix**
fi

# OpenVPN EasyRSAの設定
if [ ! -d "/etc/openvpn/easyrsa3" ]; then
	make-cadir /etc/openvpn/easyrsa3
fi
#後でシステム管理者が生成する以下のファイルを削除
rm -f /etc/openvpn/easyrsa3/pki/vars || true
rm -f /etc/openvpn/easyrsa3/vars

# --dahdiオプションが提供された場合、Dahdiカードサポートをインストール
if [ "$dahdi" ]; then
    message "DAHDIカードサポートをインストールしています..."
    DAHDIPKGS=("asterisk${ASTVERSION}-dahdi"
           "dahdi-firmware"
           "dahdi-linux"
           "dahdi-linux-devel"
           "dahdi-tools"
           "libpri"
           "libpri-devel"
           "wanpipe"
           "wanpipe-devel"
           "dahdi-linux-kmod-${kernel_version}"
           "kmod-wanpipe-${kernel_version}"
	)

        for i in "${!DAHDIPKGS[@]}"; do
                pkg_install ${DAHDIPKGS[$i]}
        done
fi

# libfdk-aac2のインストール
if [ $noaac ] ; then
	message "noaacオプションのためlibfdk-aac2のインストールをスキップします"
else
	pkg_install libfdk-aac2
fi

setCurrentStep "不要なパッケージを削除しています"
apt-get autoremove -y >> "$log"

execution_time="$(($(date +%s) - start))"
message "全ての依存パッケージのインストールに要した実行時間 : $execution_time 秒"




setCurrentStep "フォルダとasterisk設定をセットアップしています"
groupExists="$(getent group asterisk || echo '')"
if [ "${groupExists}" = "" ]; then
	groupadd -r asterisk
fi

userExists="$(getent passwd asterisk || echo '')"
if [ "${userExists}" = "" ]; then
	useradd -r -g asterisk -d /home/asterisk -M -s /bin/bash asterisk
fi

# asteriskをsudoersリストに追加
#echo "%asterisk ALL=(ALL:ALL) NOPASSWD: ALL" >> /etc/sudoers

# /tftpbootディレクトリの作成
mkdir -p /tftpboot
chown -R asterisk:asterisk /tftpboot
# tftpプロセスのパスをtftpbootに変更
sed -i -e "s|^TFTP_DIRECTORY=\"/srv\/tftp\"$|TFTP_DIRECTORY=\"/tftpboot\"|" /etc/default/tftpd-hpa
# IPv6が利用できない場合、正常な実行を可能にするためにtftpとchronyのオプションを変更
if [ ! -f /proc/net/if_inet6 ]; then
	sed -i -e "s|^TFTP_OPTIONS=\"--secure\"$|TFTP_OPTIONS=\"--secure --ipv4\"|" /etc/default/tftpd-hpa
	if [ "$nochrony" != true ]; then
		sed -i -e "s|^DAEMON_OPTS=\"-F 1\"$|DAEMON_OPTS=\"-F 1 -4\"|" /etc/default/chrony
	fi
fi
# tftpとchronyデーモンを起動
mv /etc/init.d/tftpd-hpa.disabled /etc/init.d/tftpd-hpa # **Edited: systemctl unmask tftpd-hpa.service**
/etc/init.d/tftpd-hpa start # **Edited: systemctl start tftpd-hpa.service**

if [ "$nochrony" != true ]; then
	mv /etc/init.d/chrony.disabled /etc/init.d/chrony # **Edited: systemctl unmask chrony.service**
	/etc/init.d/chrony start # **Edited: systemctl start chrony.service**
fi

# asterisk音声ディレクトリの作成
mkdir -p /var/lib/asterisk/sounds
chown -R asterisk:asterisk /var/lib/asterisk

# katanaと互換性を持たせるためにopensslを変更
sed -i -e 's/^openssl_conf = openssl_init$/openssl_conf = default_conf/' /etc/ssl/openssl.cnf

isSSLConfigAdapted=$(grep "FreePBX 17 変更" /etc/ssl/openssl.cnf |wc -l)
if [ "0" = "${isSSLConfigAdapted}" ]; then
	cat <<EOF >> /etc/ssl/openssl.cnf
# FreePBX 17 変更 - 開始
[ default_conf ]
ssl_conf = ssl_sect
[ssl_sect]
system_default = system_default_sect
[system_default_sect]
MinProtocol = TLSv1.2
CipherString = DEFAULT:@SECLEVEL=1
# FreePBX 17 変更 - 終了
EOF
fi

#IPv4により高い優先度を設定
sed -i 's/^#\s*precedence ::ffff:0:0\/96  100/precedence ::ffff:0:0\/96  100/' /etc/gai.conf

# screen設定
isScreenRcAdapted=$(grep "FreePBX 17 変更" /root/.screenrc |wc -l)
if [ "0" = "${isScreenRcAdapted}" ]; then
	cat <<EOF >> /root/.screenrc
# FreePBX 17 変更 - 開始
hardstatus alwayslastline
hardstatus string '%{= kG}[ %{G}%H %{g}][%= %{=kw}%?%-Lw%?%{r}(%{W}%n*%f%t%?(%u)%?%{r})%{w}%?%+Lw%?%?%= %{g}][%{B}%Y-%m-%d %{W}%c %{g}]'
# FreePBX 17 変更 - 終了
EOF
fi


# マウスのコピー＆ペースト用のVIM設定
isVimRcAdapted=$(grep "FreePBX 17 変更" /etc/vim/vimrc.local |wc -l)
if [ "0" = "${isVimRcAdapted}" ]; then
	VIMRUNTIME=$(vim -e -T dumb --cmd 'exe "set t_cm=\<C-M>"|echo $VIMRUNTIME|quit' | tr -d '\015' )
	VIMRUNTIME_FOLDER=$(echo $VIMRUNTIME | sed 's/ //g')

	cat <<EOF >> /etc/vim/vimrc.local
" FreePBX 17 変更 - 開始
" このファイルは最初にデフォルトのvimオプションを読み込み、後で再度読み込まれるのを防ぎます。
" その他のオプションはすべて追加されるか、デフォルト設定を上書きします。
" このファイルの最後に好きなだけオプションを追加してください。

" デフォルトを読み込む
source $VIMRUNTIME_FOLDER/defaults.vim

" ユーザーにローカルのvimrc（~/.vimrc）がない場合、デフォルトが後で再度読み込まれるのを防ぐ
let skip_defaults_vim = 1


" より多くのオプションを設定（/usr/share/vim/vim80/defaults.vimの設定を上書き）
" 好きなだけオプションを追加してください

" マウスモードを'r'に設定
if has('mouse')
  set mouse=r
endif
" FreePBX 17 変更 - 終了
EOF
fi


# 既存の設定を常に上書きしないようにaptの設定
cat <<EOF >> /etc/apt/apt.conf.d/00freepbx
DPkg::options { "--force-confdef"; "--force-confold"; }
EOF


#chown -R asterisk:asterisk /etc/ssl

# Asteriskのインストール
if [ $noast ] ; then
	message "noasteriskオプションのためAsteriskのインストールをスキップします"
else
	# TODO 既にAsteriskがインストールされている場合、それを削除して新しいものをインストールする必要があります。
	# Asterisk 21のインストール
	setCurrentStep "Asteriskパッケージをインストールしています。"
	install_asterisk $ASTVERSION
fi

# PBX依存パッケージのインストール
setCurrentStep "FreePBXパッケージをインストールしています"

FPBXPKGS=("sysadmin17"
	   "sangoma-pbx17"
	   "ffmpeg"
   )
for i in "${!FPBXPKGS[@]}"; do
	pkg_install ${FPBXPKGS[$i]}
done


#freepbx.iniファイルの有効化
setCurrentStep "モジュールを有効化しています。"
phpenmod freepbx
mkdir -p /var/lib/php/session

#デフォルト設定ファイルの作成
mkdir -p /etc/asterisk
touch /etc/asterisk/extconfig_custom.conf
touch /etc/asterisk/extensions_override_freepbx.conf
touch /etc/asterisk/extensions_additional.conf
touch /etc/asterisk/extensions_custom.conf
chown -R asterisk:asterisk /etc/asterisk

setCurrentStep "fail2banを再起動しています"
service fail2ban restart  >> $log # **Edited: systemctl restart fail2ban  >> $log**


if [ $nofpbx ] ; then
  message "nofreepbxオプションのためFreePBX 17のインストールをスキップします"
else
  setCurrentStep "FreePBX 17をインストールしています"
  pkg_install ioncube-loader-82
  pkg_install freepbx17

  if [ -n "$NPM_MIRROR" ] ; then
    setCurrentStep "環境変数npm_config_registry=$NPM_MIRRORを設定しています"
    export npm_config_registry="$NPM_MIRROR"
  fi

  # オープンソースのみが必要な場合、商用モジュールを削除
  if [ "$opensourceonly" ]; then
    setCurrentStep "商用モジュールを削除しています"
    fwconsole ma list | awk '/Commercial/ {print $2}' | xargs -I {} fwconsole ma -f remove {} >> "$log"
    # 商用のsysadminモジュールに依存しているため、ファイアウォールモジュールも削除
    fwconsole ma -f remove firewall >> "$log" || true
  fi

  if [ $dahdi ]; then
    fwconsole ma downloadinstall dahdiconfig >> $log
    echo 'export PERL5LIB=$PERL5LIB:/etc/wanpipe/wancfg_zaptel' | sudo tee -a /root/.bashrc
  fi

  setCurrentStep "すべてのローカルモジュールをインストールしています"
  fwconsole ma installlocal >> $log

  setCurrentStep "FreePBX 17モジュールをアップグレードしています"
  fwconsole ma upgradeall >> $log

  setCurrentStep "FreePBX 17をリロードして再起動しています"
  fwconsole reload >> $log
  fwconsole restart >> $log

  if [ "$opensourceonly" ]; then
    # sysadmin商用モジュール用のsysadminヘルパーパッケージをアンインストール
    message "sysadmin17をアンインストールしています"
    apt-get purge -y sysadmin17 >> "$log"
    # 商用モジュールとfreepbx17パッケージのインストールに必要なionCubeローダーをアンインストール
    message "ioncube-loader-82をアンインストールしています"
    apt-get purge -y ioncube-loader-82 >> "$log"
  fi
fi

setCurrentStep "インストールプロセスを完了しています"
#systemctl daemon-reload >> "$log" # **Edited: コメントアウト**
if [ ! $nofpbx ] ; then
  #systemctl enable freepbx >> "$log" # **Edited: コメントアウト**
fi

#apache2のindex.htmlを削除（不要なファイルのため）
rm -f /var/www/html/index.html

#apache mod sslを有効化
a2enmod ssl  >> "$log"

#apache mod expiresを有効化
a2enmod expires  >> "$log"

#apacheを有効化
a2enmod rewrite >> "$log"

#FreePBX apache設定を有効化
if [ ! $nofpbx ] ; then 
  a2ensite freepbx.conf >> "$log"
  a2ensite default-ssl >> "$log"
fi

#postfixのサイズを100MBに設定
postconf -e message_size_limit=102400000

# 攻撃者に少ない情報を提供するためにexpose_phpを無効化
sed -i 's/\(^expose_php = \).*/\1Off/' /etc/php/${PHPVERSION}/apache2/php.ini

# 攻撃者に少ない情報を提供するためにServerTokensとServerSignatureを無効化
sed -i 's/\(^ServerTokens \).*/\1Prod/' /etc/apache2/conf-available/security.conf
sed -i 's/\(^ServerSignature \).*/\1Off/' /etc/apache2/conf-available/security.conf

# apache2を再起動
apache2ctl -k restart # **Edited: systemctl restart apache2 >> "$log"**

setCurrentStep "パッケージをホールドしています"

hold_packages

# logrotate設定の更新
if grep -q '^#dateext' /etc/logrotate.conf; then
   message "logrotate.confを設定しています"
   sed -i 's/^#dateext/dateext/' /etc/logrotate.conf
fi

#権限の設定
chown -R asterisk:asterisk /var/www/html/

#post aptスクリプトの作成
create_post_apt_script

# 署名の更新
setCurrentStep "モジュールの署名を更新しています。"
count=1
if [ ! $nofpbx ]; then
  while [ $count -eq 1 ]; do
    set +e
    refresh_signatures
    exit_status=$?
    set -e
    if [ $exit_status -eq 0 ]; then
      break
    else
      log "コマンド'fwconsole ma refreshsignatures'の実行に失敗しました。終了ステータス: $exit_status。バックグラウンドジョブとして実行します"
      refresh_signatures &
      log "残りのスクリプト実行を続行します"
      break
    fi
  done
fi


setCurrentStep "FreePBX 17のインストールが正常に完了しました。"


############ インストール後の検証 ############################################
# インストール後の検証コマンド
# スクリプトの早期終了を防ぐため、非ゼロの終了コードに遭遇した際の自動スクリプト終了を無効化します。
set +e
setCurrentStep "インストール後の検証"

#check_services # **Edited: コメントアウト**

check_php_version

if [ ! $nofpbx ] ; then
 check_freepbx
fi

check_asterisk

execution_time="$(($(date +%s) - start))"
message "スクリプトの総実行時間: $execution_time"
message "$host $kernelのFreePBX 17インストールプロセスが完了しました"
message "FreePBXコミュニティフォーラムに参加してください: https://community.freepbx.org/ ";

if [ ! $nofpbx ] ; then
  fwconsole motd
fi
