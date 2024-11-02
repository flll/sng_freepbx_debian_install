FROM debian:bookworm-20241016
# require: kernel 5.15.0-124-generic
LABEL org.opencontainers.image.title="FreePBX17 Docker"
LABEL org.opencontainers.image.version="20241029.1600"
LABEL org.opencontainers.image.source="https://github.com/flll/sng_freepbx_debian_install"
LABEL org.opencontainers.image.description="FreePBX17 の Debian Unstable版 のDockerイメージ"
LABEL org.opencontainers.image.url="https://freepbx.org/"
LABEL org.opencontainers.image.vendor="flll"

ENV container docker

# freepbx17のリポジトリを追加
COPY <<-EOF /etc/apt/preferences.d/99sangoma-fpbx-repository
	Package: *
	Pin: origin deb.freepbx.org
	Pin-Priority: 600
EOF

# freepbx17のリポジトリを追加
RUN apt update && apt -y -o DPkg::Options::="--force-confnew" -o Dpkg::Options::="--force-overwrite" \
	install \
		software-properties-common=0.99.30-4.1~deb12u1 \
		wget=1.21.3-1+b2 && \
	apt-key del "9641 7C6E 0423 6E0A 986B  69EF DE82 7447 3C8D 0E52" ;\
	add-apt-repository -y -S "deb [ arch=amd64 ] http://deb.freepbx.org/freepbx17-dev bookworm main" ;\
	wget -O - http://deb.freepbx.org/gpg/aptly-pubkey.asc | gpg --dearmor --yes -o /etc/apt/trusted.gpg.d/freepbx.gpg

# freepbx17パッケージをあらかじめインストール ./apt_package.list から列挙
COPY ./apt_package.list /tmp/apt_package.list
RUN apt update && apt -y -o DPkg::Options::="--force-confnew" -o Dpkg::Options::="--force-overwrite" \
	install \
		$(grep -v '^#' /tmp/apt_package.list | tr '\n' ' ')

# freepbx17のインストールスクリプト
# `/tmp/sng_freepbx_debian_install.sh` 
# - 新バージョンをスキップ: skipversion=true --skipversion
# - -dahdiをインストール: --dahdi いらない
# - テストリポジトリ: --testing
# - chronyを無効化: --nochrony
COPY --chmod=700 ./sng_freepbx_debian_install.sh /tmp/sng_freepbx_debian_install.sh
#RUN bash /tmp/sng_freepbx_debian_install.sh --skipversion --testing --nochrony

CMD ["sleep", "infinity"]

STOPSIGNAL SIGTERM
