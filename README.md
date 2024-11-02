
詳細、ライセンスはフォーク元のREADMEをご覧ください。

## 概要

[FreePBX](http://www.freepbx.org/ "FreePBX ホームページ")は[Asterisk©](http://www.asterisk.org/ "Asterisk ホームページ")(PBX)を制御・管理するオープンソースのGUI(グラフィカルユーザーインターフェース)です。FreePBXはGPLライセンスの下で提供されています。

```sh
sng_freepbx_debian_install.sh
```
これはFreePBX 17 のインストールスクリプトで、Debian 12.x OS上にFreePBXをインストールするためのものです。

[FreePBX](http://www.freepbx.org/ "FreePBX ホームページ")は、PHPとJavascriptで書かれた完全にモジュール化されたAsterisk用のGUIです。これは、お客様が[Asterisk](http://www.asterisk.org/ "Asterisk ホームページ")の有益な機能を活用できるよう、必要なモジュールを簡単に作成し、無料で配布できることを意味します。

## バージョン関連

### マシン

```yml
$ hostnamectl
 Static hostname: debian
       Icon name: computer-desktop
         Chassis: desktop 🖥️
Operating System: Debian GNU/Linux 12 (bookworm) 
          Kernel: Linux 6.1.0-25-amd64
    Architecture: x86-64
 Hardware Vendor: BESSTAR TECH LIMITED
  Hardware Model: HM80
Firmware Version: 5.16
```


このスクリプトは、FreePBXに必要な依存パッケージをインストールした後、FreePBXソフトウェア自体をインストールします。

詳細なインストールログは `/var/log/pbx/freepbx17-install.log` で確認できます。

- [WIKI](https://sangomakb.atlassian.net/wiki/spaces/FP/pages/9732130/Install+FreePBX)

# Debian 12.7 のインストール

- [Preseed-raw](https://raw.githubusercontent.com/flll/sng_freepbx_debian_install/refs/heads/master/debian-preseed.cfg)
  - ![image](https://github.com/user-attachments/assets/3b51f3d4-516e-47f2-964a-70ba957f6776)

### プロビジョニング

```sh
# tailscale インストール
curl -fsSL https://tailscale.com/install.sh | sh ;
tailscale set --auto-update ;
sudo tailscale up --accept-risk all --ssh --advertise-routes=10.0.0.0/24 --accept-routes --advertise-exit-node ;

echo 'net.ipv4.ip_forward = 1' | sudo tee -a /etc/sysctl.d/99-tailscale.conf
echo 'net.ipv6.conf.all.forwarding = 1' | sudo tee -a /etc/sysctl.d/99-tailscale.conf
sudo sysctl -p /etc/sysctl.d/99-tailscale.conf


# サスペンドとハイバネーションを無効化
sudo systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target
# 自動サスペンドを無効化
gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-ac-type 'nothing'
gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-battery-type 'nothing'
sudo nano /etc/systemd/logind.conf
    # HandleLidSwitch=ignore
    # HandleLidSwitchExternalPower=ignore
    # IdleAction=ignore に変更
sudo systemctl restart systemd-logind
```

### freepbx のインストール

```sh
git clone https://github.com/flll/sng_freepbx_debian_install
cd sng_freepbx_debian_install
bash sng_freepbx_debian_install.sh --skipversion --dahdi
# freepbx のファイアウォールは有効にしないこと
# もし開始してしまった場合は`fwconsole firewall stop`で停止できる。
```
