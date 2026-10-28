# 内网 IP 上报

Linux 客户端定时把本机内网 IP 上报到服务器，通过网页查看最新 IP 和历史记录。
每台客户端必须设置一个可读的**标志**（例如 `guo`、`office-pc`），方便区分不同机器。

- 面板：<https://ip.ooops.dpdns.org/>
- 服务端目录：`/home/USER/ip-reporter`
- 数据目录：`/home/USER/ip-reporter/data`

以下命令中的 `USER@SERVER` 和 `/home/USER` 请替换为实际的 SSH 用户、服务器地址和用户目录。

## 一、安装客户端

需要 Python 3.8+ 和 systemd。在目标电脑上执行：

```bash
mkdir -p ~/ip-reporter-client && cd ~/ip-reporter-client

scp -i ~/.ssh/id_rsa -r \
  USER@SERVER:/home/USER/ip-reporter/client \
  USER@SERVER:/home/USER/ip-reporter/systemd .

TOKEN=$(ssh -i ~/.ssh/id_rsa USER@SERVER \
  'sudo -n python3 /home/USER/ip-reporter/server/ip_reporter_server.py \
    --config /home/USER/ip-reporter/config/server.json --show-tokens' \
  | sed -n 's/^report_token=//p')

sudo ./client/install.sh \
  --server-url https://ip.ooops.dpdns.org \
  --token "$TOKEN" \
  --label guo
```

`--label` 是必填的客户端标志，会显示在面板卡片和查询结果中。已经安装过的客户端
可以再次执行同一条命令（带上 `--label guo`）只更新标志；也可以直接修改
`/etc/ip-reporter/client.json` 里的 `"label": "guo"`，然后执行
`sudo systemctl start ip-reporter.service`。注意 `--force` 会重写整个客户端配置；
如果只想修改标志，请不要加 `--force`。

默认每 5 分钟上报一次，开机和网络变化时也会触发。修改间隔：

```bash
sudo ./client/install.sh --interval 2min
```

查看状态：

```bash
systemctl list-timers ip-reporter.timer --no-pager
journalctl -u ip-reporter.service -n 50 --no-pager
```

只查看检测结果，不上传：

```bash
sudo /usr/local/bin/ip-reporter \
  --config /etc/ip-reporter/client.json --print-payload
```

卸载：

```bash
sudo ./client/install.sh --uninstall --purge
```

## 二、打开面板

访问 <https://ip.ooops.dpdns.org/>，在右上角输入 `admin_token`。

查看令牌：

```bash
sudo python3 /home/USER/ip-reporter/server/ip_reporter_server.py \
  --config /home/USER/ip-reporter/config/server.json --show-tokens
```

| 令牌 | 用途 |
|---|---|
| `report_token` | 只能给客户端上报 |
| `admin_token` | 面板、查询、历史、删除 |

不要把 `admin_token` 写进客户端配置。

## 三、常用命令

服务端状态：

```bash
systemctl status ip-reporter-server --no-pager
curl -fsS http://127.0.0.1:8765/healthz
journalctl -u ip-reporter-server -n 50 --no-pager
```

查询某台机器的内网 IP（按主机名或标志）：

```bash
ADMIN_TOKEN='你的 admin_token'

curl -fsS -H "Authorization: Bearer $ADMIN_TOKEN" \
  'https://ip.ooops.dpdns.org/api/v1/lookup?hostname=my-laptop&format=text'

curl -fsS -H "Authorization: Bearer $ADMIN_TOKEN" \
  'https://ip.ooops.dpdns.org/api/v1/lookup?label=guo&format=text'
```

标志用于方便地区分客户端，不要求唯一；如果多个客户端使用同一个标志，返回最近
上报的那一台。需要精确定位时请使用 `client_id`。

查看所有客户端，或按标志搜索：

```bash
curl -fsS -H "Authorization: Bearer $ADMIN_TOKEN" \
  'https://ip.ooops.dpdns.org/api/v1/clients'

curl -fsS -H "Authorization: Bearer $ADMIN_TOKEN" \
  'https://ip.ooops.dpdns.org/api/v1/clients?q=guo'
```

备份数据：

```bash
sudo tar czf ip-reporter-data-$(date +%F).tar.gz \
  -C /home/USER/ip-reporter data
```

## 四、配置

服务端配置：`/home/USER/ip-reporter/config/server.json`

常用字段：`data_dir`、`report_token`、`admin_token`、`online_threshold_seconds`、`history_retention_days`、`history_max_per_client`。

客户端配置：`/etc/ip-reporter/client.json`

常用字段：`server_url`、`report_token`、`label`、`exclude_interfaces`、`timeout_seconds`、`retries`。

`label` 是客户端标志，**必填**，最多 64 个字符，可以包含中文。也可以在临时运行时
用 `--label` 覆盖，或通过环境变量 `IP_REPORTER_LABEL` 指定：

```bash
/usr/local/bin/ip-reporter --config /etc/ip-reporter/client.json \
  --print-payload --label guo
```

修改后重启：

```bash
sudo systemctl restart ip-reporter-server
sudo systemctl restart ip-reporter.timer
sudo systemctl start ip-reporter.service
```

## 五、常见问题

**面板没有数据**

客户端未安装或首次上报失败：

```bash
journalctl -u ip-reporter.service -n 50 --no-pager
```

**面板上看不到标志**

确认客户端配置里有 `"label": "guo"`，并且客户端版本已经更新：

```bash
sudo /usr/local/bin/ip-reporter \
  --config /etc/ip-reporter/client.json --print-payload
```

输出的 JSON 中应该包含 `"label": "guo"`。

**客户端报 label is required**

新版客户端要求必须设置标志。重新运行安装脚本或直接修改配置：

```bash
sudo ./client/install.sh --label guo
```

**客户端 401**

`report_token` 不一致。重新安装并指定正确的 token：

```bash
sudo ./client/install.sh \
  --server-url https://ip.ooops.dpdns.org \
  --token '正确的 report_token' \
  --label '你的标志' --force
```

**nginx 502**

```bash
systemctl status ip-reporter-server --no-pager
curl -v http://127.0.0.1:8765/healthz
```

**看不到某个网卡的 IP**

编辑 `/etc/ip-reporter/client.json` 里的 `exclude_interfaces`，然后执行：

```bash
sudo systemctl start ip-reporter.service
```

## 六、服务端部署/升级

```bash
cd /home/USER/ip-reporter

sudo ./server/install.sh \
  --dir /home/USER/ip-reporter \
  --user USER \
  --port 8765
```

首次部署还需要配置 nginx 和证书：

```bash
sudo cp server/nginx-ip.ooops.dpdns.org.conf \
  /etc/nginx/sites-available/ip.ooops.dpdns.org
sudo ln -sf /etc/nginx/sites-available/ip.ooops.dpdns.org \
  /etc/nginx/sites-enabled/ip.ooops.dpdns.org

sudo certbot certonly --webroot -w /var/www/html \
  -d ip.ooops.dpdns.org

sudo nginx -t
sudo systemctl reload nginx
```

Cloudflare 的 SSL/TLS 模式保持 **Full** 或 **Full (strict)**，不要用 **Flexible**。
