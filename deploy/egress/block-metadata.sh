#!/bin/sh
# 执行面容器启动时运行：把云元数据地址在内核层黑洞。
#
# 为什么还要这一层：进程内闸门（gate.CheckDial）已经拒绝元数据地址，
# 但"纵深防御"要求即使二进制被替换、或被注入脚本绕过 Go 代码，
# 网络层也拿不到元数据。需要 NET_ADMIN（仅执行面，控制面不需要）。
set -eu

for ip in 169.254.169.254 169.254.170.2 100.100.100.200 192.0.0.192; do
  iptables -C OUTPUT -d "$ip" -j REJECT 2>/dev/null || iptables -A OUTPUT -d "$ip" -j REJECT
done
ip6tables -C OUTPUT -d fd00:ec2::254 -j REJECT 2>/dev/null || ip6tables -A OUTPUT -d fd00:ec2::254 -j REJECT

# 可选：只允许访问授权网段（把 10.20.0.0/16 换成实际范围）
# iptables -A OUTPUT -m owner --uid-owner 10001 ! -d 10.20.0.0/16 -j REJECT

echo "argus: metadata endpoints blackholed"
