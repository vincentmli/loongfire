# LoongFire - The Open Source Firewall on LoongArch CPU (龙芯开源防火墙）

# What is LoongFire?

LoongFire is port of IPFire for LoongArch CPU

LoongFire is a hardened, versatile, state-of-the-art Open Source firewall based on
Linux. Its ease of use, high performance in any scenario and extensibility make
it usable for everyone. For a full list of features have a look [here](https://www.ipfire.org/about).

LoongFire also enable revolutionary kernel eBPF XDP/TC features for dynamic, high
speed network processing.

LoongFire 是IPFire移植到龙芯的, 一个基于Linux的安全坚固、多功能、先进的开源防火墙. LoongFire 为普罗大众带来革命创新性的eBPF技术，为家庭用户或任何大小组织企业的网络安全保驾护航. 当前支持的eBPF应用包括：

1. XDP DDoS protection [Pkgten DDoS attack](https://youtu.be/QVh7kihvYaM?si=tAdGCiDib4tp2BSj)
2. XDP DNS monitor, blocking
3. XDP SSL/TLS server name indicator (SNI) monitor, blocking
4. Intrusion prevention system (IPS) in XDP mode [suricata XDP](https://youtu.be/zcWsaZbs5aA?si=v_h6iHu3k4WZsBOn)
5. DNS Load balancing in eBPF XSK AF_XDP mode [dnsdist AF_XDP](https://youtu.be/O5BK1CGHDkU?si=r5VDnUc7_PU0Xt-R0)
6. eBPF based LoxiLB load balancer, Firewall, Proxy, see full features [LoxiLB](https://loxilb-io.github.io/loxilbdocs/#overall-features-of-loxilb)

LoongArch mini PC Home Internet Firewall Demo [here](https://youtu.be/rVHkBf1HB7Y?si=cxZphLIn4RhRp3-F)

This repository contains the source code of LoongFire which is used to build
the whole distribution from scratch, since LoongFire is not based on any other
distribution.

# Where can I get LoongFire?

https://bpfire.net/download/loongfire

# What computer hardwares LoongFire requires?

LoongFire support Loongson 3A6000 mini PC (NUC), Loongson server should be supported, but not tested due to lack of hardware for testing.

for example [mini PC](https://www.aliexpress.us/item/3256807861547435.html?spm=a2g0o.order_list.order_list_main.5.6c6c1802f4v4tf&gatewayAdapt=glo2usa) I use at home.

# How to build LoongFire?

On LoongArch machine (I used Loongson 3A6000 mini PC running Fedora):

1. git clone https://github.com/vincentmli/loongfire.git
2. cd loongfire
3. wget --mirror --convert-links --adjust-extension --page-requisites --no-parent --cut-dirs=2 -nH --reject "index.html*" --reject "*.gif" https://www.bpfire.net/download/loongfire/cache/
4. ./make.sh build
