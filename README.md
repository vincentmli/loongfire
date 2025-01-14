# LoongFire - The Open Source Firewall on Loongson CPU (龙芯开源防火墙）

# What is LoongFire?

LoongFire is port of IPFire for Loongson CPU which is designed and made in China.

LoongFire is a hardened, versatile, state-of-the-art Open Source firewall based on
Linux. Its ease of use, high performance in any scenario and extensibility make
it usable for everyone. For a full list of features have a look [here](https://www.ipfire.org/about).

LoongFire also enables revolutionary kernel eBPF XDP/TC features for dynamic, high
speed network processing.

LoongFire 是IPFire 2.x 移植到龙芯的, 一个基于Linux的安全坚固、多功能、先进的开源防火墙. LoongFire 为普罗大众带来革命创新性的eBPF技术，为家庭>用户或任何大小组织企业的网络安全保驾护航. 当前支持的eBPF应用包括：

1. XDP DNS monitor, blocking
2. XDP SSL/TLS server name indicator (SNI) monitor, blocking

Loongson mini PC Home Internet Firewall Demo [here](https://youtu.be/rVHkBf1HB7Y?si=cxZphLIn4RhRp3-F)

This repository contains the source code of LoongFire which is used to build
the whole distribution from scratch, since LoongFire is not based on any other
distribution.

# Where can I get LoongFire?

中国大陆用户下载地址: https://www.vcn.bc.ca/~vli/bpfire/

http://bpfire.net/download/

# What computer hardwares LoongFire requires?

LoongFire support Loongson 3A6000 mini PC (NUC), Loongson server should be supported, but not tested due to lack of hardware for testing.

for example [mini PC](https://www.aliexpress.us/item/3256807861547435.html?spm=a2g0o.order_list.order_list_main.5.6c6c1802f4v4tf&gatewayAdapt=glo2usa) I use at home.

# How to build LoongFire?

1. git clone https://github.com/vincentmli/BPFire.git
2. cd BPFire; wget http://www.bpfire.net/download/cache.tar.xz; tar xJvf cache.tar.xz
3. git checkout loongfire; ./make.sh build
