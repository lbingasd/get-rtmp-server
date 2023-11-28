# 简介
一个简单的读取指定网卡中的数据，并提取出rtmp的地址和密钥,仅供研究使用

# 思路
1. 获取指定网卡
2. 按照一定规则进行过滤
3. 根据规则获取里面的信息

# 使用的包
- gopacket 
  - gopacket 是 google 出品的 golang 三方库
  - [项目地址](https://github.com/google/gopacket)

# 需要安装的工具
- windows
  - [npcap](https://npcap.com/)

- linux
  - [libpcap](https://www.tcpdump.org/)

# 使用教程
- 要通过运行程序的电脑上网,这样才能有数据流过网卡
- 通过命令行运行软件根据提示选择网卡
- 等待出现`开始捕获数据：`
- 运行要推流的程序获取推流数据(比如抖音这种,点击开始直播就会出现推流数据)
- 复制终端出现的数据到你需要的地方