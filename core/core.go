package core

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var StreamServiceUrl = ""
var StreamCode = ""

func GetAllDevs() []string {
	devices, err := pcap.FindAllDevs()
	devices_count := len(devices)
	device_desc := make([]string, devices_count)
	if err == nil {
		for k, v := range devices {
			device_desc[k] = v.Description
			fmt.Printf("%d: %s\n", k, v.Description)
		}
	}
	return device_desc
}

func StartListen(index int64, c chan error) error {
	StreamServiceUrl = ""
	StreamCode = ""
	devices, err := pcap.FindAllDevs()
	if err == nil {
		if len(devices) > (int(index) + 1) {
			FilterInfo(devices[index].Name, c)
		} else {
			return errors.New("out of index")
		}
	}
	return err
}

// 界面交互
func getScan() int {
	// 默认网卡序号为0
	num := 0
	fmt.Println("请输入网卡序号：")
	fmt.Scanln(&num)
	return num
}

// 获取网卡
func GetAllEth() string {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Println(err)
		return ""
	}

	for k, v := range devices {
		fmt.Printf("%d: %s\n", k, v.Description)
	}
	num := getScan()
	// fmt.Println("网卡序号为：", num)
	// 防止超出切片下标
	if num >= len(devices) {
		return ""
	}
	return devices[num].Name
}

// 过滤信息
func FilterInfo(s string, c chan error) {
	// 如果s为空说明没有传入任何信息
	if s == "" {
		return
	}
	// 打开网卡
	handle, err := pcap.OpenLive(s, 1600, true, pcap.BlockForever)
	if err != nil {
		fmt.Println(err)
		c <- err
		return
	}
	defer handle.Close()
	// 设置过滤器
	var filter = "tcp and port 1935"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		fmt.Println("handle.SetBPFFilter", err)
		c <- err
		return
	}
	c <- nil

	fmt.Println("开始捕获数据：")
	// 开始捕获数据包
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	isOver := byte(0)
	for packet := range packetSource.Packets() {

		// 检查是否为 RTMPT 数据包
		// 保证网络层和传输层信息不为空,并且传输层协议为TCP协议
		if packet.NetworkLayer() == nil || packet.TransportLayer() == nil ||
			packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
			continue
		}
		// 类型断言，将接口类型转换为 *layers.TCP 类型
		tcp := packet.TransportLayer().(*layers.TCP)
		// 必须满足以下条件才提取数据
		if tcp.DstPort != 1935 || len(tcp.Payload) > 500 || len(tcp.Payload) < 30 {
			continue
		}

		// 处理数据包
		if decode(tcp) {
			isOver += 1
		}

		if isOver == 2 {
			fmt.Println("获取数据结束")
			return
		}

	}
}

func decode(tcp *layers.TCP) bool {
	flag := false
	// 判断包
	pay_load_len := len(tcp.Payload)
	for k, v := range tcp.Payload {
		if v == 0x02 { // amf0标志
			// 获取字符串长度
			if pay_load_len > k+2 {
				sLen := tcp.Payload[k+2]
				// 判断是否为connect和rekeaseStream的长度
				if sLen == 7 {
					flag = getConnect(tcp.Payload[k+3:])
				} else if sLen == 13 {
					flag = getRekeaseStream(tcp.Payload[k+3:])
				}
			}
		}
		if flag {
			return true
		}
	}
	return false
}

// connect连接
func getConnect(data []byte) bool {
	// 获取存储数据的Object
	for k, v := range data {
		if v == 0x03 {
			data = data[k+1:]
			break
		}
	}
	for k, v := range data {
		if v == 0x05 {
			tmpData := data[k+1 : k+6]
			if string(tmpData) == "tcUrl" {
				urlLen := int(data[k+6+2])
				// 排除数据中的c3,+1是因为数组在长度后面
				dataRe := bytes.ReplaceAll(data[k+6+2+1:], []byte{0xc3}, []byte{})
				data := dataRe[:urlLen]
				StreamServiceUrl = string(data)
				fmt.Printf("Url:%s\n", string(data))
				return true
			}
		}
	}

	return false

}

// rekeaseStream连接
func getRekeaseStream(data []byte) bool {
	// 获取存储字符串的位置
	for k, v := range data {
		if v == 0x02 {
			urlLen := int(data[k+2])
			// 排除数据中的c3,+1是因为数组在长度后面
			dataRe := bytes.ReplaceAll(data[k+2+1:], []byte{0xc3}, []byte{})
			data := dataRe[:urlLen]
			StreamCode = string(data)
			fmt.Printf("Key:%s\n", string(data))
			return true
		}
	}

	return false
}
