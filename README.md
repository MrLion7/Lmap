# Lmap
A tool combined with the advantages of masscan and nmap  

V2.0 更新：  
1.可自定义路径，windows可用。  
2.默认开启scan-title模式，可扫描存活端口title，默认扫描并发量为100。  
3.默认nmap扫描模式为sS,忽略具体版本扫描加快速度，如有需要请设置-sv True。  
4.支持排除waf，默认一个ip如果连续开放50个端口则判断有waf，会丢弃结果，可通过更改config.ini的waf-threshold参数改变阈值。  
5.各细节优化。  

![image](https://user-images.githubusercontent.com/47624672/144983177-faba1d48-e7c8-456c-8620-e7d5ead59375.png)
![image](https://user-images.githubusercontent.com/47624672/144980779-107023c0-889e-4494-a969-e19fc4a0b6d1.png)
![image](https://user-images.githubusercontent.com/47624672/144980772-38bcb2e0-0952-4542-9e31-7134272c6c32.png)

一个简单的Nmap和Masscan联动脚本

前置需求：Linux系统,python3.8+,已安装masscan和nmap，引用库：rich,prettytable和lxml

参考文章：https://www.sohu.com/a/336991344_354899

代码思路：将ip和端口分为多组，通过异步实现多个masscan并发扫描，利用生产者-消费者模型，一旦masscan扫描到存活端口，就会联动nmap扫描端口服务，并使用httpx扫描Title。

config.ini是配置文件，默认Masscan并发数为3，单个masscan速率为500，ip每3个一组，端口每11000一组，Nmap并发限制量为10。如果觉得结果不准可以调低限制。默认扫描title并发量为100。

不是专业开发，代码质量不高，如有bug欢迎反馈。
