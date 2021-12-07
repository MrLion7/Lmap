# Lmap
A tool combined with the advantages of masscan and nmap

V2.0 更新：
1.可自定义路径，windows可用
2.默认开启scan-title模式，可扫描title文件，使用httpx库和asyncio，默认扫描title并发量为100。
3.默认nmap扫描模式为sS,忽略具体版本扫描加快速度，如有需要请设置-sv True。
4.各细节优化


一个简单的Nmap和Masscan联动脚本

前置需求：Linux系统,python3.8+,已安装masscan和nmap，引用库：rich,prettytable和lxml

参考文章：https://www.sohu.com/a/336991344_354899

代码思路：将ip和端口分为多组，通过异步实现多个masscan并发扫描，利用生产者-消费者模型，一旦masscan扫描到存活端口，就会联动nmap扫描端口服务，并使用httpx扫描Title。

config.ini是配置文件，默认Masscan并发数为3，单个masscan速率为500，ip每3个一组，端口每11000一组，Nmap并发限制量为10。如果觉得结果不准可以调低限制。默认扫描title并发量为100。

不是专业开发，代码质量不高，如有bug欢迎反馈。
