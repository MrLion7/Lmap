# Lmap
A tool combined with the advantages of masscan and nmap


一个简单的Nmap和Masscan联动脚本

前置需求：Linux系统,python3.8+,已安装masscan和nmap，引用库：rich和prettytable

代码思路：将ip和端口分为多组，通过异步实现多个masscan并发扫描，利用生产者-消费者模型，一旦masscan扫描到存活端口，就会联动nmap扫描端口服务。

config.ini是配置文件，默认Masscan并发数为3，单个masscan速率为1000，ip每3个一组，端口每11000一组，Nmap并发限制量为10。

不是专业开发，代码质量不高，如有bug欢迎反馈。
