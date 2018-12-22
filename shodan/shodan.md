# shodan

# 一、shodan基本介绍
## 1.总体介绍
* Wikipedia上是这样介绍shodan的：“shodan是一个用户可以找到特定类型的计算机的搜索引擎。这些计算机通过各种过滤器连接到互联网上。也有人称它为那些服务器发送回客户机的元数据的搜索引擎。这可以是关于服务器软件的信息、服务支持的选项、欢迎消息或客户端在与服务器交互之前能够发现的任何其他信息。”
* 通俗地说，**shodan**是一个用来搜索互联网连接设备的搜索引擎。它与Google、Bing、百度等这些普通的搜索引擎不同的是，在shodan上用户可以使用shodan搜索语法查找并连接到互联网的设备上，而这些设备，可以是摄像头、路由器、服务器等。
## 2.基本信息
* shodan的搜索流程

![](/pictures/shodan的搜索流程.PNG)

* banner是shodan采集的基本数据单位。它描述的是设备所运行服务时的标志性文本信息。banner的内容可以跟着服务类型的变化而变化。例如，对Web服务器来说，banner就将返回标题或telnet登录界面。
以下是几个banner例子：

![](/pictures/http的banner.PNG)

> 上面的banner显示该设备正在运行一个2.7版本的gSOAP服务器软件。

![](/pictures/西门子的banner.PNG)

> 上面的banner显示这是一个西门子S7工控系统协议。其中包含了大量的详细信息，例如公司名称、模块类型、基本固件、模块名称、序号、基本硬件等。


> 注：shodan搜索的是联网设备运行服务时的banner，而不是单一的主机信息。

* 设备元数据
shodan除了获取banner以外，还可以获取相关设备的元数据。比如地址、主机名、操作系统、最近的一次更新时间等。其中大部分元数据可以通过shodan的官网获取，小部分可以通过使用API编程获取。

![](/pictures/元数据.PNG)

## 3.数据采集
* 爬虫工作频率
shodan的爬虫全天工作，并实时更新数据库。
* 爬虫分布
爬虫分布在世界各地：美国（东海岸、西海岸）、中国、冰岛、法国、台湾、越南、罗马尼亚、捷克共和国。
从世界各地收集数据是为了防止地区各种因素的差异造成数据的偏差。因此分布在世界各地的shodan爬虫就可以确保任何全国性的封锁不会影响数据收集。
* 爬虫的基本算法
    1.随机生成一个IPv4地址。
    2.从shodan能解析的端口列表中生成一个随机端口测试。
    3.检测随机端口上的随机IPv4地址，并获取Banner。
    4.重复步骤1。
这意味着爬虫不扫描增量的网络范围，而完全是随机的。这样可以防止数据的偏差。
## 4.SSL的收集
shodan也可以收集SSL的banner，包括收集它们的漏洞信息及功能服务。
* heartbleed漏洞

heartbleed漏洞，CVE号是CVE-2014-0160。它的产生是由于未能在memcpy()调用受害用户输入内容作为长度参数之前正确进行边界检查。这样，攻击者可以追踪OpenSSL所分配的64KB缓存、将超出必要范围的字节信息复制到缓存当中再返回缓存内容，这样一来受害者的内存内容就会以每次64KB的速度进行泄露。

如果一个服务heartbleed漏洞，则返回的banner将包含一下两个附加属性:
```
"opts": {
        "heartbleed": "... 174.142.92.126:8443 - VULNERABLE\n",
        "vulns": ["CVE-2014-0160"]
    }
```
> opts.heartbleed包含对服务进行heartbleed漏洞测试的原始回应。

> opts.vulns列表中存放参数来确定设备是否易于受到攻击。如果该设备容易受到攻击，爬虫会将*CVE-2014-0160*添加到opts.vulns列表中。如果该设备不容易受到攻击，爬虫会将!*CVE-2014-0160*添加到opts.vulns列表中。

同时，shodan也支持漏洞信息搜索。使用的过滤器：*vuln* 。它允许通过CVE进行搜索，返回易受特定CVE攻击的设备。但是它是只有具备小型企业开发者会员资格(每月299美元)或学术会员资源的人才能使用的。故这里使用的图片其实来源于网络。

![](/pictures/过滤器.PNG)

> 上图显示的是：搜索美国受心脏滴血漏洞影响的设备。在shodan中输入country:US vuln:CVE-2014-0160

* FREAK漏洞

FREAK漏洞全称是：Factoring RSA Export Keys，CVE号是CVE-2015-0204。这个漏洞是由于1990年代时，美国软件制造商出口的软件由于规定，只能使用512位或以下的RSA进行加密，而随着计算能力的发展，破解这种加密已经不再是政府机构才能做到的事。这个漏洞还可以和中间人攻击结合使用，只要先破译网站的512位弱加密，再进行中间人攻击，就能使任何允许使用512位出口级密钥的网站失去安全保障。

```
"opts": {
        "heartbleed": "... 174.142.92.126:8443 - VULNERABLE\n",
        "vulns": ["CVE-2014-0160"]
    }
```
> 如果服务支持导出密码，则爬虫将“CVE-2014-0160”添加到opts.vulns列表中。

* Logjam攻击

Logjam攻击属于SSL加密安全漏洞，与FREAK类似，LogJam也是利用90年代美国政府禁止输出高规格加密标准管理方法，诱骗服务器采用较弱、长度较短的512-bit密钥。
LogJam出现在常用的密钥交换加密演算法中，让HTTPS、SSH、IPSec及SMTPS等网络协定产生共享的加密密钥，并建立安全连线。LogJam漏洞使黑客得以发动中间人攻击，让有漏洞的TLS连线降级为512-bit出口等级的密码交换安全性，再读取或修改经由TLS加密连线传输的资料。该漏洞情况与同年三月爆发的FREAK颇为类似，差别在于它是基于TLS协定的漏洞，而非实际的瑕疵，而且攻击目的为Diffie-Hellman，不是RSA的密钥交换。

```
"dhparams": {
    "prime": "bbbc2dcad84674907c43fcf580e9...",
    "public_key": "49858e1f32aefe4af39b28f51c...",
    "bits": 1024,
    "generator": 2,
    "fingerprint": "nginx/Hardcoded 1024-bit prime"
}
```
> 爬虫将短暂使用Diffie-Hellman密码连接到SSL服务，若连接成功就存储返回以上信息。

* 版本

一般情况下，一个浏览器在连接SSL服务时，它应该与服务器一起协商使用的SSL版本和密码。然后它们会统一使用某个版本的SSL用于通信。
shodan的爬虫一开始按照上面所说的方法进行正常请求，与服务器进行协商连接SSL。但是在的得到一个可以用于通信的SSL协议后，还会显式地尝试使用其他的SSL版本连接服务器。也就是说，shodan的爬虫将尝试使用SSLv2、SSLV3、TLSv1.0、TLSv1.1和TLSv1.2连接服务器，来确定该SSL服务支持的所有版本。

收集到的这个信息将在ssl.versions版本字段中显示：
```
    "ssl": {
        "versions": ["TLSv1", "SSLv3", "-SSLv2", "-TLSv1.1", "-TLSv1.2"]
    }
```
> 如果在版本前面有一个“-”符号，则说明该设备不支持该SSL版本。所以，上面的服务器所支持的SSL版本是：TLSv1、SSLv3；不支持：SSLv2、TLSv1.1、TLSv1.2。

同时，版本信息也可以通过shodan网站进行搜索。

![](/pictures/sslv3.PNG)

>上图就是输入ssl.version:sslv3搜索到的允许使用SSLv3的所有SSL服务。（SSLv3, TLSv1, TLSv1.1, TLSv1.2等）

## 5.两种shodan使用的高级数据分析技术
从大部分情况来看，爬虫试图分析主要的banner文本，然后解析出有用的信息。不过有的情况需要使用两种高级数据分析技术。
* Web组件
当爬虫尝试确定创建网站的web技术时，对于http和https，它将分析header和HTML来分解网站的组件。结果存储到http.components属性中。这个属性是一个技术字典。例如：
```
"http": {
    ...
        "components": {
            "jQuery": {
                "categories": ["javascript-frameworks"]
            },
            "Drupal": {
                "categories": ["cms"]
            },
            "PHP": {
                "categories": ["programming-languages"]
            }
        },
             ...
    },
```
而当我们需要获得所有可能类别的完整列表，使用这个命令：
```
shodan stats --facets http.component_category:1000 http
```
在kali中安装并运行shodan。
安装命令：
```
git clone https://github.com/achillean/shodan-python.git && cd shodan-python
python setup.py install
```

![](/pictures/kali安装1.PNG)
![](/pictures/kali安装2.PNG)

安装好shodan之后首先应该init API_Key
```
shodan init <api key>
```
其中API_Key在创建shodan账号的时候shodan已经分配了。可以在网页版看到属于自己的API_Key。

![](/pictures/shodan初始化.PNG)

查看完整列表命令：
```
shodan stats --facets http.component_category:1000 http
```

![](/pictures/完整列表.PNG)


* 级联
如果一个banner返回了关于对等点的信息，或者有关于另一个运行服务的IP地址的信息，那么爬虫就会试图在这个IP/服务上执行一个banner抓取。
为了跟踪初始扫描请求与任何子级/级联请求之间的关系，我们引入了2个新属性：
1. _shodan.id：banner的唯一ID。如果可以从服务启动级联请求，这个属性就一定存在，但这并不一定意味着级联请求会成功。
2. _shodan.options.referrer：提供触发创建当前banner的banner的唯一ID。即引用者是当前banner的父代。













![](/pictures/.PNG)























# 参考资料
1. [shodan 维基百科](https://en.wikipedia.org/wiki/Shodan_(website))
2. [Complete Guide to Shodan](https://leanpub.com/shodan)
3. [shodan 手册](http://b404.xyz/2018/02/08/Shodan-Manual/)
4. [研究发现SSL新漏洞LogJam 或影响大量服务器](http://soft.yesky.com/144/65610644.shtml)
