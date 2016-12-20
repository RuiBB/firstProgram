# libpcap

借鉴网络上的一些资料，尝试在ubuntu上使用libpcap库编写简单抓包程序

使用到的库为libpcap，libarpack

在官方下载了libpcap的下载文件，然后进行make

./configure

sudo make

sudo make install

将pcap文件夹复制到etc/bin下，usr/local/lib下的so文件移动至usr/lib中，即可使用该库。
