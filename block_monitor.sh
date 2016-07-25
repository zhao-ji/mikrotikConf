#!/bin/sh

export LC_MESSAGES=C

ALEXA_DOWNLOAD_URL="http://s3.amazonaws.com/alexa-static/top-1m.csv.zip"
ERROR_LOG="scan_log/log_error"

TODAY_RECORD="scan_log/$(date +%y_%m_%d_DNS_record)"

# 从alexa下载每日更新的全球前1M域名
rm top1m.zip top-1m.csv
wget $ALEXA_DOWNLOAD_URL -O top1m.zip 2> /dev/null
unzip top1m.zip

touch $TODAY_RECORD

# 打开监控 关注域名的返回
(sudo python recieve_DNS_record.py 2> $ERROR_LOG >> $TODAY_RECORD)&

# 向GOOGLE DNS服务器查询A记录
cut -d, -f2 top-1m.csv|head -n 100|sudo python send_DNS_request.py &> $ERROR_LOG

# 休息五分钟后把没有解析结果的域名再查一遍
# sleep 5m
# comm -23 <(cut -d, -f2 top-1m.csv|sort) <(cut -d ' ' -f1 $TODAY_RECORD|sort -u)\
#     | sudo python send_DNS_request.py &> $ERROR_LOG

# 休息五分钟后杀掉上个后台任务
# http://stackoverflow.com/questions/1624691/linux-kill-background-task
sleep 1m
sudo kill $!
