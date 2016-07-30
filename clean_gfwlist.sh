sensitive_pattern='google\|youtube\|wordpress\|appspot\|tumblr\|somee\|proxy\|hide\|vpn\|tunnel'
cat plaintext |
    awk '!/^@@/ && !/^\!/ && !/\[/'     | # 移除 白名单 注释 和 文件名 的行
    awk NF                              | # 移除空行
    sed 's_^|\|^||\|^\.__g'             | # 去掉 前缀匹配| 字符串匹配|| 通配符.
    sed 's_^http://\|^https://__g'      | # 去掉 开头的schema http:// https://
    sed 's_/.*$__g'                     | # 去掉行末的路径
    awk '!/\*/ && /\./ && !/^[0-9.]*$/' | # 移除包含通配符的行 移除IP地址 和字符串
    grep -v $sensitive_pattern          | # 移除关键词
    sort -u
