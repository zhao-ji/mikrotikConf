sensitive_pattern='google\|youtube\|wordpress\|appspot\|tumblr\|somee\|proxy\|hide\|vpn\|tunnel'
cat 160730_record | 
    grep -v $sensitive_pattern |
    sort -u 
