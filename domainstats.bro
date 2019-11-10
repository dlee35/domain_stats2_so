module DomainStats;

export {
    # This redef is purely for testing pcap and not designed for active networks
    # Set to F or comment before adding to production
    redef exit_only_after_terminate = T;

    global domainstats_url = "http://localhost:20000/"; # add desired DS url here
    global ignore_domains = set(".test.net", ".bing.com", ".amazonaws.com", ".googleapis.com" ); # add domains to exclude here
    global queried_domains: table[string] of count &default=0 &create_expire=1days; # keep state of domains to prevent duplicate queries
    global domain_suffixes = /MATCH_NOTHING/; # idea borrowed from: https://github.com/theflakes/bro-large_uploads
    redef enum Log::ID += { LOG };
    
    type Info: record {
        ts: time             &log;
        uid: string          &log;
        query: string        &log;
        seen_by_web: string  &log;
        seen_by_us: string   &log;
        seen_by_you: string  &log;
        rank: string         &log;
        other: string        &log &optional;
    };
}    

event bro_init() &priority=5
{
    domain_suffixes = set_to_regex(ignore_domains, "(~~)$");
    Log::create_stream(DomainStats::LOG, [$columns=Info, $path="domainstats"]);
}

event dns_A_reply(c: connection; msg:dns_msg; ans:dns_answer; a:addr;)
{
    if (c$dns?$query) {
        local dsurl = domainstats_url;
        local domain = fmt("%s",c$dns$query);
        if (domain in queried_domains || domain_suffixes in domain) {
            return;
        }
        else {
            local request: ActiveHTTP::Request = [
                $url = dsurl + domain
            ];
            queried_domains[domain] = 1;
            when (local res = ActiveHTTP::request(request)) {
                if (|res| > 0) {
                    if (res?$body && |split_string(res$body,/,/)| > 2) {
                        local resbody = fmt("%s", res$body);
                        local seen_by_web_parse = gsub(split_string(resbody,/,/)[0],/\{/,"");
                        local seen_by_web_date = strip(split_string1(gsub(split_string1(seen_by_web_parse,/:/)[1],/\"/,""),/\./)[0]); 
                        local seen_by_us_parse = split_string(resbody,/,/)[1];
                        local seen_by_us_date = strip(split_string1(gsub(split_string1(seen_by_us_parse,/:/)[1],/\"/,""),/\./)[0]); 
                        local seen_by_you_parse = split_string(resbody,/,/)[2];
                        local seen_by_you_date = strip(split_string1(gsub(split_string1(seen_by_you_parse,/:/)[1],/\"/,""),/\./)[0]); 
                        local rank_parse = split_string(resbody,/,/)[3];
                        local rank_num = strip(gsub(split_string(rank_parse,/:/)[1],/\"/,"")); 
                        local other_parse = gsub(split_string(resbody,/,/)[4],/\}|\{/,"");
                        local other_info = strip(gsub(split_string(other_parse,/:/)[1],/\"/,"")); 
                        local rec: DomainStats::Info = [$ts=c$start_time, $uid=c$uid, $query=domain, $seen_by_web=seen_by_web_date, $seen_by_us=seen_by_us_date, $seen_by_you=seen_by_you_date, $rank=rank_num, $other=other_info]; 
                        Log::write(DomainStats::LOG, rec);
                    }
                }
            }
        }
    }
}
