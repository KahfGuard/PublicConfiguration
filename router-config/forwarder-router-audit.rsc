:put "========================================="
:put "  Kahf Distribution Router Audit"
:put "========================================="

# ===== Match your config vars =====
:local safeList "Bypass_Safe"
:local clientList "Safe_Package_IPs"
:local dohList "DoH_Providers"
# ==================================

# Counters must be global so do={} blocks can write to them
:global cntPass 0
:global cntFail 0
:global cntWarn 0

# --- [1] Address lists populated ---
:put "[1] Address lists:"
:local cSafe   [:len [/ip firewall address-list find where list=$safeList]]
:local cClient [:len [/ip firewall address-list find where list=$clientList]]
:local cDoH    [:len [/ip firewall address-list find where list=$dohList]]
:if ($cSafe>0) do={
  :put "  Bypass_Safe:      $cSafe entries  OK"
  :set cntPass ($cntPass+1)
} else={
  :put "  Bypass_Safe:      MISSING"
  :set cntFail ($cntFail+1)
}
:if ($cClient>0) do={
  :put "  Safe_Package_IPs: $cClient entries  OK"
  :set cntPass ($cntPass+1)
} else={
  :put "  Safe_Package_IPs: MISSING"
  :set cntFail ($cntFail+1)
}
:if ($cDoH>=18) do={
  :put "  DoH_Providers:    $cDoH entries  OK"
  :set cntPass ($cntPass+1)
} else={
  :put "  DoH_Providers:    only $cDoH (expected 18+)"
  :set cntWarn ($cntWarn+1)
}

# --- [2] NAT redirects for plain DNS ---
:put "[2] Plain DNS NAT redirect (port 53):"
:local natUdp [:len [/ip firewall nat find where chain=dstnat and protocol=udp and dst-port=53 and src-address-list=$clientList]]
:local natTcp [:len [/ip firewall nat find where chain=dstnat and protocol=tcp and dst-port=53 and src-address-list=$clientList]]
:if ($natUdp>0) do={
  :put "  UDP/53 -> forwarder:  OK"
  :set cntPass ($cntPass+1)
} else={
  :put "  UDP/53 -> forwarder:  MISSING"
  :set cntFail ($cntFail+1)
}
:if ($natTcp>0) do={
  :put "  TCP/53 -> forwarder:  OK"
  :set cntPass ($cntPass+1)
} else={
  :put "  TCP/53 -> forwarder:  MISSING"
  :set cntFail ($cntFail+1)
}

# --- [3] Forwarder reachability ---
:put "[3] Forwarder reachability:"
:foreach r in=[/ip firewall nat find where chain=dstnat and dst-port=53] do={
  :local addrs [/ip firewall nat get $r to-addresses]
  :put "  Configured: $addrs"
  :local first $addrs
  :local dashPos [:find $addrs "-"]
  :if ($dashPos != "") do={
    :set first [:pick $addrs 0 $dashPos]
  }
  :local received [/ping address=$first count=2]
  :if ($received > 0) do={
    :put "  Ping $first: replies received"
    :set cntPass ($cntPass+1)
  } else={
    :put "  Ping $first: UNREACHABLE"
    :set cntFail ($cntFail+1)
  }
}

# --- [4] Encrypted DNS reject rules ---
:put "[4] Encrypted DNS REJECT rules (forward chain):"
:local dot  [:len [/ip firewall filter find where chain=forward and protocol=tcp and dst-port=853 and action=reject]]
:local doq  [:len [/ip firewall filter find where chain=forward and protocol=udp and dst-port=853 and action=reject]]
:local quic [:len [/ip firewall filter find where chain=forward and protocol=udp and dst-port=443 and action=reject]]
:local doh  [:len [/ip firewall filter find where chain=forward and protocol=tcp and dst-port=443 and dst-address-list=$dohList and action=reject]]
:if ($dot>0) do={
  :put "  DoT  (TCP/853):       OK"
  :set cntPass ($cntPass+1)
} else={
  :put "  DoT  (TCP/853):       MISSING"
  :set cntFail ($cntFail+1)
}
:if ($doq>0) do={
  :put "  DoQ  (UDP/853):       OK"
  :set cntPass ($cntPass+1)
} else={
  :put "  DoQ  (UDP/853):       MISSING"
  :set cntFail ($cntFail+1)
}
:if ($quic>0) do={
  :put "  QUIC (UDP/443):       OK"
  :set cntPass ($cntPass+1)
} else={
  :put "  QUIC (UDP/443):       MISSING"
  :set cntFail ($cntFail+1)
}
:if ($doh>0) do={
  :put "  DoH  (TCP/443->list): OK"
  :set cntPass ($cntPass+1)
} else={
  :put "  DoH  (TCP/443->list): MISSING"
  :set cntFail ($cntFail+1)
}

# --- [5] Reject rules placed BEFORE fasttrack ---
:put "[5] Rule ordering vs fasttrack:"
:local ftId [/ip firewall filter find where action=fasttrack-connection and chain=forward]
:if ([:len $ftId]=0) do={
  :put "  No fasttrack rule found  OK (nothing to bypass)"
  :set cntPass ($cntPass+1)
} else={
  :local ftPos 0
  :local idx 0
  :foreach r in=[/ip firewall filter find where chain=forward] do={
    :if ($r = [:pick $ftId 0]) do={ :set ftPos $idx }
    :set idx ($idx+1)
  }
  :local kahfBefore true
  :foreach k in=[/ip firewall filter find where comment~"KAHF-DNS"] do={
    :local kPos 0
    :local kIdx 0
    :foreach r in=[/ip firewall filter find where chain=forward] do={
      :if ($r = $k) do={ :set kPos $kIdx }
      :set kIdx ($kIdx+1)
    }
    :if ($kPos > $ftPos) do={ :set kahfBefore false }
  }
  :if ($kahfBefore) do={
    :put "  All KAHF-DNS rules before fasttrack:  OK"
    :set cntPass ($cntPass+1)
  } else={
    :put "  KAHF-DNS rule(s) AFTER fasttrack -- bypass risk"
    :set cntFail ($cntFail+1)
  }
}

# --- [6] Reject-with correctness ---
:put "[6] Reject-with values (instant fallback vs silent timeout):"
:local badReject [:len [/ip firewall filter find where comment~"KAHF-DNS" and action=drop]]
:if ($badReject=0) do={
  :put "  No DROP used for KAHF-DNS:  OK"
  :set cntPass ($cntPass+1)
} else={
  :put "  $badReject rule(s) use DROP -- should be REJECT"
  :set cntWarn ($cntWarn+1)
}

# --- [7] Self-resolve via forwarder ---
:put "[7] Forwarder DNS resolution test:"
:do {
  :local ip [:resolve "google.com"]
  :put "  google.com -> $ip"
  :set cntPass ($cntPass+1)
} on-error={
  :put "  Resolution FAILED"
  :set cntFail ($cntFail+1)
}

# --- [8] Baseline counters ---
:put "[8] Current hit counters (baseline before client connects):"
/ip firewall nat print stats where chain=dstnat and dst-port=53
:put ""
/ip firewall filter print stats where comment~"KAHF-DNS"

# --- Summary ---
:put "========================================="
:put "  PASS: $cntPass   FAIL: $cntFail   WARN: $cntWarn"
:put "========================================="
:if ($cntFail=0) do={
  :put "  Ready for client traffic."
} else={
  :put "  Fix FAILs before connecting clients."
}

# Cleanup globals
:set cntPass
:set cntFail
:set cntWarn
